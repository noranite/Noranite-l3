//go:build linux

package prototype

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/server"
)

func TestServerEstablishmentExecutorComposesWithNoiseProvider(t *testing.T) {
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0x70 + i)
	}

	clientIP := netip.MustParseAddr("10.77.0.2")
	clientEndpoint := netip.MustParseAddrPort("198.51.100.30:41000")
	serverEndpoint := netip.MustParseAddrPort("192.0.2.30:41675")
	clientPrivate := prototypeNoisePrivateKey(1)
	serverPrivate := prototypeNoisePrivateKey(33)
	clientPublic, err := noisehandshake.PublicKeyFromPrivate(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := noisehandshake.PublicKeyFromPrivate(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: clientIP}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	const sessionID = uint64(0xabc001)
	serverRandom := make([]byte, 8, 40)
	binary.LittleEndian.PutUint64(serverRandom, sessionID)
	serverRandom = append(serverRandom, prototypeNoiseEntropy(0x41)...)
	serverRandom = append(serverRandom, make([]byte, noisehandshake.InitMinPacketSize-noisehandshake.ResponseMinPacketSize)...)
	serverHS, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             serverCore,
		StaticPrivateKey: serverPrivate,
		Peers: []noisehandshake.AuthorizedPeer{{
			TunnelIPv4: clientIP,
			PublicKey:  clientPublic,
		}},
		Random: bytes.NewReader(serverRandom),
	})
	if err != nil {
		t.Fatalf("noisehandshake.NewServer: %v", err)
	}

	clientRandom := make([]byte, 8, 40)
	binary.LittleEndian.PutUint64(clientRandom, 0x1234)
	clientRandom = append(clientRandom, prototypeNoiseEntropy(0x81)...)
	clientRandom = append(clientRandom, 0)
	clientHS, err := noisehandshake.NewClient(noisehandshake.ClientConfig{
		ServerEndpoint:   serverEndpoint,
		RouteKey:         routeKey,
		StaticPrivateKey: clientPrivate,
		ServerPublicKey:  serverPublic,
		Random:           bytes.NewReader(clientRandom),
	})
	if err != nil {
		t.Fatalf("noisehandshake.NewClient: %v", err)
	}
	attempt, update, err := clientHS.Start(time.Unix(100, 0))
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	if len(update.Outbound) != 1 || attempt == nil {
		t.Fatalf("client Start attempt=%v outbound=%d, want one INIT", attempt, len(update.Outbound))
	}

	completed := make(chan error, 1)
	reported := make(chan error, 1)
	executor, err := newServerEstablishmentExecutor(
		serverHS,
		2048,
		2,
		1,
		func(response []byte, destination netip.AddrPort) error {
			if destination != clientEndpoint {
				return fmt.Errorf("response destination=%v, want %v", destination, clientEndpoint)
			}
			if current := serverCore.CurrentSession(clientIP); current != nil {
				return fmt.Errorf("server current before activation=%#x, want nil", current.ID())
			}

			responseScratch, err := dataplane.NewDataScratch(routeKey)
			if err != nil {
				return err
			}
			responseRoute, err := dataplane.DecodeRoute(responseScratch, response)
			if err != nil {
				return fmt.Errorf("decode response route: %w", err)
			}
			handled, clientUpdate, err := attempt.HandleDatagram(
				time.Unix(101, 0),
				serverEndpoint,
				responseRoute,
				true,
				response,
			)
			if err != nil {
				return fmt.Errorf("client RESPONSE: %w", err)
			}
			if !handled || clientUpdate.Material == nil {
				return fmt.Errorf("client RESPONSE handled=%v material=%v", handled, clientUpdate.Material)
			}
			clientSession, err := establishment.NewClientSession(*clientUpdate.Material)
			if err != nil {
				return fmt.Errorf("build client session: %w", err)
			}

			clientScratch, err := dataplane.NewDataScratch(routeKey)
			if err != nil {
				return err
			}
			keepalive, _, err := clientSession.SealKeepaliveToWithPadding(
				clientScratch,
				make([]byte, 0, dataplane.MinGeneratedControlWirePacketSize),
				0,
				dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize,
			)
			if err != nil {
				return fmt.Errorf("seal activation KEEPALIVE: %w", err)
			}
			serverScratch, err := serverCore.NewDataScratch()
			if err != nil {
				return err
			}
			inbound, _, _, err := serverCore.HandleNetworkDatagramInPlace(
				serverScratch,
				clientEndpoint,
				keepalive,
			)
			if err != nil {
				return fmt.Errorf("server activation KEEPALIVE: %w", err)
			}
			if inbound.Kind != dataplane.InboundKeepalive {
				return fmt.Errorf("activation inbound kind=%v, want KEEPALIVE", inbound.Kind)
			}
			current := serverCore.CurrentSession(clientIP)
			if current == nil || current.ID() != sessionID {
				return fmt.Errorf("server current after activation=%v, want %#x", current, sessionID)
			}

			completed <- nil
			return nil
		},
		func(err error) {
			select {
			case reported <- err:
			default:
			}
		},
	)
	if err != nil {
		t.Fatalf("newServerEstablishmentExecutor: %v", err)
	}
	defer executor.CloseAndWait()

	initScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatal(err)
	}
	initRoute, err := dataplane.DecodeRoute(initScratch, update.Outbound[0].Packet)
	if err != nil {
		t.Fatalf("decode INIT route: %v", err)
	}
	owned, accepted := executor.TrySubmit(clientEndpoint, initRoute, true, update.Outbound[0].Packet)
	if !owned || !accepted {
		t.Fatalf("TrySubmit=(owned=%v accepted=%v), want true,true", owned, accepted)
	}

	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-reported:
		t.Fatalf("executor reported error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Noise establishment executor")
	}
}

func prototypeNoisePrivateKey(start byte) noisehandshake.PrivateKey {
	var key noisehandshake.PrivateKey
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}

func prototypeNoiseEntropy(start byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}
