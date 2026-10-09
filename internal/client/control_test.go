package client

import (
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/server"
)

func TestClientKeepaliveServerACKRoundTrip(t *testing.T) {
	routeKey, c2s, s2c := testKeys()
	const sessionID uint64 = 0x7301
	const keepaliveID uint64 = 0xaabbccddeeff0011

	clientSession, err := dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	serverSession, err := dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	clientTunnel := netip.MustParseAddr("10.66.0.2")
	serverEndpoint := netip.MustParseAddrPort("198.51.100.10:41675")
	clientEndpoint := netip.MustParseAddrPort("192.0.2.10:50000")

	clientCore, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientTunnel,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Session:            clientSession,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []server.PeerConfig{{
			TunnelIPv4:     clientTunnel,
			InitialSession: serverSession,
		}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	clientScratch, err := clientCore.NewDataScratch()
	if err != nil {
		t.Fatalf("client.NewDataScratch: %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}

	keepalive, destination, err := clientCore.HandleKeepaliveTo(
		clientScratch,
		make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
		keepaliveID,
	)
	if err != nil {
		t.Fatalf("HandleKeepaliveTo: %v", err)
	}
	if destination != serverEndpoint {
		t.Fatalf("KEEPALIVE destination=%v, want %v", destination, serverEndpoint)
	}
	keepaliveSize := len(keepalive)
	if keepaliveSize < dataplane.MinGeneratedControlWirePacketSize || keepaliveSize > dataplane.MaxGeneratedControlWirePacketSize {
		t.Fatalf("KEEPALIVE len=%d, want [%d, %d]", keepaliveSize, dataplane.MinGeneratedControlWirePacketSize, dataplane.MaxGeneratedControlWirePacketSize)
	}

	serverInbound, ack, ackDestination, err :=
		serverCore.HandleNetworkDatagramInPlace(
			serverScratch,
			clientEndpoint,
			keepalive,
		)
	if err != nil {
		t.Fatalf("server HandleNetworkDatagramInPlace: %v", err)
	}
	if serverInbound.Kind != dataplane.InboundKeepalive || serverInbound.KeepaliveID != keepaliveID {
		t.Fatalf("server inbound=%+v, want KEEPALIVE %#x", serverInbound, keepaliveID)
	}
	if ackDestination != clientEndpoint {
		t.Fatalf("ACK destination=%v, want %v", ackDestination, clientEndpoint)
	}
	if len(ack) < dataplane.MinGeneratedControlWirePacketSize || len(ack) > keepaliveSize {
		t.Fatalf("ACK len=%d, want [%d, %d]", len(ack), dataplane.MinGeneratedControlWirePacketSize, keepaliveSize)
	}

	clientInbound, response, _, err := clientCore.HandleNetworkDatagramInPlace(
		clientScratch,
		serverEndpoint,
		ack,
	)
	if err != nil {
		t.Fatalf("client HandleNetworkDatagramInPlace: %v", err)
	}
	if clientInbound.Kind != dataplane.InboundACK || clientInbound.KeepaliveID != keepaliveID {
		t.Fatalf("client inbound=%+v, want ACK %#x", clientInbound, keepaliveID)
	}
	if len(response) != 0 {
		t.Fatal("client generated response to ACK")
	}
}
