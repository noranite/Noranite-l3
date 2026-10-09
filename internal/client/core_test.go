package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/server"
)

func testLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}
}

func TestClientServerRoundTrip(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19

	clientSession, err := dataplane.NewSession(
		sessionID,
		c2s, // client TX
		s2c, // client RX
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}

	serverSession, err := dataplane.NewSession(
		sessionID,
		s2c, // server TX
		c2s, // server RX
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	clientTunnelIPv4 := netip.MustParseAddr("10.66.0.2")
	serverTunnelIPv4 := netip.MustParseAddr("10.66.0.1")

	serverEndpoint := netip.MustParseAddrPort(
		"198.51.100.10:41675",
	)

	clientEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	clientCore, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientTunnelIPv4,
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
		Peers: []server.PeerConfig{
			{
				TunnelIPv4:     clientTunnelIPv4,
				InitialSession: serverSession,
			},
		},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	clientTX, err := clientCore.NewDataScratch()
	if err != nil {
		t.Fatalf("client TX scratch: %v", err)
	}

	clientRX, err := clientCore.NewDataScratch()
	if err != nil {
		t.Fatalf("client RX scratch: %v", err)
	}

	serverTX, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server TX scratch: %v", err)
	}

	serverRX, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server RX scratch: %v", err)
	}

	// ------------------------------------------------------------
	// Client -> server.
	// ------------------------------------------------------------

	toServer := testIPv4Packet(
		t,
		clientTunnelIPv4,
		serverTunnelIPv4,
		[]byte("hello server"),
	)

	clientOut := make(
		[]byte,
		0,
		len(toServer)+dataplane.MaxDataExpansion,
	)

	wireToServer, destination, err :=
		clientCore.HandleInnerPacketTo(
			clientTX,
			clientOut,
			toServer,
		)
	if err != nil {
		t.Fatalf("client HandleInnerPacketTo: %v", err)
	}

	if destination != serverEndpoint {
		t.Fatalf(
			"client UDP destination=%v, want %v",
			destination,
			serverEndpoint,
		)
	}

	openedByServer, err :=
		serverCore.HandleDatagramInPlace(
			serverRX,
			clientEndpoint,
			wireToServer,
		)
	if err != nil {
		t.Fatalf("server HandleDatagramInPlace: %v", err)
	}

	if !bytes.Equal(openedByServer, toServer) {
		t.Fatal(
			"server plaintext differs from original client packet",
		)
	}

	// An authenticated client packet teaches the server its UDP endpoint.
	learnedEndpoint, ok := serverSession.Endpoint()
	if !ok {
		t.Fatal("server did not learn client endpoint")
	}

	if learnedEndpoint != clientEndpoint {
		t.Fatalf(
			"server learned endpoint=%v, want %v",
			learnedEndpoint,
			clientEndpoint,
		)
	}

	// ------------------------------------------------------------
	// Server -> client.
	// ------------------------------------------------------------

	toClient := testIPv4Packet(
		t,
		serverTunnelIPv4,
		clientTunnelIPv4,
		[]byte("hello client"),
	)

	serverOut := make(
		[]byte,
		0,
		len(toClient)+dataplane.MaxDataExpansion,
	)

	wireToClient, destination, err :=
		serverCore.HandleInnerPacketTo(
			serverTX,
			serverOut,
			toClient,
		)
	if err != nil {
		t.Fatalf("server HandleInnerPacketTo: %v", err)
	}

	if destination != clientEndpoint {
		t.Fatalf(
			"server UDP destination=%v, want %v",
			destination,
			clientEndpoint,
		)
	}

	openedByClient, err :=
		clientCore.HandleDatagramInPlace(
			clientRX,
			serverEndpoint,
			wireToClient,
		)
	if err != nil {
		t.Fatalf("client HandleDatagramInPlace: %v", err)
	}

	if !bytes.Equal(openedByClient, toClient) {
		t.Fatal(
			"client plaintext differs from original server packet",
		)
	}
}

func TestConcurrentDuplicateDeliveryAcceptsExactlyOneCopy(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19

	clientSession, err := dataplane.NewSession(
		sessionID,
		c2s,
		s2c,
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}

	serverSession, err := dataplane.NewSession(
		sessionID,
		s2c,
		c2s,
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	serverEndpoint := netip.MustParseAddrPort("198.51.100.10:41675")
	clientCore, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         netip.MustParseAddr("10.66.0.2"),
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Session:            clientSession,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serverScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("server scratch: %v", err)
	}

	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		netip.MustParseAddr("10.66.0.2"),
		[]byte("same client datagram"),
	)
	wireStorage := make([]byte, 0, len(inner)+dataplane.MaxDataExpansion)
	wire, _, err := serverSession.SealDataTo(serverScratch, wireStorage, inner)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}

	const workers = 32
	scratches := make([]*dataplane.DataScratch, workers)
	for i := range scratches {
		scratches[i], err = clientCore.NewDataScratch()
		if err != nil {
			t.Fatalf("client scratch %d: %v", i, err)
		}
	}

	var successes atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := range workers {
		go func(worker int) {
			defer wg.Done()

			// AEAD Open is in-place, so each simulated UDP delivery owns its
			// own receive buffer and worker-local scratch.
			packet := bytes.Clone(wire)
			_, err := clientCore.HandleDatagramInPlace(
				scratches[worker],
				serverEndpoint,
				packet,
			)

			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, dataplane.ErrReplay):
				// Expected for every copy that loses the serialized replay commit.
			default:
				unexpected.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful copies=%d, want exactly 1", got)
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("unexpected errors=%d, want 0", got)
	}
}

func TestClientRejectsWrongLocalSourceWithoutConsumingSequence(
	t *testing.T,
) {
	routeKey, c2s, s2c := testKeys()

	session, err := dataplane.NewSession(
		1,
		c2s,
		s2c,
		77,
	)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	core, err := New(Config{
		RouteKey: routeKey,

		TunnelIPv4: netip.MustParseAddr(
			"10.66.0.2",
		),

		ServerEndpoint: netip.MustParseAddrPort(
			"198.51.100.10:41675",
		),

		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Session:            session,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	scratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("NewDataScratch: %v", err)
	}

	packet := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.99"),
		netip.MustParseAddr("1.1.1.1"),
		nil,
	)

	out := make(
		[]byte,
		0,
		len(packet)+dataplane.MaxDataExpansion,
	)

	before := session.TxSequence()

	_, _, err = core.HandleInnerPacketTo(
		scratch,
		out,
		packet,
	)

	if !errors.Is(err, ErrUnauthorizedSource) {
		t.Fatalf(
			"error=%v, want ErrUnauthorizedSource",
			err,
		)
	}

	after := session.TxSequence()

	if after != before {
		t.Fatalf(
			"rejected packet consumed sequence: before=%d after=%d",
			before,
			after,
		)
	}
}

func TestClientRejectsAuthenticatedPacketForAnotherTunnelAddress(
	t *testing.T,
) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 123

	clientSession, err := dataplane.NewSession(
		sessionID,
		c2s,
		s2c,
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}

	serverSession, err := dataplane.NewSession(
		sessionID,
		s2c,
		c2s,
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	core, err := New(Config{
		RouteKey: routeKey,

		TunnelIPv4: netip.MustParseAddr(
			"10.66.0.2",
		),

		ServerEndpoint: netip.MustParseAddrPort(
			"198.51.100.10:41675",
		),

		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Session:            clientSession,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clientRX, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("client scratch: %v", err)
	}

	serverTX, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("server scratch: %v", err)
	}

	packet := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		netip.MustParseAddr("10.66.0.99"),
		nil,
	)

	out := make(
		[]byte,
		0,
		len(packet)+dataplane.MaxDataExpansion,
	)

	wire, _, err := serverSession.SealDataTo(
		serverTX,
		out,
		packet,
	)
	if err != nil {
		t.Fatalf("server SealDataTo: %v", err)
	}

	_, err = core.HandleDatagramInPlace(
		clientRX,
		netip.MustParseAddrPort(
			"198.51.100.10:41675",
		),
		wire,
	)

	if !errors.Is(err, ErrUnauthorizedDestination) {
		t.Fatalf(
			"error=%v, want ErrUnauthorizedDestination",
			err,
		)
	}
}

func testKeys() (
	routeKey [32]byte,
	c2s [32]byte,
	s2c [32]byte,
) {
	for i := range 32 {
		routeKey[i] = byte(i + 1)
		c2s[i] = byte(0x40 + i)
		s2c[i] = byte(0x80 + i)
	}

	return routeKey, c2s, s2c
}

func testIPv4Packet(
	t *testing.T,
	source netip.Addr,
	destination netip.Addr,
	payload []byte,
) []byte {
	t.Helper()

	if !source.Is4() {
		t.Fatalf("source is not IPv4: %v", source)
	}

	if !destination.Is4() {
		t.Fatalf(
			"destination is not IPv4: %v",
			destination,
		)
	}

	const headerLength = 20

	totalLength := headerLength + len(payload)

	if totalLength > 0xffff {
		t.Fatalf(
			"IPv4 packet too large: %d",
			totalLength,
		)
	}

	packet := make(
		[]byte,
		totalLength,
	)

	// Version = 4, IHL = 5.
	packet[0] = 0x45

	binary.BigEndian.PutUint16(
		packet[2:4],
		uint16(totalLength),
	)

	packet[8] = 64 // TTL.
	packet[9] = 17 // UDP; the transport protocol is immaterial here.

	sourceBytes := source.As4()
	destinationBytes := destination.As4()

	copy(
		packet[12:16],
		sourceBytes[:],
	)

	copy(
		packet[16:20],
		destinationBytes[:],
	)

	copy(
		packet[headerLength:],
		payload,
	)

	return packet
}

func TestNewMaxInnerPacketSizeBounds(t *testing.T) {
	config := Config{
		RouteKey:       [32]byte{1},
		TunnelIPv4:     netip.MustParseAddr("10.66.0.2"),
		ServerEndpoint: netip.MustParseAddrPort("192.0.2.1:41675"),
		Lifecycle:      testLifecycleConfig(),
	}
	for _, size := range []int{-1, 0, 1, 19, 20, dataplane.MaxTunnelMTU, dataplane.MaxTunnelMTU + 1} {
		config.MaxInnerPacketSize = size
		_, err := New(config)
		if size >= 20 && size <= dataplane.MaxTunnelMTU {
			if err != nil {
				t.Fatalf("New with size %d: %v", size, err)
			}
		} else if !errors.Is(err, dataplane.ErrInvalidConfig) {
			t.Fatalf("New with size %d error=%v, want %v", size, err, dataplane.ErrInvalidConfig)
		}
	}
}
