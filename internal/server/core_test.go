package server

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestServerClientRoundTrip(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		900,
		100,
	)

	clientEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	serverRX := newServerDataScratch(t, server)
	serverTX := newServerDataScratch(t, server)

	clientRX := newTestDataScratch(
		t,
		routeKey,
	)

	// ---------------------------------------------------------------------
	// Client -> server.
	// ---------------------------------------------------------------------

	innerToServer := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("hello server"),
	)

	wireToServer, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		innerToServer,
	)

	openedByServer, err := server.HandleDatagramInPlace(
		serverRX,
		clientEndpoint,
		wireToServer,
	)
	if err != nil {
		t.Fatalf(
			"server HandleDatagramInPlace: %v",
			err,
		)
	}

	// The server strips DATA padding before returning the packet to TUN.
	if !bytes.Equal(
		openedByServer,
		innerToServer,
	) {
		t.Fatal(
			"server plaintext differs from original client packet",
		)
	}

	// ---------------------------------------------------------------------
	// Server -> client.
	// ---------------------------------------------------------------------

	innerToClient := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		[]byte("hello client"),
	)

	out := make(
		[]byte,
		0,
		len(innerToClient)+MaxDataExpansion,
	)

	wireToClient, destination, err := server.HandleInnerPacketTo(
		serverTX,
		out,
		innerToClient,
	)
	if err != nil {
		t.Fatalf(
			"server HandleInnerPacketTo: %v",
			err,
		)
	}

	if destination != clientEndpoint {
		t.Fatalf(
			"destination=%v, want %v",
			destination,
			clientEndpoint,
		)
	}

	// Decode the route as the client receive path does:
	//
	//	route PRF
	//	→ session ID / sequence
	//	→ AEAD
	//	→ replay
	//	→ IPv4 / padding
	sessionID, sequence, err := decodePacketRoute(
		clientRX,
		wireToClient,
	)
	if err != nil {
		t.Fatalf(
			"client decode route: %v",
			err,
		)
	}

	if sessionID != client.ID() {
		t.Fatalf(
			"client got session=%#x, want %#x",
			sessionID,
			client.ID(),
		)
	}

	serverEndpoint := netip.MustParseAddrPort(
		"198.51.100.10:41675",
	)

	openedByClient, err := client.AuthenticateInPlace(
		clientRX,
		wireToClient,
		sequence,
	)
	if err != nil {
		t.Fatalf(
			"client AEAD authenticate: %v",
			err,
		)
	}

	// This test bypasses client.Core, so commit authenticated RX explicitly.
	if _, err := client.CommitAuthenticatedRX(
		sequence,
		serverEndpoint,
	); err != nil {
		t.Fatalf(
			"client RX commit: %v",
			err,
		)
	}

	header, err := ParseIPv4(openedByClient)
	if err != nil {
		t.Fatalf(
			"client ParseIPv4: %v",
			err,
		)
	}

	paddingLength := len(openedByClient) - header.TotalLength

	if paddingLength < 0 || paddingLength > MaxDataPadding {
		t.Fatalf(
			"client padding length=%d, want 0..%d",
			paddingLength,
			MaxDataPadding,
		)
	}

	// The reference sender zero-fills padding.
	for i, value := range openedByClient[header.TotalLength:] {
		if value != 0 {
			t.Fatalf(
				"padding byte %d=%#x, want zero",
				i,
				value,
			)
		}
	}

	openedByClient = openedByClient[:header.TotalLength]

	if !bytes.Equal(
		openedByClient,
		innerToClient,
	) {
		t.Fatal(
			"client plaintext differs from original server packet",
		)
	}
}

func TestServerInboundDataPaddingIsTrimmedBeforeTun(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		10,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	clientTX := newTestDataScratch(
		t,
		routeKey,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("padded packet"),
	)

	// Use fixed maximum padding to test the receive boundary.
	dst := make(
		[]byte,
		0,
		len(inner)+DataOverhead+MaxDataPadding,
	)

	wire, _, err := client.SealDataToWithPadding(
		clientTX,
		dst,
		inner,
		MaxDataPadding,
	)
	if err != nil {
		t.Fatalf(
			"sealToWithPadding: %v",
			err,
		)
	}

	opened, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		wire,
	)
	if err != nil {
		t.Fatalf(
			"HandleDatagramInPlace: %v",
			err,
		)
	}

	// Only bytes covered by IPv4 Total Length may reach TUN.
	if !bytes.Equal(
		opened,
		inner,
	) {
		t.Fatalf(
			"trimmed plaintext mismatch:\n got: %x\nwant: %x",
			opened,
			inner,
		)
	}
}

func TestServerRejectsAuthenticatedExcessiveDataPadding(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		10,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	clientTX := newTestDataScratch(
		t,
		routeKey,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	// Append 16 bytes beyond IPv4 Total Length. Authentication succeeds, but
	// DATA grammar must reject the excessive padding.
	plaintext := make(
		[]byte,
		len(inner)+MaxDataPadding+1,
	)

	copy(
		plaintext,
		inner,
	)

	dst := make(
		[]byte,
		0,
		len(plaintext)+DataOverhead,
	)

	wire, _, err := client.SealDataToWithPadding(
		clientTX,
		dst,
		plaintext,
		0,
	)
	if err != nil {
		t.Fatalf(
			"sealToWithPadding: %v",
			err,
		)
	}

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		wire,
	); !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf(
			"error=%v, want ErrInvalidPadding",
			err,
		)
	}
}

func TestServerRejectsInnerPacketLargerThanConfiguredMTUWithValidPadding(
	t *testing.T,
) {
	server, client, routeKey := newTestServer(
		t,
		0,
		10,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	clientTX := newTestDataScratch(
		t,
		routeKey,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	// Server MaxInnerPacketSize == 1380.
	//
	// Build a valid 1395-byte IPv4 packet.
	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		make([]byte, 1395-20),
	)

	if len(inner) != 1395 {
		t.Fatalf(
			"inner length=%d, want 1395",
			len(inner),
		)
	}

	// With no padding, the wire packet is:
	//
	//	1395 + 32 = 1427 bytes
	//
	// The general pre-crypto upper bound is:
	//
	//	1380 + 32 + 15 = 1427 bytes.
	//
	// The pre-crypto bound admits this datagram; post-authentication validation
	// must reject the oversized inner packet.
	dst := make(
		[]byte,
		0,
		len(inner)+DataOverhead,
	)

	wire, _, err := client.SealDataToWithPadding(
		clientTX,
		dst,
		inner,
		0,
	)
	if err != nil {
		t.Fatalf(
			"sealToWithPadding: %v",
			err,
		)
	}

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		wire,
	); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf(
			"error=%v, want ErrPacketTooLarge",
			err,
		)
	}
}

func TestServerRejectsReplay(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		10,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	wire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	// Preserve a copy because HandleDatagramInPlace mutates ciphertext.
	replayedWire := bytes.Clone(wire)

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		wire,
	); err != nil {
		t.Fatalf(
			"first receive: %v",
			err,
		)
	}

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		replayedWire,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf(
			"second receive error=%v, want ErrReplay",
			err,
		)
	}
}

func TestUnauthenticatedPacketDoesNotChangeEndpoint(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		1,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	goodEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	badEndpoint := netip.MustParseAddrPort(
		"198.51.100.20:60000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte{1},
	)

	good, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		goodEndpoint,
		good,
	); err != nil {
		t.Fatalf(
			"receive good: %v",
			err,
		)
	}

	before, ok := server.CurrentSession(testPeerTunnelIPv4()).Endpoint()
	if !ok || before != goodEndpoint {
		t.Fatalf(
			"endpoint before attack=%v ok=%v",
			before,
			ok,
		)
	}

	bad, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	// Tamper with ciphertext while preserving the route and tag.
	bad[RouteSize] ^= 0x80

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		badEndpoint,
		bad,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"bad packet error=%v, want ErrAuthentication",
			err,
		)
	}

	after, ok := server.CurrentSession(testPeerTunnelIPv4()).Endpoint()
	if !ok || after != goodEndpoint {
		t.Fatalf(
			"unauthenticated packet changed endpoint: got=%v want=%v",
			after,
			goodEndpoint,
		)
	}
}

func TestOldButUnseenPacketDoesNotMoveEndpointBack(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		100,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	oldEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	newEndpoint := netip.MustParseAddrPort(
		"198.51.100.20:60000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	// Prepare two consecutive packets.
	packet100, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	packet101, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	// The newer packet arrives from the new network first.
	if _, err := server.HandleDatagramInPlace(
		serverRX,
		newEndpoint,
		packet101,
	); err != nil {
		t.Fatalf(
			"receive 101: %v",
			err,
		)
	}

	// The delayed packet is unseen and inside the replay window, but it must not
	// move the endpoint back.
	if _, err := server.HandleDatagramInPlace(
		serverRX,
		oldEndpoint,
		packet100,
	); err != nil {
		t.Fatalf(
			"receive delayed 100: %v",
			err,
		)
	}

	endpoint, ok := server.CurrentSession(testPeerTunnelIPv4()).Endpoint()
	if !ok || endpoint != newEndpoint {
		t.Fatalf(
			"endpoint=%v ok=%v, want %v",
			endpoint,
			ok,
			newEndpoint,
		)
	}
}

func TestAuthenticatedMalformedIPv4ConsumesReplayAndUpdatesEndpoint(
	t *testing.T,
) {
	server, client, routeKey := newTestServer(
		t,
		0,
		55,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	firstEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	secondEndpoint := netip.MustParseAddrPort(
		"198.51.100.20:60000",
	)

	// The plaintext authenticates but is not an IPv4 packet.
	wire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		[]byte{0x01, 0x02, 0x03},
	)

	// Preserve a copy before the first in-place decryption.
	replayedWire := bytes.Clone(wire)

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		firstEndpoint,
		wire,
	); !errors.Is(err, ErrInvalidIPv4) {
		t.Fatalf(
			"first error=%v, want ErrInvalidIPv4",
			err,
		)
	}

	// Endpoint roaming commits after AEAD and replay checks, before IPv4 validation.
	endpoint, ok := server.CurrentSession(testPeerTunnelIPv4()).Endpoint()
	if !ok || endpoint != firstEndpoint {
		t.Fatalf(
			"endpoint=%v ok=%v, want %v",
			endpoint,
			ok,
			firstEndpoint,
		)
	}

	// Replaying the same datagram must not update the endpoint.
	if _, err := server.HandleDatagramInPlace(
		serverRX,
		secondEndpoint,
		replayedWire,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf(
			"second error=%v, want ErrReplay",
			err,
		)
	}

	endpoint, _ = server.CurrentSession(testPeerTunnelIPv4()).Endpoint()

	if endpoint != firstEndpoint {
		t.Fatalf(
			"replay changed endpoint: got=%v want=%v",
			endpoint,
			firstEndpoint,
		)
	}
}

func TestSpoofedSourceRejectedAfterAuthentication(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		0,
		1,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	spoofed := testIPv4Packet(
		t,
		"10.66.0.99",
		"10.66.0.1",
		nil,
	)

	wire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		spoofed,
	)

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		wire,
	); !errors.Is(err, ErrUnauthorizedSource) {
		t.Fatalf(
			"error=%v, want ErrUnauthorizedSource",
			err,
		)
	}
}

func TestServerOutboundRequiresLearnedEndpoint(t *testing.T) {
	server, _, _ := newTestServer(
		t,
		0,
		0,
	)

	serverTX := newServerDataScratch(
		t,
		server,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		nil,
	)

	dst := make(
		[]byte,
		0,
		len(inner)+MaxDataExpansion,
	)

	if _, _, err := server.HandleInnerPacketTo(
		serverTX,
		dst,
		inner,
	); !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf(
			"error=%v, want ErrNoEndpoint",
			err,
		)
	}
}

func TestServerOutboundUnknownDestinationRejectedWithoutConsumingSequence(
	t *testing.T,
) {
	server, _, _ := newTestServer(
		t,
		77,
		0,
	)

	serverTX := newServerDataScratch(
		t,
		server,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.99",
		nil,
	)

	dst := make(
		[]byte,
		0,
		len(inner)+MaxDataExpansion,
	)

	before := server.CurrentSession(testPeerTunnelIPv4()).TxSequence()

	if _, _, err := server.HandleInnerPacketTo(
		serverTX,
		dst,
		inner,
	); !errors.Is(err, ErrUnauthorizedDestination) {
		t.Fatalf(
			"error=%v, want ErrUnauthorizedDestination",
			err,
		)
	}

	after := server.CurrentSession(testPeerTunnelIPv4()).TxSequence()

	if after != before {
		t.Fatalf(
			"invalid outbound packet consumed sequence: before=%d after=%d",
			before,
			after,
		)
	}
}

func TestServerOutboundRejectsTrailingBytesFromTunWithoutConsumingSequence(
	t *testing.T,
) {
	server, _, _ := newTestServer(
		t,
		77,
		0,
	)

	serverTX := newServerDataScratch(
		t,
		server,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		nil,
	)

	// Decrypted DATA may contain trailing padding; a TUN packet must contain
	// exactly one IPv4 packet.
	withTrailing := append(
		bytes.Clone(inner),
		0x00,
	)

	dst := make(
		[]byte,
		0,
		len(withTrailing)+MaxDataExpansion,
	)

	before := server.CurrentSession(testPeerTunnelIPv4()).TxSequence()

	if _, _, err := server.HandleInnerPacketTo(
		serverTX,
		dst,
		withTrailing,
	); !errors.Is(err, ErrInvalidIPv4) {
		t.Fatalf(
			"error=%v, want ErrInvalidIPv4",
			err,
		)
	}

	after := server.CurrentSession(testPeerTunnelIPv4()).TxSequence()

	if after != before {
		t.Fatalf(
			"invalid outbound packet consumed sequence: before=%d after=%d",
			before,
			after,
		)
	}
}

func TestBitFlipsFail(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "opaque route",
			mutate: func(packet []byte) {
				packet[0] ^= 0x01
			},
		},
		{
			name: "ciphertext",
			mutate: func(packet []byte) {
				packet[RouteSize] ^= 0x01
			},
		},
		{
			name: "tag",
			mutate: func(packet []byte) {
				packet[len(packet)-1] ^= 0x01
			},
		},
	}

	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			server, client, routeKey := newTestServer(
				t,
				0,
				10,
			)

			serverRX := newServerDataScratch(
				t,
				server,
			)

			endpoint := netip.MustParseAddrPort(
				"192.0.2.10:50000",
			)

			inner := testIPv4Packet(
				t,
				"10.66.0.2",
				"10.66.0.1",
				[]byte{1, 2, 3},
			)

			wire, _ := sealTestPacket(
				t,
				client,
				&routeKey,
				inner,
			)

			tt.mutate(wire)

			if _, err := server.HandleDatagramInPlace(
				serverRX,
				endpoint,
				wire,
			); err == nil {
				t.Fatal(
					"mutated packet was accepted",
				)
			}
		})
	}
}

func TestConcurrentDuplicateDeliveryAcceptsExactlyOneCopy(
	t *testing.T,
) {
	server, client, routeKey := newTestServer(
		t,
		0,
		500,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("same datagram"),
	)

	wire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	const workers = 32

	// Give each packet-processing worker its own non-concurrent DataScratch.
	scratches := make(
		[]*DataScratch,
		workers,
	)

	for i := range scratches {
		scratches[i] = newServerDataScratch(
			t,
			server,
		)
	}

	var successes atomic.Int32
	var unexpected atomic.Int32

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(worker int) {
			defer wg.Done()

			// Each simulated UDP delivery needs its own in-place receive buffer.
			packet := bytes.Clone(wire)

			_, err := server.HandleDatagramInPlace(
				scratches[worker],
				endpoint,
				packet,
			)

			switch {
			case err == nil:
				successes.Add(1)

			case errors.Is(err, ErrReplay):
				// Expected for every loser of the replay race.

			default:
				unexpected.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf(
			"successful copies=%d, want exactly 1",
			got,
		)
	}

	if got := unexpected.Load(); got != 0 {
		t.Fatalf(
			"unexpected errors=%d, want 0",
			got,
		)
	}
}

func TestWrongTrafficKeyFailsAuthentication(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19

	client, err := NewSession(
		sessionID,
		c2s,
		s2c,
		10,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(client): %v",
			err,
		)
	}

	// Give the server an incorrect RX key.
	wrongC2S := c2s
	wrongC2S[0] ^= 0xff

	serverSession, err := NewSession(
		sessionID,
		s2c,
		wrongC2S,
		0,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(server): %v",
			err,
		)
	}

	server, err := NewServerCore(ServerConfig{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{
				TunnelIPv4:     testPeerTunnelIPv4(),
				InitialSession: serverSession,
			},
		},
	})
	if err != nil {
		t.Fatalf(
			"NewServerCore: %v",
			err,
		)
	}

	serverRX := newServerDataScratch(
		t,
		server,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	wire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		inner,
	)

	_, err = server.HandleDatagramInPlace(
		serverRX,
		netip.MustParseAddrPort(
			"192.0.2.10:50000",
		),
		wire,
	)

	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf(
			"error=%v, want ErrAuthentication",
			err,
		)
	}
}

func TestWrongRouteKeyCannotProduceValidPacket(t *testing.T) {
	server, client, correctRouteKey := newTestServer(
		t,
		0,
		10,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	wire, _ := sealTestPacket(
		t,
		client,
		&correctRouteKey,
		inner,
	)

	// Scratch already contains keyed BLAKE2s state, so construct it with the
	// wrong route key explicitly.
	wrongRouteKey := correctRouteKey
	wrongRouteKey[0] ^= 0xff

	wrongRX := newTestDataScratch(
		t,
		wrongRouteKey,
	)

	if _, err := server.HandleDatagramInPlace(
		wrongRX,
		endpoint,
		wire,
	); err == nil {
		t.Fatal(
			"packet encoded with another K_route was accepted",
		)
	}
}

func TestOutboundSealConsumesSequenceImmediately(t *testing.T) {
	server, client, routeKey := newTestServer(
		t,
		900,
		1,
	)

	serverRX := newServerDataScratch(
		t,
		server,
	)

	serverTX := newServerDataScratch(
		t,
		server,
	)

	decodeScratch := newTestDataScratch(
		t,
		routeKey,
	)

	endpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	// First, teach the server an authenticated client endpoint.
	clientInner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	clientWire, _ := sealTestPacket(
		t,
		client,
		&routeKey,
		clientInner,
	)

	if _, err := server.HandleDatagramInPlace(
		serverRX,
		endpoint,
		clientWire,
	); err != nil {
		t.Fatalf(
			"learn endpoint: %v",
			err,
		)
	}

	serverInner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		nil,
	)

	firstDst := make(
		[]byte,
		0,
		len(serverInner)+MaxDataExpansion,
	)

	firstWire, _, err := server.HandleInnerPacketTo(
		serverTX,
		firstDst,
		serverInner,
	)
	if err != nil {
		t.Fatalf(
			"first HandleInnerPacketTo: %v",
			err,
		)
	}

	_, firstSequence, err := decodePacketRoute(
		decodeScratch,
		firstWire,
	)
	if err != nil {
		t.Fatalf(
			"decode first route: %v",
			err,
		)
	}

	// Even without a successful UDP send, the next seal must use a new sequence.
	secondDst := make(
		[]byte,
		0,
		len(serverInner)+MaxDataExpansion,
	)

	secondWire, _, err := server.HandleInnerPacketTo(
		serverTX,
		secondDst,
		serverInner,
	)
	if err != nil {
		t.Fatalf(
			"second HandleInnerPacketTo: %v",
			err,
		)
	}

	_, secondSequence, err := decodePacketRoute(
		decodeScratch,
		secondWire,
	)
	if err != nil {
		t.Fatalf(
			"decode second route: %v",
			err,
		)
	}

	if firstSequence != 900 || secondSequence != 901 {
		t.Fatalf(
			"sequences=(%d,%d), want (900,901)",
			firstSequence,
			secondSequence,
		)
	}

	if got := server.CurrentSession(testPeerTunnelIPv4()).TxSequence(); got != 902 {
		t.Fatalf(
			"next tx sequence=%d, want 902",
			got,
		)
	}
}

func TestNewMaxInnerPacketSizeBounds(t *testing.T) {
	config := Config{
		RouteKey: [32]byte{1},
		Lifecycle: LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []PeerConfig{{TunnelIPv4: netip.MustParseAddr("10.66.0.2")}},
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
