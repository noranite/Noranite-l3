package server

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func testPeerTunnelIPv4() netip.Addr {
	return netip.MustParseAddr("10.66.0.2")
}

func testLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}
}

// testKeys returns deterministic, non-secret test keys.
func testKeys() (route, c2s, s2c [32]byte) {
	for i := 0; i < 32; i++ {
		route[i] = byte(i + 1)
		c2s[i] = byte(0x40 + i)
		s2c[i] = byte(0x80 + i)
	}

	return route, c2s, s2c
}

// testIPv4Packet builds a minimal syntactically valid IPv4 packet.
func testIPv4Packet(
	t *testing.T,
	source string,
	destination string,
	payload []byte,
) []byte {
	t.Helper()

	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()

	packet := make([]byte, 20+len(payload))

	// Version=4, IHL=5:
	//
	//	4 << 4
	//	+
	//	5 words * 4 bytes = 20-byte IPv4 header.
	packet[0] = 0x45

	// Total Length includes the IPv4 header and payload.
	binary.BigEndian.PutUint16(
		packet[2:4],
		uint16(len(packet)),
	)

	packet[8] = 64
	packet[9] = 17 // UDP.

	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)

	return packet
}

// newTestServer creates a server core and a matching client-side session.
//
// server:
//
//	TX = K_s2c
//	RX = K_c2s
//
// client:
//
//	TX = K_c2s
//	RX = K_s2c
func newTestServer(
	t *testing.T,
	serverInitialSeq uint64,
	clientInitialSeq uint64,
) (*ServerCore, *Session, [32]byte) {
	t.Helper()

	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19

	serverSession, err := NewSession(
		sessionID,
		s2c,
		c2s,
		serverInitialSeq,
	)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	clientSession, err := NewSession(
		sessionID,
		c2s,
		s2c,
		clientInitialSeq,
	)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
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
		t.Fatalf("NewServerCore: %v", err)
	}

	return server, clientSession, routeKey
}

// newTestDataScratch creates standalone scratch state for a route key.
func newTestDataScratch(
	t *testing.T,
	routeKey [32]byte,
) *DataScratch {
	t.Helper()

	scratch, err := NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch: %v", err)
	}

	return scratch
}

// newServerDataScratch creates worker-local scratch through ServerCore.
func newServerDataScratch(
	t *testing.T,
	server *ServerCore,
) *DataScratch {
	t.Helper()

	scratch, err := server.NewDataScratch()
	if err != nil {
		t.Fatalf("server.NewDataScratch: %v", err)
	}

	return scratch
}

// sealTestPacket — test-only deterministic wrapper.
//
// sealTestPacket uses fixed nonzero padding to keep correctness tests
// deterministic while exercising the padded receive path.
func sealTestPacket(
	t *testing.T,
	session *Session,
	routeKey *[32]byte,
	plaintext []byte,
) ([]byte, uint64) {
	t.Helper()

	scratch := newTestDataScratch(t, *routeKey)

	dst := make(
		[]byte,
		0,
		len(plaintext)+DataOverhead+7,
	)

	wire, sequence, err := session.SealDataToWithPadding(
		scratch,
		dst,
		plaintext,
		7,
	)
	if err != nil {
		t.Fatalf("sealToWithPadding: %v", err)
	}

	return wire, sequence
}
