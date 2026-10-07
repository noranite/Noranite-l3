package server

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestKeepalivePromotesPendingAndReturnsBoundedACK(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := testPeerTunnelIPv4()

	oldServer, _ := newLifecycleSessionPair(t, 0x6101, 0x11)
	newServer, newClient := newLifecycleSessionPair(t, 0x6102, 0x22)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{{
			TunnelIPv4:     peerIP,
			InitialSession: oldServer,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Unix(1_700_010_000, 0)
	core.now = func() time.Time { return now }

	if err := core.InstallPendingSession(peerIP, newServer); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	const keepaliveID uint64 = 0x0123456789abcdef
	clientTX := newTestDataScratch(t, routeKey)
	keepaliveBuffer := make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize)
	keepalive, _, err := newClient.SealKeepaliveToWithPadding(
		clientTX,
		keepaliveBuffer,
		keepaliveID,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+13,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding: %v", err)
	}

	// Server reuses the receive buffer for ACK, so preserve the exact original
	// wire packet for the replay test below.
	duplicateKeepalive := bytes.Clone(keepalive)
	keepaliveWireSize := len(keepalive)
	clientEndpoint := netip.MustParseAddrPort("192.0.2.44:50044")

	inbound, ack, destination, err := core.HandleNetworkDatagramInPlace(
		newServerDataScratch(t, core),
		clientEndpoint,
		keepalive,
	)
	if err != nil {
		t.Fatalf("HandleNetworkDatagramInPlace(KEEPALIVE): %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != keepaliveID {
		t.Fatalf("inbound=%+v, want KEEPALIVE %#x", inbound, keepaliveID)
	}
	if len(ack) == 0 {
		t.Fatal("accepted current KEEPALIVE did not produce ACK")
	}
	if destination != clientEndpoint {
		t.Fatalf("ACK destination=%v, want %v", destination, clientEndpoint)
	}
	if len(ack) > keepaliveWireSize {
		t.Fatalf("ACK len=%d > triggering KEEPALIVE len=%d", len(ack), keepaliveWireSize)
	}
	if got := core.CurrentSession(peerIP); got != newServer {
		t.Fatal("KEEPALIVE did not promote pending Session to current")
	}

	// ACK must be encrypted through the newly promoted Session, not through the
	// old receive-grace Session.
	clientRX := newTestDataScratch(t, routeKey)
	route, err := dataplane.DecodeRoute(clientRX, ack)
	if err != nil {
		t.Fatalf("DecodeRoute(ACK): %v", err)
	}
	if route.SessionID != newServer.ID() {
		t.Fatalf("ACK session=%#x, want promoted %#x", route.SessionID, newServer.ID())
	}

	plaintext, err := newClient.AuthenticateInPlace(clientRX, ack, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(ACK): %v", err)
	}
	control, err := dataplane.ParseControl(plaintext)
	if err != nil {
		t.Fatalf("ParseControl(ACK): %v", err)
	}
	if control.Type != dataplane.ControlACK || control.KeepaliveID != keepaliveID {
		t.Fatalf("ACK=%+v, want keepalive_id %#x", control, keepaliveID)
	}

	// Exact packet replay is rejected before CONTROL handling, so it cannot
	// generate a second ACK.
	_, secondACK, _, err := core.HandleNetworkDatagramInPlace(
		newServerDataScratch(t, core),
		clientEndpoint,
		duplicateKeepalive,
	)
	if !errors.Is(err, dataplane.ErrReplay) {
		t.Fatalf("duplicate KEEPALIVE error=%v, want ErrReplay", err)
	}
	if len(secondACK) != 0 {
		t.Fatal("replayed KEEPALIVE generated a second ACK")
	}
}

func TestZeroSourcePortCannotPromotePendingOrConsumePacket(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := testPeerTunnelIPv4()

	oldServer, _ := newLifecycleSessionPair(t, 0x6151, 0x11)
	newServer, newClient := newLifecycleSessionPair(t, 0x6152, 0x22)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{{
			TunnelIPv4:     peerIP,
			InitialSession: oldServer,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := core.InstallPendingSession(peerIP, newServer); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	keepalive, _, err := newClient.SealKeepaliveToWithPadding(
		newTestDataScratch(t, routeKey),
		make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
		0x55,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding: %v", err)
	}
	original := bytes.Clone(keepalive)

	if _, _, _, err := core.HandleNetworkDatagramInPlace(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.44:0"),
		keepalive,
	); !errors.Is(err, dataplane.ErrInvalidConfig) {
		t.Fatalf("zero-port source error=%v, want ErrInvalidConfig", err)
	}
	if !bytes.Equal(keepalive, original) {
		t.Fatal("zero-port source reached destructive AEAD path")
	}
	if got := core.CurrentSession(peerIP); got != oldServer {
		t.Fatal("zero-port source promoted pending Session")
	}
}

func TestReceiveGraceKeepaliveIsAcceptedAndACKedOnSameSession(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := testPeerTunnelIPv4()

	oldServer, oldClient := newLifecycleSessionPair(t, 0x6201, 0x31)
	newServer, newClient := newLifecycleSessionPair(t, 0x6202, 0x42)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{{
			TunnelIPv4:     peerIP,
			InitialSession: oldServer,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Unix(1_700_020_000, 0)
	core.now = func() time.Time { return now }
	if err := core.InstallPendingSession(peerIP, newServer); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	// Confirm the new pending Session first, moving oldServer into receive grace.
	newKeepalive, _, err := newClient.SealKeepaliveToWithPadding(
		newTestDataScratch(t, routeKey),
		make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
		1,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+4,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding(new): %v", err)
	}
	if _, _, _, err := core.HandleNetworkDatagramInPlace(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.50:50050"),
		newKeepalive,
	); err != nil {
		t.Fatalf("confirm new pending: %v", err)
	}

	oldKeepalive, _, err := oldClient.SealKeepaliveToWithPadding(
		newTestDataScratch(t, routeKey),
		make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
		2,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+8,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding(old): %v", err)
	}

	oldEndpoint := netip.MustParseAddrPort("192.0.2.51:50051")
	inbound, ack, destination, err := core.HandleNetworkDatagramInPlace(
		newServerDataScratch(t, core),
		oldEndpoint,
		oldKeepalive,
	)
	if err != nil {
		t.Fatalf("receive grace KEEPALIVE: %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != 2 {
		t.Fatalf("inbound=%+v, want grace KEEPALIVE", inbound)
	}
	if len(ack) == 0 {
		t.Fatal("accepted receive-grace KEEPALIVE did not produce ACK")
	}
	if destination != oldEndpoint {
		t.Fatalf("ACK destination=%v, want triggering source %v", destination, oldEndpoint)
	}

	// A KEEPALIVE response is tied to the Session that authenticated the request.
	// This is important for confirmation retries: losing an earlier ACK must not
	// force a new handshake merely because the Session role changed meanwhile.
	ackScratch := newTestDataScratch(t, routeKey)
	route, err := dataplane.DecodeRoute(ackScratch, ack)
	if err != nil {
		t.Fatalf("DecodeRoute(grace ACK): %v", err)
	}
	if route.SessionID != oldServer.ID() {
		t.Fatalf("grace ACK session=%#x, want %#x", route.SessionID, oldServer.ID())
	}
	plaintext, err := oldClient.AuthenticateInPlace(ackScratch, ack, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(grace ACK): %v", err)
	}
	control, err := dataplane.ParseControl(plaintext)
	if err != nil {
		t.Fatalf("ParseControl(grace ACK): %v", err)
	}
	if control.Type != dataplane.ControlACK || control.KeepaliveID != 2 {
		t.Fatalf("grace ACK=%+v, want keepalive_id 2", control)
	}

	if got := core.CurrentSession(peerIP); got != newServer {
		t.Fatal("receive-grace KEEPALIVE changed current Session")
	}
}

func TestSupersededNeverActivePendingKeepaliveDoesNotProduceACK(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := testPeerTunnelIPv4()

	serverA, _ := newLifecycleSessionPair(t, 0x6301, 0x11)
	serverB, clientB := newLifecycleSessionPair(t, 0x6302, 0x22)
	serverC, _ := newLifecycleSessionPair(t, 0x6303, 0x33)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{{
			TunnelIPv4:     peerIP,
			InitialSession: serverA,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_030_000, 0)
	now := t0
	core.now = func() time.Time { return now }
	if err := core.InstallPendingSession(peerIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}

	keepalive, _, err := clientB.SealKeepaliveToWithPadding(
		newTestDataScratch(t, routeKey),
		make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
		0x6302,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+4,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding(B): %v", err)
	}

	source := netip.MustParseAddrPort("192.0.2.63:50063")
	now = t0.Add(100 * time.Millisecond)
	op, err := core.AdmitNetworkDatagram(newServerDataScratch(t, core), source, keepalive)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(B): %v", err)
	}
	if !op.admission.MayPromote {
		t.Fatal("B KEEPALIVE was not admitted as pending")
	}
	if err := op.Decrypt(newServerDataScratch(t, core)); err != nil {
		t.Fatalf("Decrypt(B): %v", err)
	}

	// A newer handshake supersedes B while the admitted B operation is between
	// AEAD and ordered commit. B may finish replay/endpoint/dispatch but must not
	// manufacture reverse transport proving a server switch that never happened.
	now = t0.Add(200 * time.Millisecond)
	if err := core.InstallPendingSession(peerIP, serverC); err != nil {
		t.Fatalf("InstallPendingSession(C): %v", err)
	}

	now = t0.Add(300 * time.Millisecond)
	inbound, outbound, err := core.CommitInbound(op, true)
	if err != nil {
		t.Fatalf("CommitInbound(B): %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != 0x6302 {
		t.Fatalf("inbound=%+v, want stale B KEEPALIVE dispatch", inbound)
	}
	if outbound != nil {
		t.Fatal("superseded never-active B produced ACK")
	}
	if got := core.CurrentSession(peerIP); got != serverA {
		t.Fatal("superseded B changed current Session")
	}
	if endpoint, ok := serverB.Endpoint(); !ok || endpoint != source {
		t.Fatalf("stale admitted B endpoint=(%v,%v), want %v", endpoint, ok, source)
	}
}

func TestParallelPendingKeepalivesMayBothACKAfterOnePromotes(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := testPeerTunnelIPv4()

	serverA, _ := newLifecycleSessionPair(t, 0x6401, 0x11)
	serverB, clientB := newLifecycleSessionPair(t, 0x6402, 0x22)
	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers:              []PeerConfig{{TunnelIPv4: peerIP, InitialSession: serverA}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_031_000, 0)
	core.now = func() time.Time { return t0 }
	if err := core.InstallPendingSession(peerIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}

	makeKeepalive := func(id uint64) []byte {
		wire, _, err := clientB.SealKeepaliveToWithPadding(
			newTestDataScratch(t, routeKey),
			make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize),
			id,
			dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+4,
		)
		if err != nil {
			t.Fatalf("SealKeepaliveToWithPadding(%d): %v", id, err)
		}
		return wire
	}

	source := netip.MustParseAddrPort("192.0.2.64:50064")
	op1, err := core.AdmitNetworkDatagram(newServerDataScratch(t, core), source, makeKeepalive(1))
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(1): %v", err)
	}
	op2, err := core.AdmitNetworkDatagram(newServerDataScratch(t, core), source, makeKeepalive(2))
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(2): %v", err)
	}
	if err := op1.Decrypt(newServerDataScratch(t, core)); err != nil {
		t.Fatalf("Decrypt(1): %v", err)
	}
	if err := op2.Decrypt(newServerDataScratch(t, core)); err != nil {
		t.Fatalf("Decrypt(2): %v", err)
	}

	_, ack1, err := core.CommitInbound(op1, true)
	if err != nil {
		t.Fatalf("CommitInbound(1): %v", err)
	}
	if ack1 == nil {
		t.Fatal("first pending KEEPALIVE did not produce ACK")
	}
	_, ack2, err := core.CommitInbound(op2, true)
	if err != nil {
		t.Fatalf("CommitInbound(2): %v", err)
	}
	if ack2 == nil {
		t.Fatal("second B KEEPALIVE was suppressed even though B was already current")
	}
}
