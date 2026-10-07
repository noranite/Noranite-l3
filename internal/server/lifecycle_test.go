package server

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestPeerPendingReplacementDoesNotCancelAdmittedRX(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}

	peer, err := NewPeer(nil, lifecycle)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	serverA, clientA := newLifecycleSessionPair(t, 0x1001, 0x11)
	serverB, _ := newLifecycleSessionPair(t, 0x1002, 0x22)
	t0 := time.Unix(1_700_000_000, 0)

	pendingA, err := peer.InstallPending(serverA, t0)
	if err != nil {
		t.Fatalf("InstallPending(A): %v", err)
	}

	// Admission is the lifecycle decision point. Once this succeeds, replacing
	// pending cannot revoke the packet operation while AEAD is in flight.
	admission, err := peer.AdmitRX(pendingA, t0.Add(100*time.Millisecond))
	if err != nil {
		t.Fatalf("AdmitRX(A): %v", err)
	}
	if !admission.MayPromote {
		t.Fatal("pending admission did not capture MayPromote")
	}

	wire, sequence := sealLifecyclePacket(
		t,
		clientA,
		routeKey,
		[]byte("authenticated before replacement"),
	)
	rxScratch := newTestDataScratch(t, routeKey)
	if _, err := pendingA.AuthenticateInPlace(rxScratch, wire, sequence); err != nil {
		t.Fatalf("AuthenticateInPlace(A): %v", err)
	}

	// A newer handshake supersedes A while its already-admitted operation is
	// between AEAD and sequential commit.
	if _, err := peer.InstallPending(serverB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallPending(B): %v", err)
	}

	endpointA := netip.MustParseAddrPort("192.0.2.10:50000")
	result, err := peer.CommitAuthenticatedRX(
		admission,
		sequence,
		endpointA,
		t0.Add(time.Second),
	)
	if err != nil {
		t.Fatalf("CommitAuthenticatedRX(A): %v", err)
	}
	if result.Promoted {
		t.Fatal("superseded pending Session was resurrected as current")
	}

	// The admitted operation itself still commits Session-local authenticated
	// state. That state is harmless because A is no longer lifecycle-visible.
	if endpoint, ok := serverA.Endpoint(); !ok || endpoint != endpointA {
		t.Fatalf("admitted stale endpoint=(%v,%v), want %v", endpoint, ok, endpointA)
	}

	if got := peer.LookupRX(serverA.ID(), t0.Add(time.Second)); got != nil {
		t.Fatal("replaced pending Session is still RX-eligible for NEW operations")
	}
	if got := peer.LookupRX(serverB.ID(), t0.Add(time.Second)); got == nil {
		t.Fatal("new pending Session is not RX-eligible")
	}
}

func TestPeerPromotionCreatesReceiveGraceWithoutChangingActivePath(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}

	oldServer, oldClient := newLifecycleSessionPair(
		t,
		0x2001,
		0x31,
	)
	newServer, newClient := newLifecycleSessionPair(
		t,
		0x2002,
		0x42,
	)

	peer, err := NewPeer(oldServer, lifecycle)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	t0 := time.Unix(1_700_000_100, 0)
	oldEndpoint := netip.MustParseAddrPort("192.0.2.10:50000")
	newEndpoint := netip.MustParseAddrPort("192.0.2.20:50001")
	lateOldEndpoint := netip.MustParseAddrPort("192.0.2.30:50002")

	// First, the current session learns an authenticated endpoint.
	commitLifecyclePacket(
		t,
		peer,
		oldClient,
		routeKey,
		oldServer.ID(),
		oldEndpoint,
		t0,
	)

	if _, err := peer.InstallPending(
		newServer,
		t0.Add(100*time.Millisecond),
	); err != nil {
		t.Fatalf("InstallPending(new): %v", err)
	}

	// The first valid pending packet promotes it and gives the old current
	// session a bounded receive-only grace period.
	result := commitLifecyclePacket(
		t,
		peer,
		newClient,
		routeKey,
		newServer.ID(),
		newEndpoint,
		t0.Add(200*time.Millisecond),
	)
	if !result.Promoted {
		t.Fatal("pending Session was not promoted")
	}
	if peer.CurrentSession() != newServer {
		t.Fatal("new Session is not current after promotion")
	}

	// The old session may still receive in-flight packets during grace.
	graceTime := t0.Add(time.Second)
	if got := peer.LookupRX(oldServer.ID(), graceTime); got == nil {
		t.Fatal("old current is not RX-eligible during receive grace")
	}

	commitLifecyclePacket(
		t,
		peer,
		oldClient,
		routeKey,
		oldServer.ID(),
		lateOldEndpoint,
		graceTime,
	)

	// A grace session may update its own endpoint; outbound traffic still uses
	// only the current session.
	if endpoint, ok := oldServer.Endpoint(); !ok || endpoint != lateOldEndpoint {
		t.Fatalf(
			"old grace endpoint=(%v,%v), want %v",
			endpoint,
			ok,
			lateOldEndpoint,
		)
	}

	// New outbound traffic must use the new current session and endpoint.
	inner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		[]byte("server outbound"),
	)
	txScratch := newTestDataScratch(t, routeKey)
	dst := make([]byte, 0, len(inner)+dataplane.MaxDataExpansion)

	wire, destination, err := peer.SealCurrentDataTo(
		txScratch,
		dst,
		inner,
		graceTime,
	)
	if err != nil {
		t.Fatalf("SealCurrentDataTo: %v", err)
	}
	if destination != newEndpoint {
		t.Fatalf("destination=%v, want new endpoint %v", destination, newEndpoint)
	}

	route, err := dataplane.DecodeRoute(txScratch, wire)
	if err != nil {
		t.Fatalf("DecodeRoute(outbound): %v", err)
	}
	if route.SessionID != newServer.ID() {
		t.Fatalf(
			"outbound session=%#x, want current %#x",
			route.SessionID,
			newServer.ID(),
		)
	}

	// Grace expires exactly at the deadline because eligibility is strict.
	graceDeadline := t0.Add(200 * time.Millisecond).Add(lifecycle.ReceiveGrace)
	if got := peer.LookupRX(oldServer.ID(), graceDeadline); got != nil {
		t.Fatal("old Session remained RX-eligible at grace deadline")
	}
}

func TestPeerPendingDeadlineRejectsNewAdmission(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	peer, err := NewPeer(nil, lifecycle)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	serverSession, _ := newLifecycleSessionPair(t, 0x3001, 0x53)
	t0 := time.Unix(1_700_000_200, 0)
	pending, err := peer.InstallPending(serverSession, t0)
	if err != nil {
		t.Fatalf("InstallPending: %v", err)
	}

	_, err = peer.AdmitRX(pending, t0.Add(lifecycle.GenerationLifetime))
	if !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("AdmitRX at deadline error=%v, want ErrSessionNotRXEligible", err)
	}
	if endpoint, ok := serverSession.Endpoint(); ok {
		t.Fatalf("rejected admission learned endpoint %v", endpoint)
	}
}

func TestPeerAdmissionBeforePendingDeadlineCommitsAfterDeadline(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	peer, err := NewPeer(nil, lifecycle)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	serverSession, clientSession := newLifecycleSessionPair(t, 0x3002, 0x54)
	t0 := time.Unix(1_700_000_200, 0)
	pending, err := peer.InstallPending(serverSession, t0)
	if err != nil {
		t.Fatalf("InstallPending: %v", err)
	}

	receivedAt := t0.Add(lifecycle.GenerationLifetime - time.Nanosecond)
	admission, err := peer.AdmitRX(pending, receivedAt)
	if err != nil {
		t.Fatalf("AdmitRX before deadline: %v", err)
	}

	wire, sequence := sealLifecyclePacket(
		t,
		clientSession,
		routeKey,
		[]byte("admitted before expiry"),
	)
	rxScratch := newTestDataScratch(t, routeKey)
	if _, err := pending.AuthenticateInPlace(rxScratch, wire, sequence); err != nil {
		t.Fatalf("AuthenticateInPlace: %v", err)
	}

	endpoint := netip.MustParseAddrPort("192.0.2.40:50003")
	committedAt := t0.Add(lifecycle.GenerationLifetime + 250*time.Millisecond)
	result, err := peer.CommitAuthenticatedRX(
		admission,
		sequence,
		endpoint,
		committedAt,
	)
	if err != nil {
		t.Fatalf("CommitAuthenticatedRX after deadline: %v", err)
	}
	if !result.Promoted {
		t.Fatal("admitted pending packet did not promote after worker delay")
	}
	if peer.CurrentSession() != serverSession {
		t.Fatal("admitted Session is not current after delayed commit")
	}
	if got, ok := serverSession.Endpoint(); !ok || got != endpoint {
		t.Fatalf("endpoint=(%v,%v), want %v", got, ok, endpoint)
	}
}

func newLifecycleSessionPair(
	t *testing.T,
	sessionID uint64,
	keyTweak byte,
) (serverSession, clientSession *dataplane.Session) {
	t.Helper()

	_, c2s, s2c := testKeys()
	for i := range c2s {
		c2s[i] ^= keyTweak
		s2c[i] ^= keyTweak
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

	clientSession, err = dataplane.NewSession(
		sessionID,
		c2s,
		s2c,
		0,
	)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}

	return serverSession, clientSession
}

func sealLifecyclePacket(
	t *testing.T,
	clientSession *dataplane.Session,
	routeKey [32]byte,
	plaintext []byte,
) (wire []byte, sequence uint64) {
	t.Helper()

	txScratch := newTestDataScratch(t, routeKey)
	dst := make([]byte, 0, len(plaintext)+dataplane.DataOverhead)

	wire, sequence, err := clientSession.SealDataToWithPadding(
		txScratch,
		dst,
		plaintext,
		0,
	)
	if err != nil {
		t.Fatalf("SealDataToWithPadding: %v", err)
	}

	return bytes.Clone(wire), sequence
}

func commitLifecyclePacket(
	t *testing.T,
	peer *Peer,
	clientSession *dataplane.Session,
	routeKey [32]byte,
	sessionID uint64,
	source netip.AddrPort,
	now time.Time,
) RXCommitResult {
	t.Helper()

	candidate := peer.LookupRX(sessionID, now)
	if candidate == nil {
		t.Fatalf("LookupRX(%#x): no RX-eligible Session", sessionID)
	}
	admission, err := peer.AdmitRX(candidate, now)
	if err != nil {
		t.Fatalf("AdmitRX(%#x): %v", sessionID, err)
	}

	wire, sequence := sealLifecyclePacket(
		t,
		clientSession,
		routeKey,
		[]byte("lifecycle packet"),
	)
	rxScratch := newTestDataScratch(t, routeKey)

	if _, err := candidate.AuthenticateInPlace(
		rxScratch,
		wire,
		sequence,
	); err != nil {
		t.Fatalf("AuthenticateInPlace(%#x): %v", sessionID, err)
	}

	result, err := peer.CommitAuthenticatedRX(
		admission,
		sequence,
		source,
		now,
	)
	if err != nil {
		t.Fatalf("CommitAuthenticatedRX(%#x): %v", sessionID, err)
	}

	return result
}

func TestCorePendingPromotesThroughNormalReceivePath(t *testing.T) {
	server, oldClient, routeKey := newTestServer(t, 0, 0)

	// Freeze lifecycle time so this test verifies state transitions, not wall
	// clock timing.
	now := time.Unix(1_700_000_300, 0)
	server.now = func() time.Time { return now }

	oldEndpoint := netip.MustParseAddrPort("192.0.2.50:50004")
	oldInner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("old current"),
	)
	oldWire, _ := sealTestPacket(t, oldClient, &routeKey, oldInner)

	if _, err := server.HandleDatagramInPlace(
		newServerDataScratch(t, server),
		oldEndpoint,
		oldWire,
	); err != nil {
		t.Fatalf("receive old current: %v", err)
	}

	newServerSession, newClientSession := newLifecycleSessionPair(
		t,
		0x4001,
		0x64,
	)
	if err := server.InstallPendingSession(testPeerTunnelIPv4(), newServerSession); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	newEndpoint := netip.MustParseAddrPort("192.0.2.60:50005")
	newInner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("new pending confirms itself"),
	)
	newWire, _ := sealTestPacket(t, newClientSession, &routeKey, newInner)

	opened, err := server.HandleDatagramInPlace(
		newServerDataScratch(t, server),
		newEndpoint,
		newWire,
	)
	if err != nil {
		t.Fatalf("receive pending: %v", err)
	}
	if !bytes.Equal(opened, newInner) {
		t.Fatal("pending receive returned wrong inner packet")
	}
	if server.CurrentSession(testPeerTunnelIPv4()) != newServerSession {
		t.Fatal("normal receive path did not promote pending Session")
	}

	// Server outbound immediately follows the promoted current Session and its
	// authenticated endpoint.
	toClient := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		[]byte("reply through promoted session"),
	)
	out := make([]byte, 0, len(toClient)+dataplane.MaxDataExpansion)
	txScratch := newServerDataScratch(t, server)

	wire, destination, err := server.HandleInnerPacketTo(
		txScratch,
		out,
		toClient,
	)
	if err != nil {
		t.Fatalf("HandleInnerPacketTo: %v", err)
	}
	if destination != newEndpoint {
		t.Fatalf("outbound destination=%v, want %v", destination, newEndpoint)
	}

	route, err := dataplane.DecodeRoute(txScratch, wire)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if route.SessionID != newServerSession.ID() {
		t.Fatalf(
			"outbound session=%#x, want promoted %#x",
			route.SessionID,
			newServerSession.ID(),
		)
	}
}

func TestPeerPromotionPreservesGenerationRejectAt(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_000_300, 0)
	peer, err := newPeerAt(nil, lifecycle, t0)
	if err != nil {
		t.Fatalf("newPeerAt: %v", err)
	}

	serverB, clientB := newLifecycleSessionPair(t, 0x3101, 0x61)
	if _, err := peer.InstallPending(serverB, t0); err != nil {
		t.Fatalf("InstallPending(B): %v", err)
	}

	commitLifecyclePacket(
		t,
		peer,
		clientB,
		routeKey,
		serverB.ID(),
		netip.MustParseAddrPort("192.0.2.61:50061"),
		t0.Add(500*time.Millisecond),
	)
	if peer.CurrentSession() != serverB {
		t.Fatal("B is not current after promotion")
	}

	// Promotion must not refresh the generation lifetime. B was installed at t0,
	// so it is no longer admissible exactly at t0+GenerationLifetime.
	if got := peer.LookupRX(serverB.ID(), t0.Add(lifecycle.GenerationLifetime)); got != nil {
		t.Fatal("promotion refreshed B rejectAt")
	}
	if _, err := peer.AdmitCurrentData(t0.Add(lifecycle.GenerationLifetime)); !errors.Is(err, ErrSessionNotTXEligible) {
		t.Fatalf("AdmitCurrentData at hard deadline error=%v, want ErrSessionNotTXEligible", err)
	}
}

func TestPeerHardTXDeadlineRejectsBeforeSequenceReservation(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       500 * time.Millisecond,
	}
	t0 := time.Unix(1_700_000_400, 0)
	serverSession, _ := newLifecycleSessionPairWithSequence(t, 0x3201, 0x71, 9)
	peer, err := newPeerAt(serverSession, lifecycle, t0)
	if err != nil {
		t.Fatalf("newPeerAt: %v", err)
	}

	// Endpoint absence would otherwise fail earlier, so establish one while the
	// generation is still hard-valid.
	if _, err := serverSession.CommitAuthenticatedRX(
		0,
		netip.MustParseAddrPort("192.0.2.72:50072"),
	); err != nil {
		t.Fatalf("CommitAuthenticatedRX(endpoint): %v", err)
	}

	if _, err := peer.AdmitCurrentData(t0.Add(time.Second)); !errors.Is(err, ErrSessionNotTXEligible) {
		t.Fatalf("AdmitCurrentData at deadline error=%v, want ErrSessionNotTXEligible", err)
	}
	sequence, err := serverSession.ReserveTXSequence()
	if err != nil {
		t.Fatalf("ReserveTXSequence after rejected TX admission: %v", err)
	}
	if sequence != 9 {
		t.Fatalf("sequence=%d, want 9; hard-expired TX admission consumed sequence", sequence)
	}
}

func newLifecycleSessionPairWithSequence(
	t *testing.T,
	sessionID uint64,
	keyTweak byte,
	serverInitialSequence uint64,
) (serverSession, clientSession *dataplane.Session) {
	t.Helper()
	_, c2s, s2c := testKeys()
	for i := range c2s {
		c2s[i] ^= keyTweak
		s2c[i] ^= keyTweak
	}

	var err error
	serverSession, err = dataplane.NewSession(sessionID, s2c, c2s, serverInitialSequence)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}
	clientSession, err = dataplane.NewSession(sessionID, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	return serverSession, clientSession
}
