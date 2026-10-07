package client

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestPeerInstallInitiatorSessionRotatesCurrentPrevious(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_000, 0)

	clientA, _ := newClientLifecycleSessionPair(t, 0x8101, 0x11, 0)
	clientB, _ := newClientLifecycleSessionPair(t, 0x8102, 0x22, 0)
	clientC, _ := newClientLifecycleSessionPair(t, 0x8103, 0x33, 0)

	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	if retired, err := peer.InstallInitiatorSession(clientB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	} else if retired != nil {
		t.Fatalf("first rotation retired %p, want nil", retired)
	}
	if peer.CurrentSession() != clientB {
		t.Fatal("B is not current after install")
	}
	if got := peer.LookupRX(clientA.ID(), t0.Add(2*time.Second)); got != clientA {
		t.Fatal("A is not RX-eligible as previous before short grace is armed")
	}

	tx, err := peer.AdmitCurrentTX(t0.Add(2 * time.Second))
	if err != nil {
		t.Fatalf("AdmitCurrentTX(B): %v", err)
	}
	if tx.Session != clientB {
		t.Fatal("TX did not pin B current")
	}

	retired, err := peer.InstallInitiatorSession(clientC, t0.Add(3*time.Second))
	if err != nil {
		t.Fatalf("InstallInitiatorSession(C): %v", err)
	}
	if retired != clientA {
		t.Fatal("C install did not retire old previous A")
	}
	if peer.CurrentSession() != clientC {
		t.Fatal("C is not current after install")
	}
	if got := peer.LookupRX(clientA.ID(), t0.Add(3*time.Second)); got != nil {
		t.Fatal("retired A remained RX-eligible")
	}
	if got := peer.LookupRX(clientB.ID(), t0.Add(3*time.Second)); got != clientB {
		t.Fatal("B is not previous after C install")
	}
}

func TestPeerCurrentAuthenticatedRXArmsPreviousGraceFromReceivedAt(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 20 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_100, 0)

	clientA, _ := newClientLifecycleSessionPair(t, 0x8201, 0x11, 0)
	clientB, serverB := newClientLifecycleSessionPair(t, 0x8202, 0x22, 0)
	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if _, err := peer.InstallInitiatorSession(clientB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}

	receivedAt := t0.Add(3 * time.Second)
	admission, err := peer.AdmitRX(clientB.ID(), receivedAt)
	if err != nil {
		t.Fatalf("AdmitRX(B): %v", err)
	}
	sequence := authenticateLifecycleInbound(t, clientB, serverB, admission, []byte("reverse B"))

	result, err := peer.CommitAuthenticatedRX(
		admission,
		sequence,
		netip.MustParseAddrPort("198.51.100.10:51820"),
	)
	if err != nil {
		t.Fatalf("CommitAuthenticatedRX(B): %v", err)
	}
	if !result.ArmedPreviousGrace {
		t.Fatal("authenticated current B did not arm grace for A")
	}

	deadline := receivedAt.Add(lifecycle.ReceiveGrace)
	if got := peer.LookupRX(clientA.ID(), deadline.Add(-time.Nanosecond)); got != clientA {
		t.Fatal("A rejected before short grace deadline")
	}
	if got := peer.LookupRX(clientA.ID(), deadline); got != nil {
		t.Fatal("A remained RX-eligible at short grace deadline")
	}
}

func TestPeerDelayedCurrentCommitDoesNotRetroactivelyCancelPreviousAdmission(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_200, 0)

	clientA, serverA := newClientLifecycleSessionPair(t, 0x8301, 0x31, 0)
	clientB, serverB := newClientLifecycleSessionPair(t, 0x8302, 0x42, 0)
	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if _, err := peer.InstallInitiatorSession(clientB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}

	bReceivedAt := t0.Add(2 * time.Second)
	bAdmission, err := peer.AdmitRX(clientB.ID(), bReceivedAt)
	if err != nil {
		t.Fatalf("AdmitRX(B): %v", err)
	}
	bSequence := authenticateLifecycleInbound(t, clientB, serverB, bAdmission, []byte("slow B"))

	// This is after the grace deadline that B will eventually establish, but B
	// has not committed yet. Admission is therefore still valid and must survive.
	aReceivedAt := t0.Add(5 * time.Second)
	aAdmission, err := peer.AdmitRX(clientA.ID(), aReceivedAt)
	if err != nil {
		t.Fatalf("AdmitRX(A before B commit): %v", err)
	}
	aSequence := authenticateLifecycleInbound(t, clientA, serverA, aAdmission, []byte("already admitted A"))

	if result, err := peer.CommitAuthenticatedRX(
		bAdmission,
		bSequence,
		netip.MustParseAddrPort("198.51.100.10:51820"),
	); err != nil {
		t.Fatalf("CommitAuthenticatedRX(B): %v", err)
	} else if !result.ArmedPreviousGrace {
		t.Fatal("B commit did not arm previous grace")
	}

	if got := peer.LookupRX(clientA.ID(), t0.Add(5*time.Second)); got != nil {
		t.Fatal("new A admission was accepted after computed grace deadline")
	}

	if _, err := peer.CommitAuthenticatedRX(
		aAdmission,
		aSequence,
		netip.MustParseAddrPort("198.51.100.10:51820"),
	); err != nil {
		t.Fatalf("already-admitted A failed after grace became armed: %v", err)
	}
}

func TestPeerStaleCurrentCompletionAfterInstallDoesNotArmNewPreviousGrace(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_300, 0)

	clientA, _ := newClientLifecycleSessionPair(t, 0x8401, 0x11, 0)
	clientB, serverB := newClientLifecycleSessionPair(t, 0x8402, 0x22, 0)
	clientC, _ := newClientLifecycleSessionPair(t, 0x8403, 0x33, 0)
	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if _, err := peer.InstallInitiatorSession(clientB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}

	bAdmission, err := peer.AdmitRX(clientB.ID(), t0.Add(2*time.Second))
	if err != nil {
		t.Fatalf("AdmitRX(B): %v", err)
	}
	bSequence := authenticateLifecycleInbound(t, clientB, serverB, bAdmission, []byte("stale B completion"))

	if _, err := peer.InstallInitiatorSession(clientC, t0.Add(3*time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(C): %v", err)
	}
	result, err := peer.CommitAuthenticatedRX(
		bAdmission,
		bSequence,
		netip.MustParseAddrPort("198.51.100.10:51820"),
	)
	if err != nil {
		t.Fatalf("CommitAuthenticatedRX(stale B): %v", err)
	}
	if result.ArmedPreviousGrace {
		t.Fatal("stale B completion armed grace for B after C became current")
	}

	// If stale B had armed grace from receivedAt+2s, this lookup at +10s would
	// fail. B must instead remain eligible until its hard generation deadline.
	if got := peer.LookupRX(clientB.ID(), t0.Add(10*time.Second)); got != clientB {
		t.Fatal("B previous was shortened by stale B completion")
	}
}

func TestPeerHardTXDeadlineRejectsBeforeSequenceReservation(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       500 * time.Millisecond,
	}
	t0 := time.Unix(1_700_200_400, 0)
	clientA, _ := newClientLifecycleSessionPair(t, 0x8501, 0x11, 7)
	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	if _, err := peer.AdmitCurrentTX(t0.Add(time.Second)); !errors.Is(err, ErrSessionNotTXEligible) {
		t.Fatalf("AdmitCurrentTX at deadline error=%v, want ErrSessionNotTXEligible", err)
	}
	sequence, err := clientA.ReserveTXSequence()
	if err != nil {
		t.Fatalf("ReserveTXSequence after rejected admission: %v", err)
	}
	if sequence != 7 {
		t.Fatalf("sequence=%d, want 7; expired TX admission consumed a sequence", sequence)
	}
}

func TestPeerGenerationIDCollisionAcrossResidentSlots(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_500, 0)
	clientA, _ := newClientLifecycleSessionPair(t, 0x8601, 0x11, 0)
	clientB, _ := newClientLifecycleSessionPair(t, 0x8602, 0x22, 0)
	collisionWithA, _ := newClientLifecycleSessionPair(t, clientA.ID(), 0x44, 0)

	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if _, err := peer.InstallInitiatorSession(clientB, t0.Add(time.Second)); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}
	if _, err := peer.InstallInitiatorSession(collisionWithA, t0.Add(2*time.Second)); !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("collision error=%v, want ErrSessionIDCollision", err)
	}
}

func newClientLifecycleSessionPair(
	t *testing.T,
	sessionID uint64,
	keyTweak byte,
	initialSequence uint64,
) (clientSession, serverSession *dataplane.Session) {
	t.Helper()
	_, c2s, s2c := testKeys()
	for i := range c2s {
		c2s[i] ^= keyTweak
		s2c[i] ^= keyTweak
	}

	var err error
	clientSession, err = dataplane.NewSession(sessionID, c2s, s2c, initialSequence)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	serverSession, err = dataplane.NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}
	return clientSession, serverSession
}

func authenticateLifecycleInbound(
	t *testing.T,
	clientSession *dataplane.Session,
	serverSession *dataplane.Session,
	admission RXAdmission,
	payload []byte,
) uint64 {
	t.Helper()
	routeKey, _, _ := testKeys()
	txScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(TX): %v", err)
	}
	rxScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(RX): %v", err)
	}

	wire, sequence, err := serverSession.SealDataToWithPadding(
		txScratch,
		make([]byte, 0, len(payload)+dataplane.DataOverhead),
		payload,
		0,
	)
	if err != nil {
		t.Fatalf("SealDataToWithPadding: %v", err)
	}
	if admission.Session != clientSession {
		t.Fatal("admission did not pin expected client Session")
	}
	if _, err := clientSession.AuthenticateInPlace(rxScratch, wire, sequence); err != nil {
		t.Fatalf("AuthenticateInPlace: %v", err)
	}
	return sequence
}

func TestPeerCanInstallFirstInitiatorSessionFromEmptyState(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       2 * time.Second,
	}
	t0 := time.Unix(1_700_200_600, 0)
	peer, err := NewPeer(nil, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer(nil): %v", err)
	}
	if _, err := peer.AdmitCurrentTX(t0); !errors.Is(err, ErrNoCurrentSession) {
		t.Fatalf("empty AdmitCurrentTX error=%v, want ErrNoCurrentSession", err)
	}

	clientA, _ := newClientLifecycleSessionPair(t, 0x8701, 0x11, 0)
	retired, err := peer.InstallInitiatorSession(clientA, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("InstallInitiatorSession(A): %v", err)
	}
	if retired != nil {
		t.Fatal("first install retired a Session")
	}
	if peer.CurrentSession() != clientA {
		t.Fatal("first installed Session is not current")
	}
}

func TestPeerHardRXDeadlineDoesNotCancelAdmittedOperation(t *testing.T) {
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       500 * time.Millisecond,
	}
	t0 := time.Unix(1_700_200_700, 0)
	clientA, serverA := newClientLifecycleSessionPair(t, 0x8801, 0x11, 0)
	peer, err := NewPeer(clientA, lifecycle, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}

	receivedAt := t0.Add(time.Second - time.Nanosecond)
	admission, err := peer.AdmitRX(clientA.ID(), receivedAt)
	if err != nil {
		t.Fatalf("AdmitRX before hard deadline: %v", err)
	}
	sequence := authenticateLifecycleInbound(t, clientA, serverA, admission, []byte("hard-deadline admitted"))

	if _, err := peer.AdmitRX(clientA.ID(), t0.Add(time.Second)); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("AdmitRX at hard deadline error=%v, want ErrSessionNotRXEligible", err)
	}
	if _, err := peer.CommitAuthenticatedRX(
		admission,
		sequence,
		netip.MustParseAddrPort("198.51.100.10:51820"),
	); err != nil {
		t.Fatalf("already-admitted RX failed after hard deadline: %v", err)
	}
}
