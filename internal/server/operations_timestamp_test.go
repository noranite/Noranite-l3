package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestServerAdmitNetworkDatagramAtUsesCapturedDequeueTimestamp(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 0)
	endpoint := netip.MustParseAddrPort("192.0.2.10:50000")

	// New installed the current generation immediately before this timestamp, so
	// receivedAt is inside its hard admission lifetime. Move the Core clock far
	// beyond that deadline to model synchronous control-plane classification
	// completing much later than the userspace UDP dequeue timestamp.
	receivedAt := time.Now()
	core.now = func() time.Time { return receivedAt.Add(24 * time.Hour) }

	inner := testIPv4Packet(
		t,
		testPeerTunnelIPv4().String(),
		"10.66.0.1",
		[]byte("captured before server demux"),
	)
	wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)

	lateScratch := newServerDataScratch(t, core)
	if _, err := core.AdmitNetworkDatagram(lateScratch, endpoint, wire); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("late implicit timestamp error=%v, want ErrSessionNotRXEligible", err)
	}

	ingressScratch := newServerDataScratch(t, core)
	op, err := core.AdmitNetworkDatagramAt(ingressScratch, endpoint, wire, receivedAt)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagramAt(receivedAt): %v", err)
	}
	if op.admission.Session == nil || op.admission.Session.ID() != clientSession.ID() {
		t.Fatalf("admission Session=%v, want session_id %#x", op.admission.Session, clientSession.ID())
	}
}
