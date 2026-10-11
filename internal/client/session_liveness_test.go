package client

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestClientCurrentRXTimestampIgnoresPreviousGeneration(t *testing.T) {
	t0 := time.Unix(1_800_001_000, 0)
	clientA, _, _ := controllerSessionPair(t, 0xd100, 0x11)
	clientB, _, _ := controllerSessionPair(t, 0xd101, 0x31)

	peer, err := NewPeer(clientA, LifecycleConfig{
		GenerationLifetime: time.Minute,
		ReceiveGrace:       5 * time.Second,
	}, t0)
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if _, err := peer.InstallInitiatorSession(clientB, t0); err != nil {
		t.Fatalf("InstallInitiatorSession: %v", err)
	}

	source := netip.MustParseAddrPort("127.0.0.1:51000")
	if _, err := peer.CommitAuthenticatedRX(RXAdmission{
		Session:    clientA,
		ReceivedAt: t0.Add(time.Second),
	}, 1, source); err != nil {
		t.Fatalf("previous CommitAuthenticatedRX: %v", err)
	}
	if got := peer.lastAuthenticatedCurrentRX(); !got.IsZero() {
		t.Fatalf("previous generation changed current RX timestamp: %v", got)
	}

	currentAt := t0.Add(2 * time.Second)
	if _, err := peer.CommitAuthenticatedRX(RXAdmission{
		Session:    clientB,
		ReceivedAt: currentAt,
	}, 1, source); err != nil {
		t.Fatalf("current CommitAuthenticatedRX: %v", err)
	}
	if got := peer.lastAuthenticatedCurrentRX(); !got.Equal(currentAt) {
		t.Fatalf("current RX timestamp=%v, want %v", got, currentAt)
	}
}

func TestSessionControllerActivityProbeStartsAfterThirtySecondsWithoutCurrentRX(t *testing.T) {
	t0 := time.Unix(1_800_001_100, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xd110, 0x12)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:51100")
	core := controllerLivenessCore(
		t,
		clock,
		netip.MustParseAddr("10.94.0.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        45 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	recordControllerCurrentRX(t, core, clientA, serverEndpoint, t0, 1)

	clock.Advance(29 * time.Second)
	controller.HandleOutboundActivity()
	controller.mu.Lock()
	nextBeforeIdle := controller.nextKeepalive
	controller.mu.Unlock()
	if !nextBeforeIdle.IsZero() {
		t.Fatalf("probe scheduled before 30s idle: %v", nextBeforeIdle)
	}

	clock.Advance(time.Second)
	controller.HandleOutboundActivity()
	controller.mu.Lock()
	nextAtIdle := controller.nextKeepalive
	controller.mu.Unlock()
	if !nextAtIdle.Equal(clock.Now()) {
		t.Fatalf("probe deadline=%v, want immediate %v", nextAtIdle, clock.Now())
	}

	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit activity probe: %v", err)
	}
	if len(runtime.transport) != 1 || runtime.transport[0].kind != outboundKeepalive {
		t.Fatalf("activity probe submissions=%d, want one KEEPALIVE", len(runtime.transport))
	}

	clock.Advance(time.Second)
	recordControllerCurrentRX(t, core, clientA, serverEndpoint, clock.Now(), 2)
	clock.Advance(defaultActivityProbeTimeout - time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("post-RX probe deadline: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("authenticated current RX did not cancel probe retry: submissions=%d", len(runtime.transport))
	}
	if factory.starts != 0 {
		t.Fatalf("authenticated current RX still triggered establishment: %d", factory.starts)
	}
}

func TestSessionControllerDelayedCurrentRXStillCancelsProbeCycle(t *testing.T) {
	t0 := time.Unix(1_800_001_150, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xd115, 0x14)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:51150")
	core := controllerLivenessCore(
		t,
		clock,
		netip.MustParseAddr("10.94.0.3"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        45 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	recordControllerCurrentRX(t, core, clientA, serverEndpoint, t0, 1)
	clock.Advance(activityProbeIdle)
	controller.HandleOutboundActivity()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit first probe: %v", err)
	}

	firstProbeAt := clock.Now()
	clock.Advance(defaultActivityProbeTimeout)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("first probe timeout: %v", err)
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("probe submissions=%d after first timeout, want 2", len(runtime.transport))
	}

	// Model an RX packet that arrived after probe #1 but sat in the local RX
	// pipeline until probe #2 had already been emitted. Its network arrival time
	// still proves the peer was alive during this probe cycle.
	delayedArrival := firstProbeAt.Add(time.Second)
	recordControllerCurrentRX(t, core, clientA, serverEndpoint, delayedArrival, 2)

	clock.Advance(defaultActivityProbeTimeout)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("second probe deadline: %v", err)
	}
	if factory.starts != 0 {
		t.Fatalf("delayed authenticated RX incorrectly triggered establishment: %d", factory.starts)
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("unexpected extra probe after delayed RX: submissions=%d", len(runtime.transport))
	}
}

func TestSessionControllerTwoMissedActivityProbesStartFreshEstablishment(t *testing.T) {
	t0 := time.Unix(1_800_001_200, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xd120, 0x13)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:51200")
	core := controllerLivenessCore(
		t,
		clock,
		netip.MustParseAddr("10.94.1.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{Outbound: []EstablishmentDatagram{{
			Packet:      []byte("activity-recovery-init"),
			Destination: serverEndpoint,
		}}}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        45 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	recordControllerCurrentRX(t, core, clientA, serverEndpoint, t0, 1)
	clock.Advance(activityProbeIdle)
	controller.HandleOutboundActivity()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit first activity probe: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("first activity probe submissions=%d, want 1", len(runtime.transport))
	}

	clock.Advance(defaultActivityProbeTimeout)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("first activity probe timeout: %v", err)
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("second activity probe submissions=%d, want 2", len(runtime.transport))
	}
	if factory.starts != 0 {
		t.Fatalf("establishment started after one missed probe: %d", factory.starts)
	}

	clock.Advance(defaultActivityProbeTimeout)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("second activity probe timeout: %v", err)
	}
	if factory.starts != 1 {
		t.Fatalf("establishment starts=%d after two missed probes, want 1", factory.starts)
	}
	if len(runtime.raw) != 1 || !bytes.Equal(runtime.raw[0].Packet, []byte("activity-recovery-init")) {
		t.Fatalf("activity recovery raw output=%v", runtime.raw)
	}
	if core.Session() != clientA {
		t.Fatal("liveness recovery changed current generation before establishment success")
	}
}

func TestSessionControllerReboundStaysSilentUntilDataThenProbesNewPath(t *testing.T) {
	t0 := time.Unix(1_800_001_240, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xd124, 0x15)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:51240")
	core := controllerLivenessCore(
		t,
		clock,
		netip.MustParseAddr("10.94.1.4"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        45 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	recordControllerCurrentRX(t, core, clientA, serverEndpoint, t0, 1)
	clock.Advance(5 * time.Second)
	controller.TransportRebound()
	controller.mu.Lock()
	next := controller.nextDueLocked()
	pathNeedsProof := controller.pathNeedsProof
	controller.mu.Unlock()
	if !next.IsZero() {
		t.Fatalf("idle rebound armed protocol work at %v", next)
	}
	if !pathNeedsProof {
		t.Fatal("rebound did not invalidate proof of the outer path")
	}

	controller.HandleOutboundActivity()
	controller.mu.Lock()
	next = controller.nextKeepalive
	controller.mu.Unlock()
	if !next.Equal(clock.Now()) {
		t.Fatalf("first DATA after rebound scheduled probe at %v, want %v", next, clock.Now())
	}
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit rebound path probe: %v", err)
	}
	if len(runtime.transport) != 1 || runtime.transport[0].kind != outboundKeepalive {
		t.Fatalf("rebound path probe submissions=%d, want one KEEPALIVE", len(runtime.transport))
	}
	if factory.starts != 0 {
		t.Fatalf("rebound path proof started establishment: %d", factory.starts)
	}
}

func TestSessionControllerReboundPreservesActiveActivityRecovery(t *testing.T) {
	t0 := time.Unix(1_800_001_260, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xd126, 0x16)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:51260")
	core := controllerLivenessCore(
		t,
		clock,
		netip.MustParseAddr("10.94.1.6"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        45 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	recordControllerCurrentRX(t, core, clientA, serverEndpoint, t0, 1)
	clock.Advance(activityProbeIdle)
	controller.HandleOutboundActivity()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit old-path activity probe: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("old-path activity probes=%d, want 1", len(runtime.transport))
	}

	controller.TransportRebound()
	controller.mu.Lock()
	next := controller.nextKeepalive
	if controller.outstandingProbeID != 0 || !controller.keepaliveDeadline.IsZero() || controller.keepaliveTimeouts != 0 {
		t.Fatalf("old-path probe state survived rebound: id=%d deadline=%v timeouts=%d",
			controller.outstandingProbeID, controller.keepaliveDeadline, controller.keepaliveTimeouts)
	}
	controller.mu.Unlock()
	if !next.Equal(clock.Now()) {
		t.Fatalf("active recovery after rebound scheduled at %v, want immediate %v", next, clock.Now())
	}
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit replacement-path activity probe: %v", err)
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("activity probes after rebound=%d, want 2", len(runtime.transport))
	}
}

func recordControllerCurrentRX(
	t *testing.T,
	core *Core,
	session *dataplane.Session,
	source netip.AddrPort,
	receivedAt time.Time,
	sequence uint64,
) {
	t.Helper()
	if _, err := core.peer.CommitAuthenticatedRX(RXAdmission{
		Session:    session,
		ReceivedAt: receivedAt,
	}, sequence, source); err != nil {
		t.Fatalf("CommitAuthenticatedRX: %v", err)
	}
}

func controllerLivenessCore(
	t *testing.T,
	clock *controllerFakeClock,
	clientIP netip.Addr,
	serverEndpoint netip.AddrPort,
	initial *dataplane.Session,
) *Core {
	t.Helper()
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0xb0 + i)
	}
	core, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: time.Minute,
			ReceiveGrace:       5 * time.Second,
		},
		Session: initial,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	core.now = clock.Now
	if initial != nil {
		core.peer.current.rejectAt = clock.Now().Add(core.peer.lifecycle.GenerationLifetime)
	}
	return core
}
