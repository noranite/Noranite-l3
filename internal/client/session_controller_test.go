package client

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
	"github.com/noranite/Noranite-l3/internal/server"
)

type controllerTestRuntime struct {
	ready chan struct{}
	done  chan struct{}

	mu        sync.Mutex
	raw       []EstablishmentDatagram
	transport []*OutboundOperation
}

func newControllerTestRuntime() *controllerTestRuntime {
	ready := make(chan struct{})
	close(ready)
	return &controllerTestRuntime{ready: ready, done: make(chan struct{})}
}

func (r *controllerTestRuntime) SendProtocolDatagram(packet []byte, destination netip.AddrPort) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copyPacket := append([]byte(nil), packet...)
	r.raw = append(r.raw, EstablishmentDatagram{Packet: copyPacket, Destination: destination})
	return nil
}

func (r *controllerTestRuntime) SubmitProtocolTransport(op *OutboundOperation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transport = append(r.transport, op)
	return nil
}

func (r *controllerTestRuntime) Ready() <-chan struct{} { return r.ready }
func (r *controllerTestRuntime) Done() <-chan struct{}  { return r.done }

type controllerTestFactory struct {
	mu         sync.Mutex
	starts     int
	startFn    func(int, time.Time) (EstablishmentAttempt, EstablishmentUpdate, error)
	classifyFn func([]byte) bool
	startedC   chan int
}

func (f *controllerTestFactory) IsEstablishmentDatagram(
	_ dataplane.Route,
	_ bool,
	packet []byte,
) bool {
	if f.classifyFn != nil {
		return f.classifyFn(packet)
	}
	return true
}

func (f *controllerTestFactory) Start(now time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
	f.mu.Lock()
	f.starts++
	n := f.starts
	fn := f.startFn
	startedC := f.startedC
	f.mu.Unlock()
	if startedC != nil {
		select {
		case startedC <- n:
		default:
		}
	}
	return fn(n, now)
}

type controllerTestAttempt struct {
	handleFn func(time.Time, netip.AddrPort, []byte) (bool, EstablishmentUpdate, error)
	retryFn  func(time.Time) (EstablishmentUpdate, error)
}

func (a *controllerTestAttempt) HandleDatagram(
	now time.Time,
	source netip.AddrPort,
	_ dataplane.Route,
	_ bool,
	packet []byte,
) (bool, EstablishmentUpdate, error) {
	if a.handleFn == nil {
		return false, EstablishmentUpdate{}, nil
	}
	return a.handleFn(now, source, packet)
}
func (a *controllerTestAttempt) Retry(now time.Time) (EstablishmentUpdate, error) {
	if a.retryFn == nil {
		return EstablishmentUpdate{}, nil
	}
	return a.retryFn(now)
}

type controllerFakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  map[*controllerFakeTimer]time.Time
	created chan struct{}
}

type controllerFakeTimer struct {
	clock *controllerFakeClock
	ch    chan time.Time
}

func newControllerFakeClock(now time.Time) *controllerFakeClock {
	return &controllerFakeClock{
		now:     now,
		timers:  make(map[*controllerFakeTimer]time.Time),
		created: make(chan struct{}, 16),
	}
}

func (c *controllerFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *controllerFakeClock) NewTimer(d time.Duration) SessionControllerTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &controllerFakeTimer{clock: c, ch: make(chan time.Time, 1)}
	c.timers[t] = c.now.Add(d)
	select {
	case c.created <- struct{}{}:
	default:
	}
	return t
}

func (c *controllerFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []*controllerFakeTimer
	for timer, deadline := range c.timers {
		if !deadline.After(now) {
			due = append(due, timer)
			delete(c.timers, timer)
		}
	}
	c.mu.Unlock()
	for _, timer := range due {
		timer.ch <- now
	}
}

func (t *controllerFakeTimer) C() <-chan time.Time { return t.ch }
func (t *controllerFakeTimer) Stop() {
	t.clock.mu.Lock()
	delete(t.clock.timers, t)
	t.clock.mu.Unlock()
}

func TestSessionControllerReadyClosesAfterFirstSessionInstall(t *testing.T) {
	t0 := time.Unix(1_799_999_990, 0)
	clock := newControllerFakeClock(t0)
	clientIP := netip.MustParseAddr("10.88.0.2")
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48800")
	core := controllerClientCore(t, clock, clientIP, serverEndpoint, nil)
	runtime := newControllerTestRuntime()
	_, _, material := controllerSessionPair(t, 0xc0e0, 0x04)
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return nil, EstablishmentUpdate{Material: &material}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	select {
	case <-controller.Ready():
		t.Fatal("Ready closed before the first Session was installed")
	default:
	}

	usable := controller.HandleOutboundDemand().Usable
	select {
	case <-usable:
		t.Fatal("outbound demand became usable before the first Session was installed")
	default:
	}
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue: %v", err)
	}
	select {
	case <-controller.Ready():
	default:
		t.Fatal("Ready did not close after the first Session install")
	}
	if core.Session() == nil || core.Session().ID() != material.SessionID {
		t.Fatalf("current session=%v, want %#x", core.Session(), material.SessionID)
	}
	select {
	case <-usable:
	default:
		t.Fatal("outbound demand did not become usable after Session install")
	}
}

func TestSessionControllerColdStartDemandAbandonsAfterAttemptBudget(t *testing.T) {
	t0 := time.Unix(1_799_999_995, 0)
	clock := newControllerFakeClock(t0)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48795")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.87.9.5"), serverEndpoint, nil)
	runtime := newControllerTestRuntime()
	retries := 0
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{retryFn: func(_ time.Time) (EstablishmentUpdate, error) {
			retries++
			return EstablishmentUpdate{}, nil
		}}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:              20 * time.Second,
		EstablishmentRetryMin:       time.Second,
		EstablishmentRetryMax:       time.Second,
		EstablishmentAttemptTimeout: 3 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	demand := controller.HandleOutboundDemand()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	for i := 0; i < 2; i++ {
		clock.Advance(time.Second)
		if err := controller.runDue(clock.Now()); err != nil {
			t.Fatalf("retry %d: %v", i+1, err)
		}
	}
	clock.Advance(time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("attempt budget expiry: %v", err)
	}

	if retries != 2 {
		t.Fatalf("retries=%d, want 2 before the 3s budget expired", retries)
	}
	select {
	case <-demand.Abandoned:
	default:
		t.Fatal("cold-start demand was not abandoned after establishment budget")
	}
	select {
	case <-demand.Usable:
		t.Fatal("cold-start demand became usable without a Session")
	default:
	}

	controller.mu.Lock()
	if controller.attempt != nil || !controller.nextAction.IsZero() {
		t.Fatalf("establishment remained active after budget: attempt=%v next=%v", controller.attempt, controller.nextAction)
	}
	controller.mu.Unlock()

	// DATA already queued behind the packet that owned the exhausted cycle must
	// not immediately buy another full establishment budget.
	nextDemand := controller.HandleOutboundDemand()
	select {
	case <-nextDemand.Abandoned:
	default:
		t.Fatal("post-abandon DATA was not suppressed during retry cool-off")
	}
	if factory.starts != 1 {
		t.Fatalf("factory starts=%d during cool-off, want 1", factory.starts)
	}

	// Once the short cool-off expires, the next DATA is fresh demand and starts
	// another independently bounded cycle.
	clock.Advance(time.Second)
	nextDemand = controller.HandleOutboundDemand()
	select {
	case <-nextDemand.Abandoned:
		t.Fatal("fresh demand inherited the previous abandonment signal after cool-off")
	default:
	}
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("restart establishment for fresh demand: %v", err)
	}
	if factory.starts != 2 {
		t.Fatalf("factory starts=%d, want a fresh second cycle", factory.starts)
	}
}

func TestSessionControllerPersistentKeepaliveRetriesAfterColdStartBudget(t *testing.T) {
	t0 := time.Unix(1_799_999_995, 0)
	clock := newControllerFakeClock(t0)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48793")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.87.9.3"), serverEndpoint, nil)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:              20 * time.Second,
		EstablishmentRetryMin:       time.Second,
		EstablishmentRetryMax:       time.Second,
		EstablishmentAttemptTimeout: 3 * time.Second,
		KeepaliveIntervalMin:        5 * time.Second,
		KeepaliveIntervalMax:        5 * time.Second,
		KeepaliveTimeout:            time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start persistent cold establishment: %v", err)
	}
	for i := 0; i < 3; i++ {
		clock.Advance(time.Second)
		if err := controller.runDue(clock.Now()); err != nil {
			t.Fatalf("persistent establishment step %d: %v", i+1, err)
		}
	}
	if factory.starts != 1 {
		t.Fatalf("factory starts=%d after first bounded cycle, want 1", factory.starts)
	}

	controller.mu.Lock()
	next := controller.nextAction
	controller.mu.Unlock()
	wantNext := clock.Now().Add(5 * time.Second)
	if !next.Equal(wantNext) {
		t.Fatalf("next persistent establishment=%v, want %v", next, wantNext)
	}

	clock.Advance(4 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue before persistent retry: %v", err)
	}
	if factory.starts != 1 {
		t.Fatalf("factory starts=%d before persistent cadence, want 1", factory.starts)
	}

	clock.Advance(time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("restart persistent establishment: %v", err)
	}
	if factory.starts != 2 {
		t.Fatalf("factory starts=%d, want second bounded cycle from persistent keepalive", factory.starts)
	}
}

func TestSessionControllerExplicitRekeyBypassesDemandCooloff(t *testing.T) {
	t0 := time.Unix(1_799_999_995, 0)
	clock := newControllerFakeClock(t0)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48794")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.87.9.4"), serverEndpoint, nil)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:              20 * time.Second,
		EstablishmentRetryMin:       5 * time.Second,
		EstablishmentRetryMax:       5 * time.Second,
		EstablishmentAttemptTimeout: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.HandleOutboundDemand()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	clock.Advance(time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("expire establishment: %v", err)
	}

	controller.RequestRekey()
	demand := controller.HandleOutboundDemand()
	select {
	case <-demand.Abandoned:
		t.Fatal("explicit rekey did not bypass demand cool-off")
	default:
	}
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("restart establishment after explicit rekey: %v", err)
	}
	if factory.starts != 2 {
		t.Fatalf("factory starts=%d, want 2", factory.starts)
	}
}

func TestSessionControllerExpiredRekeyAttemptKeepsUsableCurrent(t *testing.T) {
	t0 := time.Unix(1_799_999_996, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc0e6, 0x06)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48796")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.87.9.6"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:              20 * time.Second,
		EstablishmentRetryMin:       time.Second,
		EstablishmentRetryMax:       time.Second,
		EstablishmentAttemptTimeout: 3 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start rekey: %v", err)
	}
	for i := 0; i < 3; i++ {
		clock.Advance(time.Second)
		if err := controller.runDue(clock.Now()); err != nil {
			t.Fatalf("rekey step %d: %v", i+1, err)
		}
	}

	if core.Session() != clientA {
		t.Fatal("expired make-before-break rekey discarded the usable current Session")
	}
	demand := controller.HandleOutboundDemand()
	select {
	case <-demand.Usable:
	default:
		t.Fatal("current Session stopped being usable after rekey attempt budget")
	}
	select {
	case <-demand.Abandoned:
		t.Fatal("usable current was reported as abandoned after failed rekey")
	default:
	}
}

func TestSessionControllerLifetimeClassifierConsumesWithoutActiveAttempt(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc0f0, 0x05)
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.89.0.2"),
		netip.MustParseAddrPort("127.0.0.1:48900"),
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{
		classifyFn: func(packet []byte) bool { return bytes.HasPrefix(packet, []byte("hs:")) },
		startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
			return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
		},
	}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	handled, err := controller.HandleDatagram(
		netip.MustParseAddrPort("127.0.0.1:48900"),
		dataplane.Route{},
		false,
		[]byte("hs:late-response"),
	)
	if err != nil || !handled {
		t.Fatalf("late establishment packet handled=%v err=%v", handled, err)
	}

	handled, err = controller.HandleDatagram(
		netip.MustParseAddrPort("127.0.0.1:48900"),
		dataplane.Route{},
		false,
		[]byte("encrypted-dataplane"),
	)
	if err != nil || handled {
		t.Fatalf("dataplane packet handled=%v err=%v", handled, err)
	}
}

func TestSessionControllerOwnedPacketNeverFallsThroughWhenAttemptRejects(t *testing.T) {
	t0 := time.Unix(1_800_000_010, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc0f1, 0x06)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48910")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.89.1.2"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	attempt := &controllerTestAttempt{handleFn: func(_ time.Time, _ netip.AddrPort, _ []byte) (bool, EstablishmentUpdate, error) {
		return false, EstablishmentUpdate{}, nil
	}}
	factory := &controllerTestFactory{
		classifyFn: func(packet []byte) bool { return bytes.HasPrefix(packet, []byte("hs:")) },
		startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
			return attempt, EstablishmentUpdate{}, nil
		},
	}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}
	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}

	handled, err := controller.HandleDatagram(serverEndpoint, dataplane.Route{}, false, []byte("hs:malformed"))
	if err != nil || !handled {
		t.Fatalf("owned malformed packet handled=%v err=%v", handled, err)
	}
}

func TestSessionControllerAttemptLocalErrorIsTerminal(t *testing.T) {
	t0 := time.Unix(1_800_000_020, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc0f2, 0x07)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:48920")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.89.2.2"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	localErr := errors.New("synthetic provider invariant failure")
	attempt := &controllerTestAttempt{handleFn: func(_ time.Time, _ netip.AddrPort, _ []byte) (bool, EstablishmentUpdate, error) {
		return true, EstablishmentUpdate{}, localErr
	}}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}
	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}

	handled, err := controller.HandleDatagram(serverEndpoint, dataplane.Route{}, false, []byte("owned"))
	if !handled || !errors.Is(err, localErr) {
		t.Fatalf("local provider error handled=%v err=%v, want terminal local error", handled, err)
	}
	if core.Session() != clientA {
		t.Fatal("local establishment failure mutated current generation")
	}
}

func TestSessionControllerSuccessfulRekeyAlwaysSubmitsActivation(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	clock := newControllerFakeClock(t0)
	clientA, serverA, materialA := controllerSessionPair(t, 0xc100, 0x10)
	_, serverB, materialB := controllerSessionPair(t, 0xc101, 0x30)
	clientIP := netip.MustParseAddr("10.90.0.2")
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49000")

	core := controllerClientCore(t, clock, clientIP, serverEndpoint, clientA)
	serverCore := controllerServerCore(t, clientIP, serverA)
	if err := serverCore.InstallPendingSession(clientIP, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}

	runtime := newControllerTestRuntime()
	response := []byte("established-b")
	attempt := &controllerTestAttempt{}
	attempt.handleFn = func(_ time.Time, source netip.AddrPort, packet []byte) (bool, EstablishmentUpdate, error) {
		if !bytes.Equal(packet, response) {
			return false, EstablishmentUpdate{}, nil
		}
		if source != serverEndpoint {
			return true, EstablishmentUpdate{}, errors.New("unexpected server endpoint")
		}
		material := materialB
		return true, EstablishmentUpdate{Material: &material}, nil
	}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{Outbound: []EstablishmentDatagram{{
			Packet:      []byte("start-b"),
			Destination: serverEndpoint,
		}}}, nil
	}}

	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue start: %v", err)
	}
	if len(runtime.raw) != 1 || !bytes.Equal(runtime.raw[0].Packet, []byte("start-b")) {
		t.Fatalf("raw establishment output=%v", runtime.raw)
	}

	handled, err := controller.HandleDatagram(serverEndpoint, dataplane.Route{}, false, response)
	if err != nil {
		t.Fatalf("HandleDatagram(response): %v", err)
	}
	if !handled {
		t.Fatal("establishment response was not consumed")
	}
	if core.Session() == nil || core.Session().ID() != materialB.SessionID {
		t.Fatalf("client current session=%v, want B %#x", core.Session(), materialB.SessionID)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("activation submissions=%d, want 1", len(runtime.transport))
	}

	// The activation operation is real encrypted transport. No application DATA
	// is involved; server pending B must promote solely from this CONTROL.
	scratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("client NewDataScratch: %v", err)
	}
	wire := make([]byte, 0, runtime.transport[0].MaxWireSize())
	wire, err = runtime.transport[0].SealTo(scratch, wire)
	if err != nil {
		t.Fatalf("seal activation: %v", err)
	}
	if len(wire) < dataplane.MinGeneratedEstablishmentWirePacketSize ||
		len(wire) > dataplane.MaxGeneratedEstablishmentWirePacketSize {
		t.Fatalf("activation wire size=%d, want [%d, %d]", len(wire), dataplane.MinGeneratedEstablishmentWirePacketSize, dataplane.MaxGeneratedEstablishmentWirePacketSize)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server NewDataScratch: %v", err)
	}
	inbound, _, _, err := serverCore.HandleNetworkDatagramInPlace(
		serverScratch,
		netip.MustParseAddrPort("127.0.0.1:49001"),
		wire,
	)
	if err != nil {
		t.Fatalf("server activation receive: %v", err)
	}
	if inbound.Kind != dataplane.InboundKeepalive || inbound.KeepaliveID != 0 {
		t.Fatalf("activation inbound=%+v, want KEEPALIVE id 0", inbound)
	}
	if serverCore.CurrentSession(clientIP) != serverB {
		t.Fatal("server did not promote B from unconditional activation CONTROL")
	}

	// A exists only to make this a true rotation rather than first install.
	_ = materialA
}

func TestSessionControllerRetriesActiveAttemptWithoutChangingCurrent(t *testing.T) {
	t0 := time.Unix(1_800_000_050, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc180, 0x35)
	_, _, materialB := controllerSessionPair(t, 0xc181, 0x55)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49080")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.90.1.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	response := []byte("retry-success-b")
	retries := 0
	attempt := &controllerTestAttempt{}
	attempt.retryFn = func(_ time.Time) (EstablishmentUpdate, error) {
		retries++
		return EstablishmentUpdate{Outbound: []EstablishmentDatagram{{
			Packet:      []byte("retry-b"),
			Destination: serverEndpoint,
		}}}, nil
	}
	attempt.handleFn = func(_ time.Time, source netip.AddrPort, packet []byte) (bool, EstablishmentUpdate, error) {
		if !bytes.Equal(packet, response) {
			return false, EstablishmentUpdate{}, nil
		}
		if source != serverEndpoint {
			return true, EstablishmentUpdate{}, errors.New("unexpected source")
		}
		material := materialB
		return true, EstablishmentUpdate{Material: &material}, nil
	}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{Outbound: []EstablishmentDatagram{{
			Packet:      []byte("start-b"),
			Destination: serverEndpoint,
		}}}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: 2 * time.Second,
		EstablishmentRetryMax: 2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start attempt: %v", err)
	}
	if len(runtime.raw) != 1 || !bytes.Equal(runtime.raw[0].Packet, []byte("start-b")) {
		t.Fatalf("initial raw output=%v", runtime.raw)
	}
	if core.Session() != clientA {
		t.Fatal("starting establishment changed current generation")
	}

	clock.Advance(2 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("retry attempt: %v", err)
	}
	if retries != 1 {
		t.Fatalf("attempt retries=%d, want 1", retries)
	}
	if len(runtime.raw) != 2 || !bytes.Equal(runtime.raw[1].Packet, []byte("retry-b")) {
		t.Fatalf("retry raw output=%v", runtime.raw)
	}
	if core.Session() != clientA {
		t.Fatal("retry changed current generation before establishment success")
	}

	handled, err := controller.HandleDatagram(serverEndpoint, dataplane.Route{}, false, response)
	if err != nil {
		t.Fatalf("HandleDatagram(success): %v", err)
	}
	if !handled {
		t.Fatal("success response was not consumed")
	}
	if core.Session().ID() != materialB.SessionID {
		t.Fatalf("current=%#x, want B", core.Session().ID())
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("activation submissions=%d, want 1", len(runtime.transport))
	}
}

func TestSessionControllerRandomizedPolicyStaysInsideConfiguredRanges(t *testing.T) {
	t0 := time.Unix(1_800_000_085, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc185, 0x3a)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49085")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.90.8.2"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: 2500 * time.Millisecond,
		EstablishmentRetryMax: 3500 * time.Millisecond,
		KeepaliveIntervalMin:  25 * time.Second,
		KeepaliveIntervalMax:  35 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.mu.Lock()
	keepaliveDelay := controller.nextKeepalive.Sub(t0)
	controller.mu.Unlock()
	if keepaliveDelay < 25*time.Second || keepaliveDelay > 35*time.Second {
		t.Fatalf("initial keepalive delay=%s, want 25s..35s", keepaliveDelay)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	controller.mu.Lock()
	retryDelay := controller.nextAction.Sub(t0)
	controller.mu.Unlock()
	if retryDelay < 2500*time.Millisecond || retryDelay > 3500*time.Millisecond {
		t.Fatalf("establishment retry delay=%s, want 2.5s..3.5s", retryDelay)
	}
}

func TestSessionControllerTransportReboundImmediatelyKeepsPersistentCurrentAlive(t *testing.T) {
	t0 := time.Unix(1_800_000_087, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc187, 0x3b)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49087")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.90.8.3"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
		KeepaliveIntervalMin:  5 * time.Second,
		KeepaliveIntervalMax:  5 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	clock.Advance(5 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit first keepalive: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("keepalive submissions=%d, want 1", len(runtime.transport))
	}
	controller.mu.Lock()
	controller.keepaliveTimeouts = 2
	controller.mu.Unlock()

	controller.TransportRebound()
	controller.mu.Lock()
	if controller.outstandingProbeID != 0 || !controller.probeStartedAt.IsZero() ||
		!controller.keepaliveDeadline.IsZero() || controller.keepaliveTimeouts != 0 {
		t.Fatalf("old-path keepalive state survived rebound: id=%d startedAt=%v deadline=%v timeouts=%d",
			controller.outstandingProbeID, controller.probeStartedAt, controller.keepaliveDeadline, controller.keepaliveTimeouts)
	}
	if !controller.nextKeepalive.Equal(clock.Now()) {
		t.Fatalf("next keepalive=%v, want immediate %v", controller.nextKeepalive, clock.Now())
	}
	controller.mu.Unlock()

	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("post-rebound keepalive: %v", err)
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("keepalive submissions after rebound=%d, want 2", len(runtime.transport))
	}
	if runtime.transport[1].Session() != clientA {
		t.Fatal("post-rebound keepalive did not use existing current generation")
	}
	if factory.starts != 0 {
		t.Fatalf("transport rebound started establishment with usable current generation: %d", factory.starts)
	}
}

func TestSessionControllerTransportReboundStaysSilentWithoutPersistentKeepalive(t *testing.T) {
	t0 := time.Unix(1_800_000_087, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc186, 0x3a)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49086")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.90.8.6"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.TransportRebound()
	controller.mu.Lock()
	next := controller.nextDueLocked()
	controller.mu.Unlock()
	if !next.IsZero() {
		t.Fatalf("idle rebound armed protocol work at %v", next)
	}
	if len(runtime.transport) != 0 || factory.starts != 0 {
		t.Fatalf("idle rebound emitted work: transport=%d starts=%d", len(runtime.transport), factory.starts)
	}
}

func TestSessionControllerTransportReboundRetriesActiveEstablishmentImmediately(t *testing.T) {
	t0 := time.Unix(1_800_000_088, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc188, 0x3c)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49088")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.90.8.4"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	retries := 0
	attempt := &controllerTestAttempt{retryFn: func(_ time.Time) (EstablishmentUpdate, error) {
		retries++
		return EstablishmentUpdate{}, nil
	}}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:              20 * time.Second,
		EstablishmentRetryMin:       10 * time.Second,
		EstablishmentRetryMax:       10 * time.Second,
		EstablishmentAttemptTimeout: 5 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	if retries != 0 {
		t.Fatalf("retries=%d immediately after start, want 0", retries)
	}

	// Even if the old-path budget has elapsed, a successful transport replacement
	// is a fresh network condition and must get one immediate retry plus a fresh
	// bounded budget.
	clock.Advance(6 * time.Second)
	controller.TransportRebound()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("rebound retry: %v", err)
	}
	if retries != 1 {
		t.Fatalf("retries=%d after rebound, want 1", retries)
	}
}

func TestSessionControllerRetryLocalErrorIsTerminal(t *testing.T) {
	t0 := time.Unix(1_800_000_090, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc1f0, 0x45)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49090")
	core := controllerClientCore(t, clock, netip.MustParseAddr("10.90.9.2"), serverEndpoint, clientA)
	runtime := newControllerTestRuntime()
	localErr := errors.New("synthetic retry invariant failure")
	attempt := &controllerTestAttempt{retryFn: func(_ time.Time) (EstablishmentUpdate, error) {
		return EstablishmentUpdate{}, localErr
	}}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: 3 * time.Second,
		EstablishmentRetryMax: 3 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start establishment: %v", err)
	}
	clock.Advance(3 * time.Second)
	if err := controller.runDue(clock.Now()); !errors.Is(err, localErr) {
		t.Fatalf("retry err=%v, want local failure", err)
	}
	if core.Session() != clientA {
		t.Fatal("failed retry changed current generation")
	}
}

func TestSessionControllerStartFailureIsTerminalAndDoesNotMutateCurrent(t *testing.T) {
	t0 := time.Unix(1_800_000_100, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc200, 0x50)
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.91.0.2"),
		netip.MustParseAddrPort("127.0.0.1:49100"),
		clientA,
	)
	runtime := newControllerTestRuntime()
	localErr := errors.New("synthetic local establishment failure")
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return nil, EstablishmentUpdate{}, localErr
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: 3 * time.Second,
		EstablishmentRetryMax: 3 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); !errors.Is(err, localErr) {
		t.Fatalf("failed attempt err=%v, want local failure", err)
	}
	if factory.starts != 1 {
		t.Fatalf("factory starts=%d, want 1", factory.starts)
	}
	if core.Session() != clientA {
		t.Fatal("failed establishment changed current generation")
	}
}

func TestSessionControllerBToCDoesNotGrowClientGenerationSet(t *testing.T) {
	t0 := time.Unix(1_800_000_200, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, materialA := controllerSessionPair(t, 0xc300, 0x20)
	_, _, materialB := controllerSessionPair(t, 0xc301, 0x40)
	_, _, materialC := controllerSessionPair(t, 0xc302, 0x60)
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.0.2"),
		netip.MustParseAddrPort("127.0.0.1:49200"),
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(n int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		var material establishment.TrafficSessionMaterial
		switch n {
		case 1:
			material = materialB
		case 2:
			material = materialC
		default:
			return nil, EstablishmentUpdate{}, errors.New("unexpected extra establishment")
		}
		return nil, EstablishmentUpdate{Material: &material}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        10 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("install B: %v", err)
	}
	if core.Session().ID() != materialB.SessionID {
		t.Fatalf("current after B=%#x", core.Session().ID())
	}

	// No reverse B is delivered. Soft rekey still installs C with the fixed
	// current/previous transition once application traffic demands the tunnel;
	// there is no third client slot.
	clock.Advance(10 * time.Second)
	controller.HandleOutboundDemand()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("install C: %v", err)
	}
	if core.Session().ID() != materialC.SessionID {
		t.Fatalf("current after C=%#x, want C", core.Session().ID())
	}
	if got := core.peer.LookupRX(materialB.SessionID, clock.Now()); got == nil {
		t.Fatal("B is not resident previous after C install")
	}
	if got := core.peer.LookupRX(materialA.SessionID, clock.Now()); got != nil {
		t.Fatal("A remained resident after B->C rotation")
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("activation submissions=%d, want one for B and one for C", len(runtime.transport))
	}
}

func TestSessionControllerSupersededNeverActiveBThenC(t *testing.T) {
	t0 := time.Unix(1_800_000_250, 0)
	clock := newControllerFakeClock(t0)
	clientA, serverA, materialA := controllerSessionPair(t, 0xc350, 0x25)
	_, serverB, materialB := controllerSessionPair(t, 0xc351, 0x45)
	_, serverC, materialC := controllerSessionPair(t, 0xc352, 0x65)
	clientIP := netip.MustParseAddr("10.92.1.2")
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49250")
	core := controllerClientCore(t, clock, clientIP, serverEndpoint, clientA)
	serverCore := controllerServerCore(t, clientIP, serverA)
	runtime := newControllerTestRuntime()

	factory := &controllerTestFactory{startFn: func(n int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		var material establishment.TrafficSessionMaterial
		switch n {
		case 1:
			if err := serverCore.InstallPendingSession(clientIP, serverB); err != nil {
				return nil, EstablishmentUpdate{}, err
			}
			material = materialB
		case 2:
			if err := serverCore.InstallPendingSession(clientIP, serverC); err != nil {
				return nil, EstablishmentUpdate{}, err
			}
			material = materialC
		default:
			return nil, EstablishmentUpdate{}, errors.New("unexpected extra establishment")
		}
		return nil, EstablishmentUpdate{Material: &material}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        10 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("install B: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("B activation submissions=%d, want 1", len(runtime.transport))
	}
	// Deliberately keep activation(B) in the local TX result list and never
	// deliver it. Server therefore still has A current / B pending.
	if serverCore.CurrentSession(clientIP) != serverA {
		t.Fatal("server left A before B activation")
	}

	clock.Advance(10 * time.Second)
	controller.HandleOutboundDemand()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("install C: %v", err)
	}
	if core.Session().ID() != materialC.SessionID {
		t.Fatalf("client current=%#x, want C", core.Session().ID())
	}
	if got := core.peer.LookupRX(materialB.SessionID, clock.Now()); got == nil {
		t.Fatal("B is not client previous after C install")
	}
	if got := core.peer.LookupRX(materialA.SessionID, clock.Now()); got != nil {
		t.Fatal("A remained resident on client after C install")
	}
	if len(runtime.transport) != 2 {
		t.Fatalf("activation submissions=%d, want B and C", len(runtime.transport))
	}

	// C superseded never-active B on the server. Activation(C) must be enough to
	// promote directly A -> C; there is no requirement that B was ever active.
	scratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("client NewDataScratch: %v", err)
	}
	wire := make([]byte, 0, runtime.transport[1].MaxWireSize())
	wire, err = runtime.transport[1].SealTo(scratch, wire)
	if err != nil {
		t.Fatalf("seal activation C: %v", err)
	}
	serverScratch, err := serverCore.NewDataScratch()
	if err != nil {
		t.Fatalf("server NewDataScratch: %v", err)
	}
	if _, _, _, err := serverCore.HandleNetworkDatagramInPlace(
		serverScratch,
		netip.MustParseAddrPort("127.0.0.1:49251"),
		wire,
	); err != nil {
		t.Fatalf("server activation C: %v", err)
	}
	if serverCore.CurrentSession(clientIP) != serverC {
		t.Fatal("server did not promote C after superseding never-active B")
	}
}

func TestSessionControllerDemandDrivenSoftRekeyUsesActualInstallTime(t *testing.T) {
	t0 := time.Unix(1_800_000_275, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc380, 0x28)
	_, _, materialB := controllerSessionPair(t, 0xc381, 0x48)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49280")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.2.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	response := []byte("established-b-after-slow-final-processing")
	attempt := &controllerTestAttempt{}
	attempt.handleFn = func(_ time.Time, source netip.AddrPort, packet []byte) (bool, EstablishmentUpdate, error) {
		if !bytes.Equal(packet, response) {
			return false, EstablishmentUpdate{}, nil
		}
		if source != serverEndpoint {
			return true, EstablishmentUpdate{}, errors.New("unexpected source")
		}

		// HandleDatagram captured controller time before calling the provider.
		// Simulate non-zero final-message processing so installation happens later.
		clock.Advance(3 * time.Second)
		material := materialB
		return true, EstablishmentUpdate{Material: &material}, nil
	}
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return attempt, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        10 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	controller.RequestRekey()
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("start attempt: %v", err)
	}
	if handled, err := controller.HandleDatagram(serverEndpoint, dataplane.Route{}, false, response); err != nil || !handled {
		t.Fatalf("HandleDatagram handled=%v err=%v", handled, err)
	}

	installedAt, ok := core.peer.currentInstalledAt()
	if !ok {
		t.Fatal("current generation missing after successful establishment")
	}
	wantInstalledAt := t0.Add(3 * time.Second)
	if !installedAt.Equal(wantInstalledAt) {
		t.Fatalf("installedAt=%v, want %v", installedAt, wantInstalledAt)
	}

	controller.mu.Lock()
	next := controller.nextAction
	controller.mu.Unlock()
	if !next.IsZero() {
		t.Fatalf("idle Session armed soft-rekey work at %v", next)
	}

	clock.Advance(9 * time.Second)
	controller.HandleOutboundDemand()
	controller.mu.Lock()
	next = controller.nextAction
	controller.mu.Unlock()
	if !next.IsZero() {
		t.Fatalf("DATA before soft deadline armed rekey at %v", next)
	}

	clock.Advance(time.Second)
	controller.HandleOutboundDemand()
	controller.mu.Lock()
	next = controller.nextAction
	controller.mu.Unlock()
	if !next.Equal(clock.Now()) {
		t.Fatalf("DATA at soft deadline armed rekey at %v, want %v", next, clock.Now())
	}
}

func TestSessionControllerMissedPeerProofStartsFreshEstablishment(t *testing.T) {
	t0 := time.Unix(1_800_000_290, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc390, 0x29)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49290")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.3.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{Outbound: []EstablishmentDatagram{{
			Packet:      []byte("keepalive-recovery-init"),
			Destination: serverEndpoint,
		}}}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
		KeepaliveIntervalMin:  5 * time.Second,
		KeepaliveIntervalMax:  5 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	clock.Advance(5 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit keepalive: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("keepalive submissions=%d, want 1", len(runtime.transport))
	}
	if runtime.transport[0].kind != outboundKeepalive {
		t.Fatalf("keepalive operation kind=%v, want KEEPALIVE", runtime.transport[0].kind)
	}
	if factory.starts != 0 {
		t.Fatalf("establishment starts=%d before keepalive timeout, want 0", factory.starts)
	}

	// Model server process restart: the old generation is gone, therefore no
	// authenticated current-generation RX can arrive. Individual UDP loss is
	// tolerated; only two consecutive probe timeouts escalate to establishment.
	for miss := 1; miss < keepaliveTimeoutsBeforeRekey; miss++ {
		clock.Advance(2 * time.Second)
		if err := controller.runDue(clock.Now()); err != nil {
			t.Fatalf("keepalive timeout %d: %v", miss, err)
		}
		if factory.starts != 0 {
			t.Fatalf("establishment started after only %d keepalive timeouts", miss)
		}
		if got := len(runtime.transport); got != miss+1 {
			t.Fatalf("keepalive submissions=%d after timeout %d, want %d", got, miss, miss+1)
		}
	}
	clock.Advance(2 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("keepalive timeout recovery: %v", err)
	}
	if factory.starts != 1 {
		t.Fatalf("establishment starts=%d after consecutive keepalive timeouts, want 1", factory.starts)
	}
	if len(runtime.raw) != 1 || !bytes.Equal(runtime.raw[0].Packet, []byte("keepalive-recovery-init")) {
		t.Fatalf("keepalive recovery raw output=%v", runtime.raw)
	}
	if core.Session() != clientA {
		t.Fatal("keepalive timeout changed current generation before establishment success")
	}
}

func TestSessionControllerAuthenticatedCurrentRXPreventsRecovery(t *testing.T) {
	t0 := time.Unix(1_800_000_295, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc395, 0x2a)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49295")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.4.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
		KeepaliveIntervalMin:  5 * time.Second,
		KeepaliveIntervalMax:  5 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	clock.Advance(5 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("emit keepalive: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("keepalive submissions=%d, want 1", len(runtime.transport))
	}

	clock.Advance(time.Second)
	core.peer.mu.Lock()
	core.peer.lastCurrentAuthenticatedRX = clock.Now()
	core.peer.mu.Unlock()
	clock.Advance(time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("post-authenticated-RX runDue: %v", err)
	}
	if factory.starts != 0 {
		t.Fatalf("establishment starts=%d after authenticated current RX, want 0", factory.starts)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("authenticated current RX did not suppress retry: submissions=%d", len(runtime.transport))
	}

	controller.mu.Lock()
	deadline := controller.keepaliveDeadline
	nextKeepalive := controller.nextKeepalive
	controller.mu.Unlock()
	if !deadline.IsZero() {
		t.Fatalf("keepalive deadline remained armed after authenticated current RX: %v", deadline)
	}
	wantNextKeepalive := t0.Add(10 * time.Second)
	if !nextKeepalive.Equal(wantNextKeepalive) {
		t.Fatalf("next keepalive=%v, want cadence from last probe %v", nextKeepalive, wantNextKeepalive)
	}
}

func TestSessionControllerPersistentKeepaliveMovesAfterApplicationData(t *testing.T) {
	t0 := time.Unix(1_800_000_297, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc397, 0x2b)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49297")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.5.2"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
		KeepaliveIntervalMin:  5 * time.Second,
		KeepaliveIntervalMax:  5 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	clock.Advance(3 * time.Second)
	controller.HandleOutboundActivity()
	controller.mu.Lock()
	nextKeepalive := controller.nextKeepalive
	controller.mu.Unlock()
	want := t0.Add(8 * time.Second)
	if !nextKeepalive.Equal(want) {
		t.Fatalf("next keepalive=%v after DATA, want %v", nextKeepalive, want)
	}

	clock.Advance(2 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue at old keepalive deadline: %v", err)
	}
	if len(runtime.transport) != 0 {
		t.Fatalf("old keepalive deadline emitted %d packets after DATA", len(runtime.transport))
	}
}

func TestSessionControllerPersistentKeepaliveMovesAfterAuthenticatedRX(t *testing.T) {
	t0 := time.Unix(1_800_000_298, 0)
	clock := newControllerFakeClock(t0)
	clientA, serverA, _ := controllerSessionPair(t, 0xc398, 0x2c)
	serverEndpoint := netip.MustParseAddrPort("127.0.0.1:49298")
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.92.5.3"),
		serverEndpoint,
		clientA,
	)
	runtime := newControllerTestRuntime()
	factory := &controllerTestFactory{startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
		return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
	}}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        20 * time.Second,
		EstablishmentRetryMin: time.Second,
		EstablishmentRetryMax: time.Second,
		KeepaliveIntervalMin:  5 * time.Second,
		KeepaliveIntervalMax:  5 * time.Second,
		KeepaliveTimeout:      2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	clock.Advance(4 * time.Second)
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0xa0 + i)
	}
	txScratch, err := dataplane.NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch(TX): %v", err)
	}
	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.92.5.1"),
		core.TunnelIPv4(),
		[]byte("authenticated peer activity"),
	)
	wire, _, err := serverA.SealDataTo(
		txScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}
	rxScratch, err := core.NewDataScratch()
	if err != nil {
		t.Fatalf("NewDataScratch(RX): %v", err)
	}
	op, err := core.AdmitNetworkDatagramAt(rxScratch, serverEndpoint, wire, clock.Now())
	if err != nil {
		t.Fatalf("AdmitNetworkDatagramAt: %v", err)
	}
	if err := op.Decrypt(rxScratch); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if _, err := core.CommitInbound(op); err != nil {
		t.Fatalf("CommitInbound: %v", err)
	}

	clock.Advance(time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue at original keepalive deadline: %v", err)
	}
	if len(runtime.transport) != 0 {
		t.Fatalf("authenticated RX did not defer idle keepalive: submissions=%d", len(runtime.transport))
	}
	controller.mu.Lock()
	next := controller.nextKeepalive
	controller.mu.Unlock()
	want := t0.Add(9 * time.Second)
	if !next.Equal(want) {
		t.Fatalf("next keepalive=%v after RX, want %v", next, want)
	}

	clock.Advance(4 * time.Second)
	if err := controller.runDue(clock.Now()); err != nil {
		t.Fatalf("runDue at deferred keepalive deadline: %v", err)
	}
	if len(runtime.transport) != 1 {
		t.Fatalf("deferred keepalive submissions=%d, want 1", len(runtime.transport))
	}
}

func TestSessionControllerRunWaitsForDemandAfterSoftDeadlineAndStopsWithRuntime(t *testing.T) {
	t0 := time.Unix(1_800_000_300, 0)
	clock := newControllerFakeClock(t0)
	clientA, _, _ := controllerSessionPair(t, 0xc400, 0x70)
	core := controllerClientCore(
		t,
		clock,
		netip.MustParseAddr("10.93.0.2"),
		netip.MustParseAddrPort("127.0.0.1:49300"),
		clientA,
	)
	runtime := newControllerTestRuntime()
	started := make(chan int, 4)
	factory := &controllerTestFactory{
		startedC: started,
		startFn: func(_ int, _ time.Time) (EstablishmentAttempt, EstablishmentUpdate, error) {
			return &controllerTestAttempt{}, EstablishmentUpdate{}, nil
		},
	}
	controller, err := newSessionController(core, runtime, factory, SessionControllerConfig{
		SoftRekeyAfter:        5 * time.Second,
		EstablishmentRetryMin: 2 * time.Second,
		EstablishmentRetryMax: 2 * time.Second,
	}, clock)
	if err != nil {
		t.Fatalf("newSessionController: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	clock.Advance(5 * time.Second)
	select {
	case n := <-started:
		t.Fatalf("soft deadline started establishment without DATA, start=%d", n)
	case <-time.After(50 * time.Millisecond):
	}

	controller.HandleOutboundDemand()
	select {
	case n := <-started:
		if n != 1 {
			t.Fatalf("first start number=%d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DATA after soft deadline did not start establishment")
	}

	close(runtime.done)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("controller Run after runtime Done: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("controller did not stop with runtime")
	}
}

func controllerClientCore(
	t *testing.T,
	clock *controllerFakeClock,
	clientIP netip.Addr,
	serverEndpoint netip.AddrPort,
	initial *dataplane.Session,
) *Core {
	t.Helper()
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0xa0 + i)
	}
	core, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientIP,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Session: initial,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	core.now = clock.Now
	// New used wall time; make the initial generation belong to the same fake
	// timeline used by controller and admissions.
	if initial != nil {
		core.peer.current.rejectAt = clock.Now().Add(core.peer.lifecycle.GenerationLifetime)
	}
	return core
}

func controllerServerCore(t *testing.T, clientIP netip.Addr, initial *dataplane.Session) *server.Core {
	t.Helper()
	var routeKey [32]byte
	for i := range routeKey {
		routeKey[i] = byte(0xa0 + i)
	}
	core, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: 30 * time.Second,
			ReceiveGrace:       5 * time.Second,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: clientIP, InitialSession: initial}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return core
}

func controllerSessionPair(
	t *testing.T,
	sessionID uint64,
	seed byte,
) (*dataplane.Session, *dataplane.Session, establishment.TrafficSessionMaterial) {
	t.Helper()
	var c2s, s2c [32]byte
	for i := 0; i < 32; i++ {
		c2s[i] = seed + byte(i)
		s2c[i] = seed + 0x40 + byte(i)
	}
	material := establishment.TrafficSessionMaterial{
		SessionID: sessionID,
		C2S:       c2s,
		S2C:       s2c,
	}
	clientSession, err := establishment.NewClientSession(material)
	if err != nil {
		t.Fatalf("NewClientSession(%#x): %v", sessionID, err)
	}
	serverSession, err := establishment.NewServerSession(material)
	if err != nil {
		t.Fatalf("NewServerSession(%#x): %v", sessionID, err)
	}
	return clientSession, serverSession, material
}
