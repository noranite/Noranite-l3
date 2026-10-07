package server

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestRXEngineConcurrentDuplicateDeliveryAcceptsExactlyOneCopy(t *testing.T) {
	core, client, routeKey := newTestServer(t, 0, 500)
	engine, err := NewRXEngine(core, RXEngineConfig{
		DecryptWorkers:   4,
		DecryptQueueSize: 16,
		PeerQueueSize:    16,
	})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	defer engine.Close()

	source := netip.MustParseAddrPort("192.0.2.10:50000")
	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("same async datagram"),
	)
	wire, _ := sealTestPacket(t, client, &routeKey, inner)

	// Admission is deliberately completed for every copy before results are
	// observed. AEAD may run on different global workers, but replay commit must
	// still have exactly one owner and accept exactly one copy.
	admitScratch := newServerDataScratch(t, core)
	const copies = 32
	futures := make([]<-chan RXResult, 0, copies)

	for i := 0; i < copies; i++ {
		op, err := core.AdmitNetworkDatagram(
			admitScratch,
			source,
			bytes.Clone(wire),
		)
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}

		future, err := engine.Enqueue(op, false)
		if err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}
		futures = append(futures, future)
	}

	successes := 0
	replays := 0
	for i, future := range futures {
		result := <-future
		switch {
		case result.Err == nil:
			successes++
			if result.Inbound.Kind != dataplane.InboundIPv4 {
				t.Fatalf("result %d kind=%v, want IPv4", i, result.Inbound.Kind)
			}
			if !bytes.Equal(result.Inbound.IPv4, inner) {
				t.Fatalf("result %d plaintext differs from original", i)
			}
		case errors.Is(result.Err, dataplane.ErrReplay):
			replays++
		default:
			t.Fatalf("result %d error=%v, want nil or ErrReplay", i, result.Err)
		}
	}

	if successes != 1 || replays != copies-1 {
		t.Fatalf(
			"successes=%d replays=%d, want 1/%d",
			successes,
			replays,
			copies-1,
		)
	}
}

func TestRXEngineCloseDrainsAcceptedOperations(t *testing.T) {
	core, client, routeKey := newTestServer(t, 0, 1000)
	engine, err := NewRXEngine(core, RXEngineConfig{
		DecryptWorkers:   3,
		DecryptQueueSize: 4,
		PeerQueueSize:    4,
	})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}

	source := netip.MustParseAddrPort("192.0.2.11:50001")
	admitScratch := newServerDataScratch(t, core)

	const packetCount = 48
	futures := make([]<-chan RXResult, 0, packetCount)
	wantPayloads := make([][]byte, 0, packetCount)

	for i := 0; i < packetCount; i++ {
		payload := []byte{byte(i), byte(i >> 8), 0xa5, 0x5a}
		inner := testIPv4Packet(
			t,
			"10.66.0.2",
			"10.66.0.1",
			payload,
		)
		wire, _ := sealTestPacket(t, client, &routeKey, inner)

		op, err := core.AdmitNetworkDatagram(admitScratch, source, wire)
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}
		future, err := engine.Enqueue(op, false)
		if err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}

		futures = append(futures, future)
		wantPayloads = append(wantPayloads, inner)
	}

	// Close is a drain boundary, not cancellation. It must be legal to close the
	// engine before the caller starts consuming result channels.
	engine.Close()

	for i, future := range futures {
		result, ok := <-future
		if !ok {
			t.Fatalf("result channel %d closed without a result", i)
		}
		if result.Err != nil {
			t.Fatalf("drained result %d: %v", i, result.Err)
		}
		if !bytes.Equal(result.Inbound.IPv4, wantPayloads[i]) {
			t.Fatalf("drained result %d plaintext mismatch", i)
		}
	}

	// Idempotent shutdown and explicit rejection after the admission boundary.
	engine.Close()
	if _, err := engine.Enqueue(&InboundOperation{}, false); !errors.Is(err, ErrRXEngineClosed) {
		t.Fatalf("Enqueue after Close error=%v, want ErrRXEngineClosed", err)
	}
}

func TestRXEngineAdmissionDeadlineIsNotCompletionDeadline(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: time.Second,
		ReceiveGrace:       2 * time.Second,
	}

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          lifecycle,
		Peers: []PeerConfig{{
			TunnelIPv4: testPeerTunnelIPv4(),
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_100_000, 0)
	now := t0
	core.now = func() time.Time { return now }

	serverSession, clientSession := newLifecycleSessionPair(t, 0x7a01, 0x66)
	if err := core.InstallPendingSession(testPeerTunnelIPv4(), serverSession); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("admitted before pending expiry"),
	)
	wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	source := netip.MustParseAddrPort("192.0.2.12:50002")

	// The packet STARTS immediately before the pending deadline.
	now = t0.Add(lifecycle.GenerationLifetime - time.Nanosecond)
	admitScratch := newServerDataScratch(t, core)
	op, err := core.AdmitNetworkDatagram(admitScratch, source, wire)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram before deadline: %v", err)
	}

	// Simulate arbitrary worker/queue delay. The lifecycle decision was already
	// captured by admission, so this must not invalidate the operation.
	now = t0.Add(lifecycle.GenerationLifetime + 250*time.Millisecond)

	engine, err := NewRXEngine(core, RXEngineConfig{DecryptWorkers: 2})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	defer engine.Close()

	future, err := engine.Enqueue(op, false)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	result := <-future
	if result.Err != nil {
		t.Fatalf("result after deadline: %v", result.Err)
	}
	if !bytes.Equal(result.Inbound.IPv4, inner) {
		t.Fatal("result plaintext differs from original")
	}
	if core.CurrentSession(testPeerTunnelIPv4()) != serverSession {
		t.Fatal("admitted pending Session was not promoted after worker delay")
	}
	if endpoint, ok := serverSession.Endpoint(); !ok || endpoint != source {
		t.Fatalf("endpoint=(%v,%v), want %v", endpoint, ok, source)
	}
}

func TestRXEngineBatchKeepsPerPeerCommitOrder(t *testing.T) {
	core, client, routeKey := newTestServer(t, 0, 2000)
	engine, err := NewRXEngine(core, RXEngineConfig{DecryptWorkers: 4, BatchSize: 1})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	defer engine.Close()

	admitScratch := newServerDataScratch(t, core)
	sources := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.20:51000"),
		netip.MustParseAddrPort("192.0.2.21:51001"),
		netip.MustParseAddrPort("192.0.2.22:51002"),
	}

	ops := make([]*InboundOperation, 0, len(sources))
	for i, source := range sources {
		inner := testIPv4Packet(
			t,
			"10.66.0.2",
			"10.66.0.1",
			[]byte{byte(i)},
		)
		wire, _ := sealTestPacket(t, client, &routeKey, inner)
		op, err := core.AdmitNetworkDatagram(admitScratch, source, wire)
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}
		ops = append(ops, op)
	}

	futures, err := engine.EnqueueBatch(ops, false)
	if err != nil {
		t.Fatalf("EnqueueBatch: %v", err)
	}
	for i, future := range futures {
		if result := <-future; result.Err != nil {
			t.Fatalf("result %d: %v", i, result.Err)
		}
	}

	current := core.CurrentSession(testPeerTunnelIPv4())
	endpoint, ok := current.Endpoint()
	if !ok || endpoint != sources[len(sources)-1] {
		t.Fatalf(
			"final endpoint=(%v,%v), want last admitted source %v",
			endpoint,
			ok,
			sources[len(sources)-1],
		)
	}
}

func TestRXEnginePreviousAdmissionSurvivesGraceDeadline(t *testing.T) {
	routeKey, _, _ := testKeys()
	lifecycle := LifecycleConfig{
		GenerationLifetime: 10 * time.Second,
		ReceiveGrace:       time.Second,
	}

	oldServer, oldClient := newLifecycleSessionPair(t, 0x7b01, 0x67)
	newServer, newClient := newLifecycleSessionPair(t, 0x7b02, 0x68)
	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          lifecycle,
		Peers: []PeerConfig{{
			TunnelIPv4:     testPeerTunnelIPv4(),
			InitialSession: oldServer,
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_200_000, 0)
	now := t0
	core.now = func() time.Time { return now }

	if err := core.InstallPendingSession(testPeerTunnelIPv4(), newServer); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}
	promotionSource := netip.MustParseAddrPort("192.0.2.30:53000")
	promotionInner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("promote new current"),
	)
	promotionWire, _ := sealTestPacket(t, newClient, &routeKey, promotionInner)
	if _, err := core.HandleDatagramInPlace(
		newServerDataScratch(t, core),
		promotionSource,
		promotionWire,
	); err != nil {
		t.Fatalf("promote new current: %v", err)
	}
	if core.CurrentSession(testPeerTunnelIPv4()) != newServer {
		t.Fatal("new Session is not current after promotion")
	}

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("previous admitted before grace deadline"),
	)
	wire, _ := sealTestPacket(t, oldClient, &routeKey, inner)
	source := netip.MustParseAddrPort("192.0.2.31:53001")

	// The old Session is previous until t0+ReceiveGrace. Capture eligibility at
	// ingress immediately before that boundary.
	now = t0.Add(lifecycle.ReceiveGrace - time.Nanosecond)
	op, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		source,
		wire,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(previous before grace deadline): %v", err)
	}

	// Worker/queue latency carries the already-admitted operation past the grace
	// deadline. Commit must not re-check current lifecycle eligibility.
	now = t0.Add(lifecycle.ReceiveGrace + 250*time.Millisecond)
	engine, err := NewRXEngine(core, RXEngineConfig{DecryptWorkers: 2})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}

	future, err := engine.Enqueue(op, false)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	engine.Close()

	result := <-future
	if result.Err != nil {
		t.Fatalf("previous result after grace deadline: %v", result.Err)
	}
	if result.Inbound.Kind != dataplane.InboundIPv4 {
		t.Fatalf("inbound kind=%v, want IPv4", result.Inbound.Kind)
	}
	if !bytes.Equal(result.Inbound.IPv4, inner) {
		t.Fatal("result plaintext differs from original")
	}
	if core.CurrentSession(testPeerTunnelIPv4()) != newServer {
		t.Fatal("previous completion changed current Session")
	}
	if endpoint, ok := oldServer.Endpoint(); !ok || endpoint != source {
		t.Fatalf("previous endpoint=(%v,%v), want %v", endpoint, ok, source)
	}

	// The deadline still rejects genuinely new work; only the operation admitted
	// before it was allowed to finish.
	lateWire, _ := sealTestPacket(t, oldClient, &routeKey, inner)
	if _, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		source,
		lateWire,
	); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("new previous admission after grace error=%v, want ErrSessionNotRXEligible", err)
	}
}

func TestServerRXEngineValidationErrorClearsSubmitSeen(t *testing.T) {
	peer := &Peer{}
	engine := &RXEngine{
		peerQueues: map[*Peer]chan *rxContainer{peer: nil},
		submitSeen: make(map[*InboundOperation]struct{}),
	}
	valid := &InboundOperation{
		binding: sessionBinding{peer: peer},
		admission: RXAdmission{
			Session: new(dataplane.Session),
		},
	}

	if _, err := engine.EnqueueBatch([]*InboundOperation{valid, nil}, false); err == nil {
		t.Fatal("EnqueueBatch accepted invalid operation")
	}
	if len(engine.submitSeen) != 0 {
		t.Fatalf("submitSeen retained %d operation(s) after validation error", len(engine.submitSeen))
	}
}
