package server

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

type serverCountingBufferReleaser struct {
	mu    sync.Mutex
	count int
}

func (r *serverCountingBufferReleaser) Put([]byte) {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
}

func (r *serverCountingBufferReleaser) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

type serverTrackingBufferReleaser struct {
	mu   sync.Mutex
	seen map[*byte]int
}

func newServerTrackingBufferReleaser() *serverTrackingBufferReleaser {
	return &serverTrackingBufferReleaser{seen: make(map[*byte]int)}
}

func serverBufferIdentity(buffer []byte) *byte {
	if cap(buffer) == 0 {
		return nil
	}
	return &buffer[:1][0]
}

func (r *serverTrackingBufferReleaser) Put(buffer []byte) {
	r.mu.Lock()
	r.seen[serverBufferIdentity(buffer)]++
	r.mu.Unlock()
}

func (r *serverTrackingBufferReleaser) Count(buffer []byte) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[serverBufferIdentity(buffer)]
}

func (r *serverTrackingBufferReleaser) Total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, count := range r.seen {
		total += count
	}
	return total
}

type serverEngineErrorRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *serverEngineErrorRecorder) Report(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
}

func (r *serverEngineErrorRecorder) Errors() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func TestServerOwnedTXReleasesBufferAfterSendFailure(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte("owned tx send failure"))
	var op OutboundOperation
	if err := core.AdmitInnerPacketInto(&op, inner, len(inner)+dataplane.MaxDataExpansion); err != nil {
		t.Fatalf("AdmitInnerPacketInto: %v", err)
	}

	sendErr := errors.New("test send failure")
	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	engine, err := NewOwnedTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
		func([]TXPacket) error { return sendErr },
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedTXEngine: %v", err)
	}

	buffer := make([]byte, 0, op.MaxWireSize())
	if err := engine.EnqueueOwned(TXOwnedSubmission{Operation: op, Buffer: buffer}, releaser); err != nil {
		t.Fatalf("EnqueueOwned: %v", err)
	}
	engine.Close()

	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	errs := reporter.Errors()
	if len(errs) != 1 || !errors.Is(errs[0], sendErr) {
		t.Fatalf("reported errors=%v, want send failure", errs)
	}
}

func TestServerOwnedTXReleasesBufferAfterSealFailure(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte("owned tx seal failure"))
	var op OutboundOperation
	if err := core.AdmitInnerPacketInto(&op, inner, len(inner)+dataplane.MaxDataExpansion); err != nil {
		t.Fatalf("AdmitInnerPacketInto: %v", err)
	}
	// Keep the already-reserved sequence/session/peer but force the ACK encoder
	// to reject its impossible maximum wire size in the crypto worker.
	op.data = nil
	op.ackKeepaliveID = 1
	op.ackMaxWireSize = 1

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	engine, err := NewOwnedTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
		func([]TXPacket) error { return nil },
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedTXEngine: %v", err)
	}

	if err := engine.EnqueueOwned(
		TXOwnedSubmission{Operation: op, Buffer: make([]byte, 0, op.MaxWireSize())},
		releaser,
	); err != nil {
		t.Fatalf("EnqueueOwned: %v", err)
	}
	engine.Close()

	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	if errs := reporter.Errors(); len(errs) != 1 {
		t.Fatalf("reported errors=%v, want one seal failure", errs)
	}
}

func TestServerOwnedRXReleasesBufferAfterConsumerReturns(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 500)
	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte("owned rx backing"))
	wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	source := netip.MustParseAddrPort("192.0.2.80:52080")
	admitScratch := newServerDataScratch(t, core)
	op, err := core.AdmitNetworkDatagram(admitScratch, source, wire)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram: %v", err)
	}

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	consumeErr := errors.New("test consume failure")
	var consumeCheckErr error
	consumed := false
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func(results []RXOwnedResult) error {
			consumed = true
			switch {
			case len(results) != 1:
				consumeCheckErr = errors.New("unexpected RX result count")
			case results[0].Err != nil:
				consumeCheckErr = results[0].Err
			case !bytes.Equal(results[0].Inbound.IPv4, inner):
				consumeCheckErr = errors.New("plaintext mismatch")
			case len(results[0].Buffer) == 0 || &results[0].Buffer[0] != &wire[0]:
				consumeCheckErr = errors.New("RX result buffer does not alias admitted packet")
			case releaser.Count() != 0:
				consumeCheckErr = errors.New("RX buffer released before consumer returned")
			}
			return consumeErr
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedRXEngine: %v", err)
	}
	if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{Operation: *op}}, false, releaser); err != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", err)
	}
	engine.Close()

	if !consumed {
		t.Fatal("owned RX consumer was not called")
	}
	if consumeCheckErr != nil {
		t.Fatalf("owned RX consume check: %v", consumeCheckErr)
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	errs := reporter.Errors()
	if len(errs) != 1 || !errors.Is(errs[0], consumeErr) {
		t.Fatalf("reported errors=%v, want consume failure", errs)
	}
}

func TestServerOwnedRXReleasesBufferAfterDecryptFailure(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 500)
	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte("owned rx auth failure"))
	wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	source := netip.MustParseAddrPort("192.0.2.81:52081")
	admitScratch := newServerDataScratch(t, core)
	op, err := core.AdmitNetworkDatagram(admitScratch, source, wire)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram: %v", err)
	}
	wire[len(wire)-1] ^= 0x80

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	gotAuthFailure := false
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func(results []RXOwnedResult) error {
			gotAuthFailure = len(results) == 1 && errors.Is(results[0].Err, dataplane.ErrAuthentication)
			return nil
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedRXEngine: %v", err)
	}
	if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{Operation: *op}}, false, releaser); err != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", err)
	}
	engine.Close()

	if !gotAuthFailure {
		t.Fatal("owned RX consumer did not observe authentication failure")
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}
}

func TestServerOwnedValidationDoesNotTakeBufferOwnership(t *testing.T) {
	core, _, _ := newTestServer(t, 0, 500)

	t.Run("TX", func(t *testing.T) {
		releaser := new(serverCountingBufferReleaser)
		reporter := new(serverEngineErrorRecorder)
		engine, err := NewOwnedTXEngine(
			core,
			TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
			func([]TXPacket) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatalf("NewOwnedTXEngine: %v", err)
		}
		if err := engine.EnqueueOwned(
			TXOwnedSubmission{Buffer: make([]byte, 0, 64)},
			releaser,
		); err == nil {
			t.Fatal("EnqueueOwned accepted invalid TX operation")
		}
		engine.Close()
		if got := releaser.Count(); got != 0 {
			t.Fatalf("buffer release count=%d, want 0 before ownership transfer", got)
		}
	})

	t.Run("RX", func(t *testing.T) {
		releaser := new(serverCountingBufferReleaser)
		reporter := new(serverEngineErrorRecorder)
		engine, err := NewOwnedRXEngine(
			core,
			RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
			func([]RXOwnedResult) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatalf("NewOwnedRXEngine: %v", err)
		}
		if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{}}, false, releaser); err == nil {
			t.Fatal("EnqueueOwnedBatch accepted invalid RX operation")
		}
		engine.Close()
		if got := releaser.Count(); got != 0 {
			t.Fatalf("buffer release count=%d, want 0 before ownership transfer", got)
		}
	})
}

func TestServerOwnedRXHandlesOneIngressBatchAcrossPeers(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")
	serverA, clientA := newLifecycleSessionPair(t, 0xa101, 0x21)
	serverB, clientB := newLifecycleSessionPair(t, 0xa102, 0x22)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerA, InitialSession: serverA},
			{TunnelIPv4: peerB, InitialSession: serverB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	innerA := testIPv4Packet(t, peerA.String(), "10.66.0.1", []byte("peer A"))
	innerB := testIPv4Packet(t, peerB.String(), "10.66.0.1", []byte("peer B"))
	wireA, _ := sealTestPacket(t, clientA, &routeKey, innerA)
	wireB, _ := sealTestPacket(t, clientB, &routeKey, innerB)
	admitScratch := newServerDataScratch(t, core)
	opA, err := core.AdmitNetworkDatagram(
		admitScratch,
		netip.MustParseAddrPort("192.0.2.101:52101"),
		wireA,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(A): %v", err)
	}
	opB, err := core.AdmitNetworkDatagram(
		admitScratch,
		netip.MustParseAddrPort("192.0.2.102:52102"),
		wireB,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(B): %v", err)
	}

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	var consumeMu sync.Mutex
	consumeCalls := 0
	consumedPackets := 0
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 2, BatchSize: 2},
		func(results []RXOwnedResult) error {
			consumeMu.Lock()
			defer consumeMu.Unlock()
			consumeCalls++
			for _, result := range results {
				if result.Err != nil {
					return result.Err
				}
				if result.Inbound.Kind != dataplane.InboundIPv4 {
					return errors.New("unexpected inbound kind")
				}
				consumedPackets++
			}
			return nil
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedRXEngine: %v", err)
	}
	if err := engine.EnqueueOwnedBatch(
		[]RXOwnedSubmission{{Operation: *opA}, {Operation: *opB}},
		false,
		releaser,
	); err != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", err)
	}
	engine.Close()

	consumeMu.Lock()
	gotConsumeCalls := consumeCalls
	gotPackets := consumedPackets
	consumeMu.Unlock()
	if gotConsumeCalls < 1 || gotConsumeCalls > 2 || gotPackets != 2 {
		t.Fatalf("consume calls/packets=%d/%d, want 1..2/2", gotConsumeCalls, gotPackets)
	}
	if got := releaser.Count(); got != 2 {
		t.Fatalf("buffer release count=%d, want 2", got)
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}
}

func TestServerOwnedRXDeliveryBatchesReadyContainersAcrossPeers(t *testing.T) {
	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	var calls [][]byte

	engine := &RXEngine{
		batchSize:     2,
		deliveryQueue: make(chan *rxContainer, 2),
		consume: func(results []RXOwnedResult) error {
			got := make([]byte, len(results))
			for i := range results {
				if len(results[i].Buffer) != 1 {
					return errors.New("unexpected test buffer size")
				}
				got[i] = results[i].Buffer[0]
			}
			calls = append(calls, got)
			return nil
		},
		report: reporter.Report,
	}

	first := &rxContainer{
		owned:    true,
		releaser: releaser,
		elems: []*rxElement{{
			buffer:  []byte{1},
			inbound: dataplane.InboundPacket{Kind: dataplane.InboundKeepalive},
		}},
	}
	second := &rxContainer{
		owned:    true,
		releaser: releaser,
		elems: []*rxElement{{
			buffer:  []byte{2},
			inbound: dataplane.InboundPacket{Kind: dataplane.InboundKeepalive},
		}},
	}

	// Both committed containers are ready before delivery starts. The global
	// stage must reconstruct one vector rather than one callback per Peer.
	engine.deliveryQueue <- first
	engine.deliveryQueue <- second
	close(engine.deliveryQueue)
	engine.delivery.Add(1)
	engine.routineDelivery()

	if len(calls) != 1 || !bytes.Equal(calls[0], []byte{1, 2}) {
		t.Fatalf("delivery calls=%v, want one cross-peer vector [1 2]", calls)
	}
	if got := releaser.Count(); got != 2 {
		t.Fatalf("buffer release count=%d, want 2", got)
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}
}

func TestServerOwnedRXGeneratedACKSequenceExhaustionReachesConsumer(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, ^uint64(0), 0)
	clientScratch := newTestDataScratch(t, routeKey)
	storage := make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize)
	wire, _, err := clientSession.SealKeepaliveToWithPadding(
		clientScratch,
		storage,
		0x1122334455667788,
		dataplane.MinGeneratedControlWirePacketSize-dataplane.MinControlWirePacketSize+8,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding: %v", err)
	}

	admitScratch := newServerDataScratch(t, core)
	op, err := core.AdmitNetworkDatagram(
		admitScratch,
		netip.MustParseAddrPort("192.0.2.201:52201"),
		wire,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram: %v", err)
	}

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	gotSequenceExhausted := false
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func(results []RXOwnedResult) error {
			gotSequenceExhausted = len(results) == 1 && errors.Is(results[0].Err, dataplane.ErrSequenceExhausted)
			return nil
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedRXEngine: %v", err)
	}
	if err := engine.EnqueueOwnedBatch(
		[]RXOwnedSubmission{{Operation: *op}},
		true,
		releaser,
	); err != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", err)
	}
	engine.Close()

	if !gotSequenceExhausted {
		t.Fatal("RX-generated ACK sequence exhaustion did not reach the owned consumer")
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}
}

func TestServerOwnedTXGroupsBatchByPeerPreservesOrderAndReleasesExactlyOnce(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")
	serverA, clientA := newLifecycleSessionPair(t, 0xb101, 0x31)
	serverB, clientB := newLifecycleSessionPair(t, 0xb102, 0x32)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerA, InitialSession: serverA},
			{TunnelIPv4: peerB, InitialSession: serverB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	learnEndpoint := func(peer netip.Addr, client *dataplane.Session, endpoint netip.AddrPort) {
		t.Helper()
		inner := testIPv4Packet(t, peer.String(), "10.66.0.1", []byte("learn owned TX endpoint"))
		wire, _ := sealTestPacket(t, client, &routeKey, inner)
		if _, err := core.HandleDatagramInPlace(newServerDataScratch(t, core), endpoint, wire); err != nil {
			t.Fatalf("learn endpoint for %v: %v", peer, err)
		}
	}
	learnEndpoint(peerA, clientA, netip.MustParseAddrPort("192.0.2.171:52171"))
	learnEndpoint(peerB, clientB, netip.MustParseAddrPort("192.0.2.172:52172"))

	type sentPacket struct {
		wire []byte
	}
	var sentMu sync.Mutex
	var sent []sentPacket
	var sendBatchSizes []int
	releaser := newServerTrackingBufferReleaser()
	reporter := new(serverEngineErrorRecorder)
	engine, err := NewOwnedTXEngine(
		core,
		TXEngineConfig{
			EncryptWorkers:   4,
			EncryptQueueSize: 2,
			PeerQueueSize:    2,
			BatchSize:        4,
		},
		func(packets []TXPacket) error {
			sentMu.Lock()
			defer sentMu.Unlock()
			sendBatchSizes = append(sendBatchSizes, len(packets))
			for _, packet := range packets {
				sent = append(sent, sentPacket{wire: bytes.Clone(packet.Wire)})
			}
			return nil
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedTXEngine: %v", err)
	}
	t.Cleanup(engine.Close)

	want := map[uint64][]uint64{
		serverA.ID(): nil,
		serverB.ID(): nil,
	}
	var submittedBuffers [][]byte
	const rounds = 32
	for round := 0; round < rounds; round++ {
		submissions := make([]TXOwnedSubmission, 0, 4)
		// One server ingress batch deliberately interleaves Peers. TXEngine must
		// group it as A1,A2 and B1,B2 while preserving each Peer's admission order.
		for pairIndex := 0; pairIndex < 2; pairIndex++ {
			for _, peer := range []netip.Addr{peerA, peerB} {
				payload := []byte{byte(round), byte(pairIndex), byte(peer.As4()[3])}
				inner := testIPv4Packet(t, "10.66.0.1", peer.String(), payload)
				var op OutboundOperation
				if err := core.AdmitInnerPacketInto(&op, inner, len(inner)+dataplane.MaxDataExpansion); err != nil {
					t.Fatalf("AdmitInnerPacketInto(%v,%d,%d): %v", peer, round, pairIndex, err)
				}
				want[op.Session().ID()] = append(want[op.Session().ID()], op.Sequence())
				buffer := make([]byte, 0, op.MaxWireSize())
				submittedBuffers = append(submittedBuffers, buffer)
				submissions = append(submissions, TXOwnedSubmission{Operation: op, Buffer: buffer})
			}
		}
		if err := engine.EnqueueOwnedBatch(submissions, releaser); err != nil {
			t.Fatalf("EnqueueOwnedBatch(round %d): %v", round, err)
		}
	}
	engine.Close()

	if got, wantTotal := releaser.Total(), len(submittedBuffers); got != wantTotal {
		t.Fatalf("total buffer releases=%d, want %d", got, wantTotal)
	}
	for i, buffer := range submittedBuffers {
		if got := releaser.Count(buffer); got != 1 {
			t.Fatalf("buffer %d release count=%d, want exactly 1", i, got)
		}
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}

	sentMu.Lock()
	gotSent := append([]sentPacket(nil), sent...)
	gotBatchSizes := append([]int(nil), sendBatchSizes...)
	sentMu.Unlock()
	if len(gotSent) != len(submittedBuffers) {
		t.Fatalf("sent packets=%d, want %d", len(gotSent), len(submittedBuffers))
	}
	if len(gotBatchSizes) != rounds*2 {
		t.Fatalf("send calls=%d, want %d grouped per-Peer containers", len(gotBatchSizes), rounds*2)
	}
	for i, size := range gotBatchSizes {
		if size != 2 {
			t.Fatalf("send batch %d size=%d, want 2 packets from one grouped Peer container", i, size)
		}
	}

	got := map[uint64][]uint64{
		serverA.ID(): nil,
		serverB.ID(): nil,
	}
	decodeScratch := newTestDataScratch(t, routeKey)
	for i, packet := range gotSent {
		route, err := dataplane.DecodeRoute(decodeScratch, packet.wire)
		if err != nil {
			t.Fatalf("DecodeRoute(sent %d): %v", i, err)
		}
		got[route.SessionID] = append(got[route.SessionID], route.Sequence)
	}
	for sessionID, wantSequences := range want {
		gotSequences := got[sessionID]
		if len(gotSequences) != len(wantSequences) {
			t.Fatalf("session %#x sent %d sequences, want %d", sessionID, len(gotSequences), len(wantSequences))
		}
		for i := range wantSequences {
			if gotSequences[i] != wantSequences[i] {
				t.Fatalf(
					"session %#x sequence[%d]=%d, want %d",
					sessionID,
					i,
					gotSequences[i],
					wantSequences[i],
				)
			}
		}
	}
}

func TestServerOwnedTXConcurrentEnqueueAndCloseMaintainsOwnership(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	const iterations = 64
	for i := 0; i < iterations; i++ {
		inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte{byte(i), 0x5a})
		var op OutboundOperation
		if err := core.AdmitInnerPacketInto(&op, inner, len(inner)+dataplane.MaxDataExpansion); err != nil {
			t.Fatalf("iteration %d AdmitInnerPacketInto: %v", i, err)
		}

		releaser := new(serverCountingBufferReleaser)
		reporter := new(serverEngineErrorRecorder)
		engine, err := NewOwnedTXEngine(
			core,
			TXEngineConfig{
				EncryptWorkers:   1,
				EncryptQueueSize: 1,
				PeerQueueSize:    1,
				BatchSize:        1,
			},
			func([]TXPacket) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatalf("iteration %d NewOwnedTXEngine: %v", i, err)
		}

		start := make(chan struct{})
		enqueueResult := make(chan error, 1)
		closeDone := make(chan struct{})
		buffer := make([]byte, 0, op.MaxWireSize())
		go func() {
			<-start
			enqueueResult <- engine.EnqueueOwned(TXOwnedSubmission{Operation: op, Buffer: buffer}, releaser)
		}()
		go func() {
			<-start
			engine.Close()
			close(closeDone)
		}()
		close(start)

		var enqueueErr error
		select {
		case enqueueErr = <-enqueueResult:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d EnqueueOwned did not finish", i)
		}
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d Close did not finish", i)
		}

		switch {
		case enqueueErr == nil:
			if got := releaser.Count(); got != 1 {
				t.Fatalf("iteration %d accepted buffer release count=%d, want 1", i, got)
			}
		case errors.Is(enqueueErr, ErrTXEngineClosed):
			if got := releaser.Count(); got != 0 {
				t.Fatalf("iteration %d rejected buffer release count=%d, want 0", i, got)
			}
		default:
			t.Fatalf("iteration %d EnqueueOwned error=%v, want nil or ErrTXEngineClosed", i, enqueueErr)
		}
		if errs := reporter.Errors(); len(errs) != 0 {
			t.Fatalf("iteration %d reported errors=%v, want none", i, errs)
		}
	}
}

func TestServerContainerPoolMemoryPolicy(t *testing.T) {
	core, _, _ := newTestServer(t, 0, 0)

	tx, err := NewTXEngine(core, TXEngineConfig{EncryptWorkers: 1, BatchSize: 8}, func([]TXPacket) error { return nil })
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	if got, want := cap(tx.submitContainerOrder), min(tx.batchSize, len(tx.peerQueues)); got != want {
		t.Fatalf("TX submitContainerOrder capacity=%d, want %d", got, want)
	}
	txContainer := tx.getContainer(nil, false)
	if cap(txContainer.elems) != 0 {
		t.Fatalf("new TX container capacity=%d, want lazy 0", cap(txContainer.elems))
	}
	txContainer.elems = make([]*txElement, 1, pooledContainerCapacityLimit(tx.batchSize)+1)
	tx.putContainer(txContainer)
	if txContainer.elems != nil {
		t.Fatalf("oversized TX container retained capacity=%d", cap(txContainer.elems))
	}
	tx.Close()

	rx, err := NewRXEngine(core, RXEngineConfig{DecryptWorkers: 1, BatchSize: 8})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	if got, want := cap(rx.submitContainerOrder), min(rx.batchSize, len(rx.peerQueues)); got != want {
		t.Fatalf("RX submitContainerOrder capacity=%d, want %d", got, want)
	}
	rxContainer := rx.getContainer(nil, false)
	if cap(rxContainer.elems) != 0 {
		t.Fatalf("new RX container capacity=%d, want lazy 0", cap(rxContainer.elems))
	}
	rxContainer.elems = make([]*rxElement, 1, pooledContainerCapacityLimit(rx.batchSize)+1)
	rx.putContainer(rxContainer)
	if rxContainer.elems != nil {
		t.Fatalf("oversized RX container retained capacity=%d", cap(rxContainer.elems))
	}
	rx.Close()
}
