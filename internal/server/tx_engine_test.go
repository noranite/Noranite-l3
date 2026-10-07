package server

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestTXEnginePreservesPerPeerSendOrder(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	var mu sync.Mutex
	var sentSequences []uint64
	var sentDestinations []netip.AddrPort

	decodeScratch := newTestDataScratch(t, routeKey)
	engine, err := NewTXEngine(
		core,
		TXEngineConfig{
			EncryptWorkers:   4,
			EncryptQueueSize: 32,
			PeerQueueSize:    32,
		},
		func(packets []TXPacket) error {
			mu.Lock()
			defer mu.Unlock()
			for _, packet := range packets {
				route, err := dataplane.DecodeRoute(decodeScratch, packet.Wire)
				if err != nil {
					return err
				}
				sentSequences = append(sentSequences, route.Sequence)
				sentDestinations = append(sentDestinations, packet.Destination)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	defer engine.Close()

	const count = 64
	futures := make([]<-chan TXResult, 0, count)
	wantSequences := make([]uint64, 0, count)

	for i := 0; i < count; i++ {
		inner := testIPv4Packet(
			t,
			"10.66.0.1",
			"10.66.0.2",
			[]byte{byte(i), 0xa5},
		)
		op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
		if err != nil {
			t.Fatalf("AdmitInnerPacket(%d): %v", i, err)
		}
		wantSequences = append(wantSequences, op.Sequence())

		buffer := make([]byte, 0, op.MaxWireSize())
		future, err := engine.Enqueue(TXSubmission{Operation: op, Buffer: buffer})
		if err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}
		futures = append(futures, future)
	}

	for i, future := range futures {
		if result := <-future; result.Err != nil {
			t.Fatalf("TX result %d: %v", i, result.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sentSequences) != count {
		t.Fatalf("sent packet count=%d, want %d", len(sentSequences), count)
	}
	for i := range sentSequences {
		if sentSequences[i] != wantSequences[i] {
			t.Fatalf(
				"send sequence[%d]=%d, want admission sequence %d",
				i,
				sentSequences[i],
				wantSequences[i],
			)
		}
		if sentDestinations[i] != testLearnedEndpoint() {
			t.Fatalf(
				"destination[%d]=%v, want %v",
				i,
				sentDestinations[i],
				testLearnedEndpoint(),
			)
		}
	}
}

func TestTXEngineCloseDrainsAcceptedOperations(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 1000)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	var mu sync.Mutex
	sent := 0
	engine, err := NewTXEngine(
		core,
		TXEngineConfig{
			EncryptWorkers:   3,
			EncryptQueueSize: 4,
			PeerQueueSize:    4,
		},
		func(packets []TXPacket) error {
			mu.Lock()
			sent += len(packets)
			mu.Unlock()
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}

	const count = 48
	futures := make([]<-chan TXResult, 0, count)
	for i := 0; i < count; i++ {
		inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte{byte(i)})
		op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
		if err != nil {
			t.Fatalf("AdmitInnerPacket(%d): %v", i, err)
		}
		future, err := engine.Enqueue(TXSubmission{
			Operation: op,
			Buffer:    make([]byte, 0, op.MaxWireSize()),
		})
		if err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}
		futures = append(futures, future)
	}

	// Close is a drain boundary. It must wait for crypto and SendFunc, not just
	// close queue channels and abandon accepted packet buffers.
	engine.Close()

	for i, future := range futures {
		result, ok := <-future
		if !ok {
			t.Fatalf("result channel %d closed without result", i)
		}
		if result.Err != nil {
			t.Fatalf("drained result %d: %v", i, result.Err)
		}
	}

	mu.Lock()
	if sent != count {
		t.Fatalf("sent=%d, want %d", sent, count)
	}
	mu.Unlock()

	engine.Close()
	if _, err := engine.Enqueue(TXSubmission{}); !errors.Is(err, ErrTXEngineClosed) {
		t.Fatalf("Enqueue after Close error=%v, want ErrTXEngineClosed", err)
	}
}

func TestTXEnginePropagatesTransportFailureAfterEncryption(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 1200)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	wantErr := errors.New("synthetic send failure")
	engine, err := NewTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 2},
		func([]TXPacket) error { return wantErr },
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	defer engine.Close()

	inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte("send error"))
	op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
	if err != nil {
		t.Fatalf("AdmitInnerPacket: %v", err)
	}
	future, err := engine.Enqueue(TXSubmission{
		Operation: op,
		Buffer:    make([]byte, 0, op.MaxWireSize()),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if result := <-future; !errors.Is(result.Err, wantErr) {
		t.Fatalf("result error=%v, want %v", result.Err, wantErr)
	}
}

func learnTestServerEndpoint(
	t *testing.T,
	core *Core,
	clientSession *dataplane.Session,
	routeKey *[32]byte,
) {
	t.Helper()

	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte("learn endpoint"))
	wire, _ := sealTestPacket(t, clientSession, routeKey, inner)
	if _, err := core.HandleDatagramInPlace(
		newServerDataScratch(t, core),
		testLearnedEndpoint(),
		wire,
	); err != nil {
		t.Fatalf("learn server endpoint: %v", err)
	}
}

func testLearnedEndpoint() netip.AddrPort {
	return netip.MustParseAddrPort("192.0.2.99:51999")
}

func TestRXToTXEngineKeepaliveACKHandoff(t *testing.T) {
	routeKey, _, _ := testKeys()
	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: 1380,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{{
			TunnelIPv4: testPeerTunnelIPv4(),
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serverSession, clientSession := newLifecycleSessionPair(t, 0x91a2, 0x3c)
	if err := core.InstallPendingSession(testPeerTunnelIPv4(), serverSession); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	rxEngine, err := NewRXEngine(core, RXEngineConfig{DecryptWorkers: 2})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	defer rxEngine.Close()

	var sent []TXPacket
	txEngine, err := NewTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 2},
		func(packets []TXPacket) error {
			for _, packet := range packets {
				sent = append(sent, TXPacket{
					Wire:        append([]byte(nil), packet.Wire...),
					Destination: packet.Destination,
				})
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	defer txEngine.Close()

	const keepaliveID uint64 = 0x0123456789abcdef
	clientScratch := newTestDataScratch(t, routeKey)
	keepaliveStorage := make([]byte, 0, dataplane.MaxGeneratedControlWirePacketSize)
	keepalive, _, err := clientSession.SealKeepaliveTo(clientScratch, keepaliveStorage, keepaliveID)
	if err != nil {
		t.Fatalf("SealKeepaliveTo: %v", err)
	}

	source := netip.MustParseAddrPort("192.0.2.123:52123")
	op, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		source,
		keepalive,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(KEEPALIVE): %v", err)
	}
	future, err := rxEngine.Enqueue(op, true)
	if err != nil {
		t.Fatalf("RX Enqueue: %v", err)
	}
	rxResult := <-future
	if rxResult.Err != nil {
		t.Fatalf("RX result: %v", rxResult.Err)
	}
	if rxResult.Inbound.Kind != dataplane.InboundKeepalive || rxResult.Inbound.KeepaliveID != keepaliveID {
		t.Fatalf("RX inbound=%+v, want KEEPALIVE %x", rxResult.Inbound, keepaliveID)
	}
	if rxResult.Outbound == nil {
		t.Fatal("KEEPALIVE did not create ACK operation")
	}
	if rxResult.Outbound.Destination() != source {
		t.Fatalf("ACK destination=%v, want exact KEEPALIVE source %v", rxResult.Outbound.Destination(), source)
	}
	if core.CurrentSession(testPeerTunnelIPv4()) != serverSession {
		t.Fatal("authenticated pending KEEPALIVE did not promote Session")
	}

	ackBuffer := make([]byte, 0, rxResult.Outbound.MaxWireSize())
	txFuture, err := txEngine.Enqueue(TXSubmission{
		Operation: rxResult.Outbound,
		Buffer:    ackBuffer,
	})
	if err != nil {
		t.Fatalf("TX Enqueue(ACK): %v", err)
	}
	if result := <-txFuture; result.Err != nil {
		t.Fatalf("TX ACK result: %v", result.Err)
	}

	if len(sent) != 1 {
		t.Fatalf("sent packets=%d, want 1 ACK", len(sent))
	}
	if sent[0].Destination != source {
		t.Fatalf("sent ACK destination=%v, want %v", sent[0].Destination, source)
	}
	if len(sent[0].Wire) > len(keepalive) {
		t.Fatalf("ACK wire size=%d exceeds KEEPALIVE size=%d", len(sent[0].Wire), len(keepalive))
	}

	ackScratch := newTestDataScratch(t, routeKey)
	route, err := dataplane.DecodeRoute(ackScratch, sent[0].Wire)
	if err != nil {
		t.Fatalf("DecodeRoute(ACK): %v", err)
	}
	if route.SessionID != clientSession.ID() {
		t.Fatalf("ACK session=%x, want %x", route.SessionID, clientSession.ID())
	}
	plaintext, err := clientSession.AuthenticateInPlace(ackScratch, sent[0].Wire, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(ACK): %v", err)
	}
	control, err := dataplane.ParseControl(plaintext)
	if err != nil {
		t.Fatalf("ParseControl(ACK): %v", err)
	}
	if control.Type != dataplane.ControlACK || control.KeepaliveID != keepaliveID {
		t.Fatalf("ACK control=%+v, want ACK %x", control, keepaliveID)
	}
}

func TestTXEngineOperationSurvivesRotation(t *testing.T) {
	core, oldClient, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, oldClient, &routeKey)

	inner := testIPv4Packet(
		t,
		"10.66.0.1",
		"10.66.0.2",
		[]byte("admitted before rotation"),
	)
	op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
	if err != nil {
		t.Fatalf("AdmitInnerPacket: %v", err)
	}
	oldSession := op.Session()
	oldSequence := op.Sequence()
	oldDestination := op.Destination()

	newServer, newClient := newLifecycleSessionPair(t, 0x92a3, 0x4d)
	if err := core.InstallPendingSession(testPeerTunnelIPv4(), newServer); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	newEndpoint := netip.MustParseAddrPort("192.0.2.100:52000")
	promotionInner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("promote replacement generation"),
	)
	promotionWire, _ := sealTestPacket(t, newClient, &routeKey, promotionInner)
	if _, err := core.HandleDatagramInPlace(
		newServerDataScratch(t, core),
		newEndpoint,
		promotionWire,
	); err != nil {
		t.Fatalf("promote replacement Session: %v", err)
	}
	if core.CurrentSession(testPeerTunnelIPv4()) != newServer {
		t.Fatal("replacement Session is not current after promotion")
	}

	var sent []TXPacket
	engine, err := NewTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 2},
		func(packets []TXPacket) error {
			for _, packet := range packets {
				sent = append(sent, TXPacket{
					Wire:        bytes.Clone(packet.Wire),
					Destination: packet.Destination,
				})
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}

	future, err := engine.Enqueue(TXSubmission{
		Operation: op,
		Buffer:    make([]byte, 0, op.MaxWireSize()),
	})
	if err != nil {
		t.Fatalf("Enqueue pinned operation after rotation: %v", err)
	}
	engine.Close()

	if result := <-future; result.Err != nil {
		t.Fatalf("TX result: %v", result.Err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent packets=%d, want 1", len(sent))
	}
	if sent[0].Destination != oldDestination {
		t.Fatalf(
			"destination=%v, want pinned pre-rotation endpoint %v",
			sent[0].Destination,
			oldDestination,
		)
	}
	if sent[0].Destination == newEndpoint {
		t.Fatal("pinned operation re-read endpoint from replacement current Session")
	}

	decodeScratch := newTestDataScratch(t, routeKey)
	route, err := dataplane.DecodeRoute(decodeScratch, sent[0].Wire)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if route.SessionID != oldSession.ID() {
		t.Fatalf(
			"session=%#x, want pinned pre-rotation Session %#x",
			route.SessionID,
			oldSession.ID(),
		)
	}
	if route.Sequence != oldSequence {
		t.Fatalf("sequence=%d, want reserved sequence %d", route.Sequence, oldSequence)
	}

	plaintext, err := oldClient.AuthenticateInPlace(
		decodeScratch,
		sent[0].Wire,
		route.Sequence,
	)
	if err != nil {
		t.Fatalf("AuthenticateInPlace with pinned Session: %v", err)
	}
	gotInner, _, err := dataplane.ParseDataIPv4(plaintext, 1380)
	if err != nil {
		t.Fatalf("ParseDataIPv4: %v", err)
	}
	if !bytes.Equal(gotInner, inner) {
		t.Fatal("decrypted packet differs from pre-rotation admitted inner packet")
	}
}

func TestServerTXEngineValidationErrorClearsSubmitSeen(t *testing.T) {
	peer := &Peer{}
	engine := &TXEngine{
		peerQueues: map[*Peer]chan *txContainer{peer: nil},
		submitSeen: make(map[*OutboundOperation]struct{}),
	}
	valid := &OutboundOperation{
		peer:    peer,
		session: new(dataplane.Session),
	}

	if _, err := engine.EnqueueBatch([]TXSubmission{{Operation: valid}, {}}); err == nil {
		t.Fatal("EnqueueBatch accepted invalid submission")
	}
	if len(engine.submitSeen) != 0 {
		t.Fatalf("submitSeen retained %d operation(s) after validation error", len(engine.submitSeen))
	}
}

func TestTXEngineCompatibilityBatchMayExceedOwnedBatchSize(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 1500)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	var mu sync.Mutex
	sent := 0
	engine, err := NewTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
		func(packets []TXPacket) error {
			mu.Lock()
			sent += len(packets)
			mu.Unlock()
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	defer engine.Close()

	submissions := make([]TXSubmission, 2)
	for i := range submissions {
		inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte{byte(i)})
		op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
		if err != nil {
			t.Fatalf("AdmitInnerPacket(%d): %v", i, err)
		}
		submissions[i] = TXSubmission{
			Operation: op,
			Buffer:    make([]byte, 0, op.MaxWireSize()),
		}
	}

	futures, err := engine.EnqueueBatch(submissions)
	if err != nil {
		t.Fatalf("EnqueueBatch: %v", err)
	}
	for i, future := range futures {
		if result := <-future; result.Err != nil {
			t.Fatalf("result %d: %v", i, result.Err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if sent != len(submissions) {
		t.Fatalf("sent=%d, want %d", sent, len(submissions))
	}
}
