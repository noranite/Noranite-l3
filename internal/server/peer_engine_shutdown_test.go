package server

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestRXRetireAfterEngineClose(t *testing.T) {
	for i := 0; i < 200; i++ {
		peer := &Peer{}
		e := &RXEngine{
			decryptQueue: make(chan *rxContainer),
			peerQueues:   map[*Peer]chan *rxContainer{peer: make(chan *rxContainer)},
			done:         make(chan struct{}),
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); e.Close() }()
		go func() { defer wg.Done(); e.RetirePeer(peer) }()
		wg.Wait()
		// Idempotent even after the map entries have been cleared by Close.
		e.RetirePeer(peer)
		e.Close()
	}
}

func TestTXRetireAfterEngineClose(t *testing.T) {
	for i := 0; i < 200; i++ {
		peer := &Peer{}
		e := &TXEngine{
			encryptQueue: make(chan *txContainer),
			peerQueues:   map[*Peer]chan *txContainer{peer: make(chan *txContainer)},
			done:         make(chan struct{}),
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); e.Close() }()
		go func() { defer wg.Done(); e.RetirePeer(peer) }()
		wg.Wait()
		e.RetirePeer(peer)
		e.Close()
	}
}

func TestRXFirstOwnedEnqueueRacesClose(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 500)
	source := netip.MustParseAddrPort("192.0.2.210:52210")

	for i := 0; i < 50; i++ {
		inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte{byte(i)})
		wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)
		op, err := core.AdmitNetworkDatagram(newServerDataScratch(t, core), source, wire)
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}

		releaser := new(serverCountingBufferReleaser)
		reporter := new(serverEngineErrorRecorder)
		engine, err := NewOwnedRXEngine(
			core,
			RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
			func([]RXOwnedResult) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var enqueueErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			enqueueErr = engine.EnqueueOwnedBatch(
				[]RXOwnedSubmission{{Operation: *op}},
				false,
				releaser,
			)
		}()
		go func() {
			defer wg.Done()
			<-start
			engine.Close()
		}()
		close(start)
		wg.Wait()
		engine.Close()

		switch {
		case enqueueErr == nil:
			if got := releaser.Count(); got != 1 {
				t.Fatalf("iteration %d accepted buffer release count=%d, want 1", i, got)
			}
		case errors.Is(enqueueErr, ErrRXEngineClosed):
			if got := releaser.Count(); got != 0 {
				t.Fatalf("iteration %d rejected buffer release count=%d, want 0", i, got)
			}
		default:
			t.Fatalf("iteration %d enqueue error=%v", i, enqueueErr)
		}
	}
}

func TestTXFirstOwnedEnqueueRacesClose(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)

	for i := 0; i < 50; i++ {
		inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte{byte(i)})
		op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
		if err != nil {
			t.Fatalf("AdmitInnerPacket(%d): %v", i, err)
		}

		releaser := new(serverCountingBufferReleaser)
		reporter := new(serverEngineErrorRecorder)
		engine, err := NewOwnedTXEngine(
			core,
			TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
			func([]TXPacket) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var enqueueErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			enqueueErr = engine.EnqueueOwned(
				TXOwnedSubmission{Operation: *op, Buffer: make([]byte, 0, op.MaxWireSize())},
				releaser,
			)
		}()
		go func() {
			defer wg.Done()
			<-start
			engine.Close()
		}()
		close(start)
		wg.Wait()
		engine.Close()

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
			t.Fatalf("iteration %d enqueue error=%v", i, enqueueErr)
		}
	}
}

func TestRXOwnedAdmissionRacesRetire(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 0, 500)
	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte("retire rx"))
	wire, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	op, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.211:52211"),
		wire,
	)
	if err != nil {
		t.Fatal(err)
	}
	peer := core.PeerForIP(testPeerTunnelIPv4())

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func([]RXOwnedResult) error { return nil },
		reporter.Report,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.RevokePeer(testPeerTunnelIPv4(), peer); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var enqueueErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		enqueueErr = engine.EnqueueOwnedBatch(
			[]RXOwnedSubmission{{Operation: *op}},
			false,
			releaser,
		)
	}()
	go func() {
		defer wg.Done()
		<-start
		engine.RetirePeer(peer)
	}()
	close(start)
	wg.Wait()

	engine.submitMu.Lock()
	_, registered := engine.peerQueues[peer]
	engine.submitMu.Unlock()
	if registered {
		t.Fatal("retired RX peer remains registered")
	}
	engine.Close()

	if enqueueErr != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", enqueueErr)
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
}

func TestTXOwnedAdmissionRacesRetire(t *testing.T) {
	core, clientSession, routeKey := newTestServer(t, 100, 700)
	learnTestServerEndpoint(t, core, clientSession, &routeKey)
	inner := testIPv4Packet(t, "10.66.0.1", "10.66.0.2", []byte("retire tx"))
	op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
	if err != nil {
		t.Fatal(err)
	}
	peer := core.PeerForIP(testPeerTunnelIPv4())

	releaser := new(serverCountingBufferReleaser)
	reporter := new(serverEngineErrorRecorder)
	engine, err := NewOwnedTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
		func([]TXPacket) error { return nil },
		reporter.Report,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.RevokePeer(testPeerTunnelIPv4(), peer); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var enqueueErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		enqueueErr = engine.EnqueueOwned(
			TXOwnedSubmission{Operation: *op, Buffer: make([]byte, 0, op.MaxWireSize())},
			releaser,
		)
	}()
	go func() {
		defer wg.Done()
		<-start
		engine.RetirePeer(peer)
	}()
	close(start)
	wg.Wait()

	engine.submitMu.Lock()
	_, registered := engine.peerQueues[peer]
	engine.submitMu.Unlock()
	if registered {
		t.Fatal("retired TX peer remains registered")
	}
	engine.Close()

	if enqueueErr != nil {
		t.Fatalf("EnqueueOwned: %v", enqueueErr)
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
}
