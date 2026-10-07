package client

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

type countingPacketBufferReleaser struct {
	mu    sync.Mutex
	count int
}

func (r *countingPacketBufferReleaser) Put([]byte) {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
}

func (r *countingPacketBufferReleaser) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

type engineErrorRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *engineErrorRecorder) Report(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
}

func (r *engineErrorRecorder) Errors() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.errs...)
}

func TestClientOwnedTXReleasesBufferAfterSendFailure(t *testing.T) {
	clientSession, _ := newClientLifecycleSessionPair(t, 0x9511, 0x51, 0)
	core, _, _ := newClientOperationCore(t, clientSession)
	inner := testIPv4Packet(
		t,
		core.TunnelIPv4(),
		netip.MustParseAddr("203.0.113.51"),
		[]byte("owned tx send failure"),
	)
	var op OutboundOperation
	if err := core.AdmitInnerPacketInto(&op, inner, len(inner)+dataplane.MaxDataExpansion); err != nil {
		t.Fatalf("AdmitInnerPacketInto: %v", err)
	}

	sendErr := errors.New("test send failure")
	releaser := new(countingPacketBufferReleaser)
	reporter := new(engineErrorRecorder)
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

func TestClientOwnedTXReleasesBufferAfterSealFailure(t *testing.T) {
	clientSession, _ := newClientLifecycleSessionPair(t, 0x9512, 0x52, 0)
	core, _, endpoint := newClientOperationCore(t, clientSession)

	releaser := new(countingPacketBufferReleaser)
	reporter := new(engineErrorRecorder)
	engine, err := NewOwnedTXEngine(
		core,
		TXEngineConfig{EncryptWorkers: 1, BatchSize: 1},
		func([]TXPacket) error { return nil },
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedTXEngine: %v", err)
	}

	// This operation passes ownership validation but has an invalid internal kind,
	// forcing the crypto worker down its seal-error recycle path.
	op := OutboundOperation{
		peer:        core.peer,
		session:     clientSession,
		destination: endpoint,
		kind:        outboundKind(0xff),
	}
	if err := engine.EnqueueOwned(
		TXOwnedSubmission{Operation: op, Buffer: make([]byte, 0, 1)},
		releaser,
	); err != nil {
		t.Fatalf("EnqueueOwned: %v", err)
	}
	engine.Close()

	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	errs := reporter.Errors()
	if len(errs) != 1 || !errors.Is(errs[0], dataplane.ErrInvalidConfig) {
		t.Fatalf("reported errors=%v, want invalid-config seal failure", errs)
	}
}

func TestClientOwnedRXDerivesReleaseBufferFromOperationPacket(t *testing.T) {
	clientSession, serverSession := newClientLifecycleSessionPair(t, 0x9411, 0x61, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientSession)
	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		core.TunnelIPv4(),
		[]byte("owned rx packet backing"),
	)
	txScratch, _ := dataplane.NewDataScratch(routeKey)
	wire, _, err := serverSession.SealDataTo(
		txScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}
	admitScratch, _ := core.NewDataScratch()
	op, err := core.AdmitNetworkDatagram(admitScratch, endpoint, wire)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram: %v", err)
	}

	releaser := new(countingPacketBufferReleaser)
	reporter := new(engineErrorRecorder)
	consumeErr := errors.New("test consume failure")
	var consumeCheckErr error
	consumed := false
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func(results []RXResult) error {
			consumed = true
			switch {
			case len(results) != 1:
				consumeCheckErr = errors.New("unexpected RX result count")
			case results[0].Err != nil:
				consumeCheckErr = results[0].Err
			case !bytes.Equal(results[0].Inbound.IPv4, inner):
				consumeCheckErr = errors.New("plaintext mismatch")
			case len(results[0].Buffer) == 0 || &results[0].Buffer[0] != &wire[0]:
				consumeCheckErr = errors.New("RX result buffer does not alias admitted operation packet")
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
	if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{Operation: *op}}, releaser); err != nil {
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

func TestClientOwnedRXReleasesBufferAfterDecryptFailure(t *testing.T) {
	clientSession, serverSession := newClientLifecycleSessionPair(t, 0x9412, 0x62, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientSession)
	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		core.TunnelIPv4(),
		[]byte("owned rx auth failure"),
	)
	txScratch, _ := dataplane.NewDataScratch(routeKey)
	wire, _, err := serverSession.SealDataTo(
		txScratch,
		make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
		inner,
	)
	if err != nil {
		t.Fatalf("SealDataTo: %v", err)
	}
	admitScratch, _ := core.NewDataScratch()
	op, err := core.AdmitNetworkDatagram(admitScratch, endpoint, wire)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram: %v", err)
	}
	wire[len(wire)-1] ^= 0x80

	releaser := new(countingPacketBufferReleaser)
	reporter := new(engineErrorRecorder)
	gotAuthFailure := false
	gotResultCount := 0
	engine, err := NewOwnedRXEngine(
		core,
		RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
		func(results []RXResult) error {
			gotResultCount = len(results)
			if len(results) == 1 {
				gotAuthFailure = errors.Is(results[0].Err, dataplane.ErrAuthentication)
			}
			return nil
		},
		reporter.Report,
	)
	if err != nil {
		t.Fatalf("NewOwnedRXEngine: %v", err)
	}
	if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{Operation: *op}}, releaser); err != nil {
		t.Fatalf("EnqueueOwnedBatch: %v", err)
	}
	engine.Close()

	if gotResultCount != 1 || !gotAuthFailure {
		t.Fatalf("owned RX result count=%d authFailure=%v, want 1/true", gotResultCount, gotAuthFailure)
	}
	if got := releaser.Count(); got != 1 {
		t.Fatalf("buffer release count=%d, want 1", got)
	}
	if errs := reporter.Errors(); len(errs) != 0 {
		t.Fatalf("reported errors=%v, want none", errs)
	}
}

func TestClientOwnedValidationDoesNotTakeBufferOwnership(t *testing.T) {
	clientSession, _ := newClientLifecycleSessionPair(t, 0x9413, 0x63, 0)
	core, _, _ := newClientOperationCore(t, clientSession)

	t.Run("TX", func(t *testing.T) {
		releaser := new(countingPacketBufferReleaser)
		reporter := new(engineErrorRecorder)
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
		releaser := new(countingPacketBufferReleaser)
		reporter := new(engineErrorRecorder)
		engine, err := NewOwnedRXEngine(
			core,
			RXEngineConfig{DecryptWorkers: 1, BatchSize: 1},
			func([]RXResult) error { return nil },
			reporter.Report,
		)
		if err != nil {
			t.Fatalf("NewOwnedRXEngine: %v", err)
		}
		if err := engine.EnqueueOwnedBatch([]RXOwnedSubmission{{}}, releaser); err == nil {
			t.Fatal("EnqueueOwnedBatch accepted invalid RX operation")
		}
		engine.Close()
		if got := releaser.Count(); got != 0 {
			t.Fatalf("buffer release count=%d, want 0 before ownership transfer", got)
		}
	})
}
