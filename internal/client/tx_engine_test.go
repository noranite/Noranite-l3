package client

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestClientTXEngineOperationSurvivesRotation(t *testing.T) {
	clientA, serverA := newClientLifecycleSessionPair(t, 0x9501, 0x41, 100)
	clientB, _ := newClientLifecycleSessionPair(t, 0x9502, 0x42, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientA)

	inner := testIPv4Packet(
		t,
		core.TunnelIPv4(),
		netip.MustParseAddr("203.0.113.20"),
		[]byte("queued before client rotation"),
	)
	op, err := core.AdmitInnerPacket(inner, len(inner)+dataplane.MaxDataExpansion)
	if err != nil {
		t.Fatalf("AdmitInnerPacket: %v", err)
	}
	oldSequence := op.Sequence()
	if _, err := core.InstallInitiatorSession(clientB); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	}

	var sent []TXPacket
	engine, err := NewTXEngine(core, TXEngineConfig{EncryptWorkers: 2}, func(packets []TXPacket) error {
		for _, packet := range packets {
			sent = append(sent, TXPacket{
				Wire:        bytes.Clone(packet.Wire),
				Destination: packet.Destination,
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}
	future, err := engine.Enqueue(TXSubmission{
		Operation: op,
		Buffer:    make([]byte, 0, op.MaxWireSize()),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	engine.Close()
	if result := <-future; result.Err != nil {
		t.Fatalf("TX result: %v", result.Err)
	}
	if len(sent) != 1 || sent[0].Destination != endpoint {
		t.Fatalf("sent=%+v, want one packet to %v", sent, endpoint)
	}

	scratch, _ := dataplane.NewDataScratch(routeKey)
	route, err := dataplane.DecodeRoute(scratch, sent[0].Wire)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if route.SessionID != clientA.ID() || route.Sequence != oldSequence {
		t.Fatalf("route=(%x,%d), want A/%d", route.SessionID, route.Sequence, oldSequence)
	}
	plaintext, err := serverA.AuthenticateInPlace(scratch, sent[0].Wire, route.Sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace(A): %v", err)
	}
	got, _, err := dataplane.ParseDataIPv4(plaintext, dataplane.ReferenceTunnelMTU)
	if err != nil || !bytes.Equal(got, inner) {
		t.Fatalf("pinned packet parse=%v equal=%v", err, bytes.Equal(got, inner))
	}
}

func TestClientTXEngineCloseDrainsAcceptedOperations(t *testing.T) {
	clientSession, _ := newClientLifecycleSessionPair(t, 0x9503, 0x43, 0)
	core, _, _ := newClientOperationCore(t, clientSession)

	var mu sync.Mutex
	sent := 0
	engine, err := NewTXEngine(core, TXEngineConfig{
		EncryptWorkers:   3,
		EncryptQueueSize: 4,
		PeerQueueSize:    4,
	}, func(packets []TXPacket) error {
		mu.Lock()
		sent += len(packets)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("NewTXEngine: %v", err)
	}

	const count = 48
	futures := make([]<-chan TXResult, 0, count)
	for i := 0; i < count; i++ {
		inner := testIPv4Packet(
			t,
			core.TunnelIPv4(),
			netip.MustParseAddr("203.0.113.30"),
			[]byte{byte(i)},
		)
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

	engine.Close()
	for i, future := range futures {
		if result := <-future; result.Err != nil {
			t.Fatalf("drained result %d: %v", i, result.Err)
		}
	}
	mu.Lock()
	gotSent := sent
	mu.Unlock()
	if gotSent != count {
		t.Fatalf("sent=%d, want %d", gotSent, count)
	}
	engine.Close()
	if _, err := engine.Enqueue(TXSubmission{}); !errors.Is(err, ErrTXEngineClosed) {
		t.Fatalf("Enqueue after Close error=%v, want ErrTXEngineClosed", err)
	}
}

func TestClientTXEngineValidationErrorClearsSubmitSeen(t *testing.T) {
	peer := &Peer{}
	engine := &TXEngine{
		core:       &Core{peer: peer},
		batchSize:  2,
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
