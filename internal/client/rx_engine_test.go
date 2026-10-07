package client

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestClientRXEngineConcurrentDuplicateDeliveryAcceptsExactlyOne(t *testing.T) {
	clientSession, serverSession := newClientLifecycleSessionPair(t, 0x9401, 0x31, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientSession)
	engine, err := NewRXEngine(core, RXEngineConfig{
		DecryptWorkers:   4,
		DecryptQueueSize: 16,
		PeerQueueSize:    16,
	})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}
	defer engine.Close()

	inner := testIPv4Packet(
		t,
		netip.MustParseAddr("10.66.0.1"),
		core.TunnelIPv4(),
		[]byte("same async client datagram"),
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
	const copies = 32
	futures := make([]<-chan RXResult, 0, copies)
	for i := 0; i < copies; i++ {
		op, err := core.AdmitNetworkDatagram(admitScratch, endpoint, bytes.Clone(wire))
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}
		future, err := engine.Enqueue(op)
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
			if !bytes.Equal(result.Inbound.IPv4, inner) {
				t.Fatalf("result %d plaintext mismatch", i)
			}
		case errors.Is(result.Err, dataplane.ErrReplay):
			replays++
		default:
			t.Fatalf("result %d error=%v", i, result.Err)
		}
	}
	if successes != 1 || replays != copies-1 {
		t.Fatalf("successes=%d replays=%d, want 1/%d", successes, replays, copies-1)
	}
}

func TestClientRXEngineCloseDrainsAcceptedOperations(t *testing.T) {
	clientSession, serverSession := newClientLifecycleSessionPair(t, 0x9402, 0x32, 0)
	core, routeKey, endpoint := newClientOperationCore(t, clientSession)
	engine, err := NewRXEngine(core, RXEngineConfig{
		DecryptWorkers:   3,
		DecryptQueueSize: 4,
		PeerQueueSize:    4,
	})
	if err != nil {
		t.Fatalf("NewRXEngine: %v", err)
	}

	admitScratch, _ := core.NewDataScratch()
	txScratch, _ := dataplane.NewDataScratch(routeKey)
	const count = 48
	futures := make([]<-chan RXResult, 0, count)
	for i := 0; i < count; i++ {
		inner := testIPv4Packet(
			t,
			netip.MustParseAddr("10.66.0.1"),
			core.TunnelIPv4(),
			[]byte{byte(i)},
		)
		wire, _, err := serverSession.SealDataTo(
			txScratch,
			make([]byte, 0, len(inner)+dataplane.MaxDataExpansion),
			inner,
		)
		if err != nil {
			t.Fatalf("SealDataTo(%d): %v", i, err)
		}
		op, err := core.AdmitNetworkDatagram(admitScratch, endpoint, wire)
		if err != nil {
			t.Fatalf("AdmitNetworkDatagram(%d): %v", i, err)
		}
		future, err := engine.Enqueue(op)
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
	engine.Close()
	if _, err := engine.Enqueue(&InboundOperation{}); !errors.Is(err, ErrRXEngineClosed) {
		t.Fatalf("Enqueue after Close error=%v, want ErrRXEngineClosed", err)
	}
}

func TestClientRXEngineValidationErrorClearsSubmitSeen(t *testing.T) {
	peer := &Peer{}
	engine := &RXEngine{
		core:       &Core{peer: peer},
		batchSize:  2,
		submitSeen: make(map[*InboundOperation]struct{}),
	}
	valid := &InboundOperation{
		peer: peer,
		admission: RXAdmission{
			Session: new(dataplane.Session),
		},
	}

	if _, err := engine.EnqueueBatch([]*InboundOperation{valid, nil}); err == nil {
		t.Fatal("EnqueueBatch accepted invalid operation")
	}
	if len(engine.submitSeen) != 0 {
		t.Fatalf("submitSeen retained %d operation(s) after validation error", len(engine.submitSeen))
	}
}
