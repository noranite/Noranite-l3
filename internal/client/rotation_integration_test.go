package client

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/server"
)

func TestClientServerDirectRotationWithoutACKDependency(t *testing.T) {
	routeKey, _, _ := testKeys()
	clientA, serverA := newClientLifecycleSessionPair(t, 0x9601, 0x51, 0)
	clientB, serverB := newClientLifecycleSessionPair(t, 0x9602, 0x52, 0)

	clientTunnel := netip.MustParseAddr("10.66.0.2")
	serverTunnel := netip.MustParseAddr("10.66.0.1")
	serverEndpoint := netip.MustParseAddrPort("198.51.100.10:51820")
	clientEndpoint := netip.MustParseAddrPort("192.0.2.10:50000")
	lifecycle := LifecycleConfig{
		GenerationLifetime: 30 * time.Second,
		ReceiveGrace:       5 * time.Second,
	}

	clientCore, err := New(Config{
		RouteKey:           routeKey,
		TunnelIPv4:         clientTunnel,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          lifecycle,
		Session:            clientA,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	serverCore, err := server.New(server.Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: lifecycle.GenerationLifetime,
			ReceiveGrace:       lifecycle.ReceiveGrace,
		},
		Peers: []server.PeerConfig{{
			TunnelIPv4:     clientTunnel,
			InitialSession: serverA,
		}},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	if err := serverCore.InstallPendingSession(clientTunnel, serverB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}
	t0 := time.Now()
	clientNow := t0
	clientCore.now = func() time.Time { return clientNow }
	if retired, err := clientCore.InstallInitiatorSession(clientB); err != nil {
		t.Fatalf("InstallInitiatorSession(B): %v", err)
	} else if retired != nil {
		t.Fatalf("first client rotation retired %p, want nil", retired)
	}

	clientScratch, _ := clientCore.NewDataScratch()
	serverScratch, _ := serverCore.NewDataScratch()

	// No KEEPALIVE/ACK is needed for correctness: ordinary DATA(B) is sufficient to
	// promote server pending B.
	activation := testIPv4Packet(
		t,
		clientTunnel,
		serverTunnel,
		[]byte("activate B with DATA"),
	)
	wireB, destination, err := clientCore.HandleInnerPacketTo(
		clientScratch,
		make([]byte, 0, len(activation)+dataplane.MaxDataExpansion),
		activation,
	)
	if err != nil {
		t.Fatalf("client B DATA: %v", err)
	}
	if destination != serverEndpoint {
		t.Fatalf("client destination=%v, want %v", destination, serverEndpoint)
	}
	if _, err := serverCore.HandleDatagramInPlace(serverScratch, clientEndpoint, wireB); err != nil {
		t.Fatalf("server receive B DATA: %v", err)
	}
	if serverCore.CurrentSession(clientTunnel) != serverB {
		t.Fatal("server did not promote B on authenticated DATA")
	}

	// The first authenticated reverse packet on client current B is the evidence
	// that arms short grace for previous A.
	clientNow = t0.Add(time.Second)
	reverse := testIPv4Packet(
		t,
		serverTunnel,
		clientTunnel,
		[]byte("reverse B evidence"),
	)
	wireReverse, destination, err := serverCore.HandleInnerPacketTo(
		serverScratch,
		make([]byte, 0, len(reverse)+dataplane.MaxDataExpansion),
		reverse,
	)
	if err != nil {
		t.Fatalf("server B DATA: %v", err)
	}
	if destination != clientEndpoint {
		t.Fatalf("server destination=%v, want learned %v", destination, clientEndpoint)
	}
	if _, err := clientCore.HandleDatagramInPlace(clientScratch, serverEndpoint, wireReverse); err != nil {
		t.Fatalf("client receive reverse B: %v", err)
	}

	clientCore.peer.mu.RLock()
	if clientCore.peer.previous.session != clientA {
		clientCore.peer.mu.RUnlock()
		t.Fatal("A is not previous after B rotation")
	}
	shortRejectAt := clientCore.peer.previous.shortRejectAt
	clientCore.peer.mu.RUnlock()
	wantShortRejectAt := clientNow.Add(lifecycle.ReceiveGrace)
	if !shortRejectAt.Equal(wantShortRejectAt) {
		t.Fatalf("A shortRejectAt=%v, want %v", shortRejectAt, wantShortRejectAt)
	}

	// A remains usable strictly before the short deadline, then becomes
	// ineligible for new admissions. This is independent of any ACK state.
	oldInner := testIPv4Packet(t, serverTunnel, clientTunnel, []byte("late A"))
	oldTX, _ := dataplane.NewDataScratch(routeKey)
	oldWire, _, err := serverA.SealDataTo(
		oldTX,
		make([]byte, 0, len(oldInner)+dataplane.MaxDataExpansion),
		oldInner,
	)
	if err != nil {
		t.Fatalf("serverA SealDataTo: %v", err)
	}

	clientNow = wantShortRejectAt.Add(-time.Nanosecond)
	beforeDeadline := append([]byte(nil), oldWire...)
	if _, err := clientCore.HandleDatagramInPlace(clientScratch, serverEndpoint, beforeDeadline); err != nil {
		t.Fatalf("previous A before short deadline: %v", err)
	}

	oldWire2, _, err := serverA.SealDataTo(
		oldTX,
		make([]byte, 0, len(oldInner)+dataplane.MaxDataExpansion),
		oldInner,
	)
	if err != nil {
		t.Fatalf("serverA SealDataTo(2): %v", err)
	}
	clientNow = wantShortRejectAt
	if _, err := clientCore.HandleDatagramInPlace(clientScratch, serverEndpoint, oldWire2); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("previous A at short deadline error=%v, want ErrSessionNotRXEligible", err)
	}
}
