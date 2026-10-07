package server

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestCoreRoutesMultiplePeersBySessionIDAndTunnelIPv4(t *testing.T) {
	routeKey, _, _ := testKeys()

	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")
	serverTunnel := netip.MustParseAddr("10.66.0.1")

	serverA, clientA := newLifecycleSessionPair(t, 0x5101, 0x11)
	serverB, clientB := newLifecycleSessionPair(t, 0x5102, 0x22)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerA, InitialSession: serverA},
			{TunnelIPv4: peerB, InitialSession: serverB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	endpointA := netip.MustParseAddrPort("192.0.2.10:50000")
	endpointB := netip.MustParseAddrPort("192.0.2.20:50001")

	// RX must choose the Peer from session_id, not from inner plaintext. Each
	// authenticated Session therefore learns only its own outer endpoint and
	// authorizes only its configured tunnel source address.
	for _, tc := range []struct {
		name     string
		peerIP   netip.Addr
		client   *dataplane.Session
		endpoint netip.AddrPort
		payload  string
	}{
		{
			name:     "peer A",
			peerIP:   peerA,
			client:   clientA,
			endpoint: endpointA,
			payload:  "from A",
		},
		{
			name:     "peer B",
			peerIP:   peerB,
			client:   clientB,
			endpoint: endpointB,
			payload:  "from B",
		},
	} {
		t.Run(tc.name+" RX", func(t *testing.T) {
			inner := testIPv4Packet(
				t,
				tc.peerIP.String(),
				serverTunnel.String(),
				[]byte(tc.payload),
			)
			wire, _ := sealTestPacket(t, tc.client, &routeKey, inner)

			opened, err := core.HandleDatagramInPlace(
				newServerDataScratch(t, core),
				tc.endpoint,
				wire,
			)
			if err != nil {
				t.Fatalf("HandleDatagramInPlace: %v", err)
			}
			if !bytes.Equal(opened, inner) {
				t.Fatal("opened inner packet differs from original")
			}
		})
	}

	if got, ok := serverA.Endpoint(); !ok || got != endpointA {
		t.Fatalf("peer A endpoint=(%v,%v), want %v", got, ok, endpointA)
	}
	if got, ok := serverB.Endpoint(); !ok || got != endpointB {
		t.Fatalf("peer B endpoint=(%v,%v), want %v", got, ok, endpointB)
	}

	// TX must independently choose Peer by exact inner destination and then use
	// only that Peer's current Session + authenticated endpoint.
	for _, tc := range []struct {
		name     string
		peerIP   netip.Addr
		server   *dataplane.Session
		endpoint netip.AddrPort
		payload  string
	}{
		{
			name:     "peer A",
			peerIP:   peerA,
			server:   serverA,
			endpoint: endpointA,
			payload:  "to A",
		},
		{
			name:     "peer B",
			peerIP:   peerB,
			server:   serverB,
			endpoint: endpointB,
			payload:  "to B",
		},
	} {
		t.Run(tc.name+" TX", func(t *testing.T) {
			inner := testIPv4Packet(
				t,
				serverTunnel.String(),
				tc.peerIP.String(),
				[]byte(tc.payload),
			)
			scratch := newServerDataScratch(t, core)
			dst := make([]byte, 0, len(inner)+dataplane.MaxDataExpansion)

			wire, destination, err := core.HandleInnerPacketTo(
				scratch,
				dst,
				inner,
			)
			if err != nil {
				t.Fatalf("HandleInnerPacketTo: %v", err)
			}
			if destination != tc.endpoint {
				t.Fatalf("destination=%v, want %v", destination, tc.endpoint)
			}

			route, err := dataplane.DecodeRoute(scratch, wire)
			if err != nil {
				t.Fatalf("DecodeRoute: %v", err)
			}
			if route.SessionID != tc.server.ID() {
				t.Fatalf(
					"session=%#x, want %#x",
					route.SessionID,
					tc.server.ID(),
				)
			}
		})
	}
}

func TestCoreRXSessionBindingEnforcesOwningPeerSource(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")

	serverA, clientA := newLifecycleSessionPair(t, 0x5201, 0x31)
	serverB, _ := newLifecycleSessionPair(t, 0x5202, 0x42)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerA, InitialSession: serverA},
			{TunnelIPv4: peerB, InitialSession: serverB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Packet authenticates under peer A Session but claims peer B's tunnel
	// source. The global session binding must still authorize against peer A.
	inner := testIPv4Packet(
		t,
		peerB.String(),
		"10.66.0.1",
		nil,
	)
	wire, _ := sealTestPacket(t, clientA, &routeKey, inner)

	_, err = core.HandleDatagramInPlace(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.30:50002"),
		wire,
	)
	if !errors.Is(err, ErrUnauthorizedSource) {
		t.Fatalf("error=%v, want ErrUnauthorizedSource", err)
	}
}

func TestCoreRejectsGlobalInitialSessionIDCollision(t *testing.T) {
	routeKey, _, _ := testKeys()

	serverA, _ := newLifecycleSessionPair(t, 0x5301, 0x51)
	serverB, _ := newLifecycleSessionPair(t, 0x5301, 0x62)

	_, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{
				TunnelIPv4:     netip.MustParseAddr("10.66.0.2"),
				InitialSession: serverA,
			},
			{
				TunnelIPv4:     netip.MustParseAddr("10.66.0.3"),
				InitialSession: serverB,
			},
		},
	})
	if !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("error=%v, want ErrSessionIDCollision", err)
	}
}

func TestCoreInstallPendingChecksCollisionAcrossPeers(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")

	serverA, _ := newLifecycleSessionPair(t, 0x5401, 0x71)
	serverB, _ := newLifecycleSessionPair(t, 0x5402, 0x72)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerA, InitialSession: serverA},
			{TunnelIPv4: peerB, InitialSession: serverB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Different traffic keys do not make a duplicate session_id acceptable:
	// route lookup must remain globally unambiguous.
	colliding, _ := newLifecycleSessionPair(t, serverB.ID(), 0x7f)
	if err := core.InstallPendingSession(peerA, colliding); !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("InstallPendingSession error=%v, want ErrSessionIDCollision", err)
	}

	if got := core.CurrentSession(peerA); got != serverA {
		t.Fatal("collision changed peer A current Session")
	}
}

func TestCorePendingReplacementRemovesOldSessionIndex(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := netip.MustParseAddr("10.66.0.2")
	current, _ := newLifecycleSessionPair(t, 0x5501, 0x21)
	pendingA, _ := newLifecycleSessionPair(t, 0x5502, 0x22)
	pendingB, _ := newLifecycleSessionPair(t, 0x5503, 0x23)

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          testLifecycleConfig(),
		Peers: []PeerConfig{
			{TunnelIPv4: peerIP, InitialSession: current},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	now := time.Unix(1_700_001_000, 0)
	core.now = func() time.Time { return now }

	if err := core.InstallPendingSession(peerIP, pendingA); err != nil {
		t.Fatalf("InstallPendingSession(A): %v", err)
	}
	if err := core.InstallPendingSession(peerIP, pendingB); err != nil {
		t.Fatalf("InstallPendingSession(B): %v", err)
	}

	if _, ok := core.lookupRXBinding(pendingA.ID()); ok {
		t.Fatal("superseded pending remains in sessionsByID")
	}
	if _, ok := core.lookupRXBinding(pendingB.ID()); !ok {
		t.Fatal("new pending is missing from sessionsByID")
	}
}

func TestCoreExpiredPendingIndexBlocksSessionIDReuseUntilRetired(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerA := netip.MustParseAddr("10.66.0.2")
	peerB := netip.MustParseAddr("10.66.0.3")

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: time.Second,
			ReceiveGrace:       2 * time.Second,
		},
		Peers: []PeerConfig{
			{TunnelIPv4: peerA},
			{TunnelIPv4: peerB},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_002_000, 0)
	core.now = func() time.Time { return t0 }

	const reusedID uint64 = 0x5601
	expired, _ := newLifecycleSessionPair(t, reusedID, 0x41)
	if err := core.InstallPendingSession(peerA, expired); err != nil {
		t.Fatalf("InstallPendingSession(expiring): %v", err)
	}

	// At the admission deadline this Session no longer accepts NEW RX work, but
	// it still occupies peerA.pending. An earlier admitted operation may still
	// finish and promote it, so the numeric ID cannot be reused yet.
	core.now = func() time.Time { return t0.Add(time.Second) }

	reused, _ := newLifecycleSessionPair(t, reusedID, 0x52)
	if err := core.InstallPendingSession(peerB, reused); !errors.Is(err, ErrSessionIDCollision) {
		t.Fatalf("reuse while expired pending is slot-resident error=%v, want ErrSessionIDCollision", err)
	}

	// A real lifecycle transition retires the expired pending and removes its
	// exact registry binding. Only then may the numeric ID be reused elsewhere.
	replacement, _ := newLifecycleSessionPair(t, 0x5602, 0x63)
	if err := core.InstallPendingSession(peerA, replacement); err != nil {
		t.Fatalf("InstallPendingSession(replacement): %v", err)
	}
	if err := core.InstallPendingSession(peerB, reused); err != nil {
		t.Fatalf("session_id should be reusable after retirement, got: %v", err)
	}

	binding, ok := core.lookupRXBinding(reusedID)
	if !ok {
		t.Fatal("reused live session_id missing from sessionsByID")
	}
	if binding.tunnelIPv4 != peerB {
		t.Fatalf("binding peer=%v, want %v", binding.tunnelIPv4, peerB)
	}
}

func TestCoreExpiredPendingRejectDoesNotRemoveBindingNeededByAdmittedPromotion(t *testing.T) {
	routeKey, _, _ := testKeys()
	peerIP := netip.MustParseAddr("10.66.0.2")

	core, err := New(Config{
		RouteKey:           routeKey,
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: time.Second,
			ReceiveGrace:       2 * time.Second,
		},
		Peers: []PeerConfig{{TunnelIPv4: peerIP}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t0 := time.Unix(1_700_002_100, 0)
	core.now = func() time.Time { return t0 }

	serverSession, clientSession := newLifecycleSessionPair(t, 0x5701, 0x71)
	if err := core.InstallPendingSession(peerIP, serverSession); err != nil {
		t.Fatalf("InstallPendingSession: %v", err)
	}

	inner := testIPv4Packet(t, peerIP.String(), "10.66.0.1", []byte("admitted before expiry"))
	p1, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	p2, _ := sealTestPacket(t, clientSession, &routeKey, inner)
	p3, _ := sealTestPacket(t, clientSession, &routeKey, inner)

	// P1 starts before the admission deadline and is allowed to finish later.
	core.now = func() time.Time { return t0.Add(time.Second - time.Nanosecond) }
	op1, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.70:57000"),
		p1,
	)
	if err != nil {
		t.Fatalf("AdmitNetworkDatagram(P1): %v", err)
	}

	// P2 arrives after the deadline. Rejecting this NEW operation must not evict
	// the binding, because P1 still owns a valid admission capability.
	core.now = func() time.Time { return t0.Add(time.Second + time.Nanosecond) }
	if _, err := core.AdmitNetworkDatagram(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.71:57001"),
		p2,
	); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("AdmitNetworkDatagram(P2) error=%v, want ErrSessionNotRXEligible", err)
	}
	if _, ok := core.lookupRXBinding(serverSession.ID()); !ok {
		t.Fatal("expired pending rejection removed a still slot-resident Session binding")
	}

	if err := op1.Decrypt(newServerDataScratch(t, core)); err != nil {
		t.Fatalf("Decrypt(P1): %v", err)
	}
	if _, _, err := core.CommitInbound(op1, false); err != nil {
		t.Fatalf("CommitInbound(P1): %v", err)
	}
	if got := core.CurrentSession(peerIP); got != serverSession {
		t.Fatal("admitted pre-deadline operation did not promote pending Session")
	}

	// Promotion after the hard generation deadline does not refresh rejectAt.
	// The binding remains globally routable/resident, but NEW RX admission must
	// still fail on the now-current generation.
	if _, ok := core.lookupRXBinding(serverSession.ID()); !ok {
		t.Fatal("promoted hard-expired Session lost its registry binding")
	}
	if _, err := core.HandleDatagramInPlace(
		newServerDataScratch(t, core),
		netip.MustParseAddrPort("192.0.2.72:57002"),
		p3,
	); !errors.Is(err, ErrSessionNotRXEligible) {
		t.Fatalf("post-promotion hard-expired RX error=%v, want ErrSessionNotRXEligible", err)
	}
}
