package servercontrol

import (
	"errors"
	"net/netip"
	"testing"
)

func TestControllerSyncPeersReusesExactAndReplacesEverythingElse(t *testing.T) {
	controller, core, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	keyA := testPublicKey(t, 1)
	keyB := testPublicKey(t, 2)
	keyC := testPublicKey(t, 3)
	ip2 := netip.MustParseAddr("10.88.0.2")
	ip3 := netip.MustParseAddr("10.88.0.3")
	ip4 := netip.MustParseAddr("10.88.0.4")

	if err := controller.SetPeer(Peer{TunnelIPv4: ip2, PublicKey: keyA}); err != nil {
		t.Fatal(err)
	}
	if err := controller.SetPeer(Peer{TunnelIPv4: ip3, PublicKey: keyB}); err != nil {
		t.Fatal(err)
	}
	oldA := core.PeerForIP(ip2)
	oldB := core.PeerForIP(ip3)

	// B moves while C takes B's old address. A sequential SetPeer(C@ip3)
	// would conflict with the old B binding; snapshot sync has no such ordering.
	if err := controller.SyncPeers([]Peer{
		{TunnelIPv4: ip2, PublicKey: keyA},
		{TunnelIPv4: ip4, PublicKey: keyB},
		{TunnelIPv4: ip3, PublicKey: keyC},
	}); err != nil {
		t.Fatalf("SyncPeers: %v", err)
	}

	if got := core.PeerForIP(ip2); got != oldA {
		t.Fatalf("unchanged A peer=%p, want %p", got, oldA)
	}
	if oldA.IsRevoked() {
		t.Fatal("unchanged A was revoked")
	}
	if !oldB.IsRevoked() {
		t.Fatal("changed B old Core peer was not revoked")
	}
	newB := core.PeerForIP(ip4)
	newC := core.PeerForIP(ip3)
	if newB == nil || newC == nil || newB == oldB || newC == oldB {
		t.Fatalf("unexpected replacement peers: B=%p C=%p oldB=%p", newB, newC, oldB)
	}

	// Swap the two changed identities. This would require ordering or temporary
	// addresses with per-peer mutation, but is just another snapshot here.
	if err := controller.SyncPeers([]Peer{
		{TunnelIPv4: ip2, PublicKey: keyA},
		{TunnelIPv4: ip3, PublicKey: keyB},
		{TunnelIPv4: ip4, PublicKey: keyC},
	}); err != nil {
		t.Fatalf("SyncPeers swap: %v", err)
	}
	if got := core.PeerForIP(ip2); got != oldA {
		t.Fatalf("unchanged A changed during swap: %p", got)
	}
	if got := core.PeerForIP(ip3); got == nil || got == newB || got == newC {
		t.Fatalf("B swap peer was not replaced: %p", got)
	}
	if got := core.PeerForIP(ip4); got == nil || got == newB || got == newC {
		t.Fatalf("C swap peer was not replaced: %p", got)
	}
}

func TestControllerSyncPeersRejectsInvalidSnapshotWithoutMutation(t *testing.T) {
	controller, core, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	keyA := testPublicKey(t, 10)
	keyB := testPublicKey(t, 11)
	ip := netip.MustParseAddr("10.88.0.20")
	if err := controller.SetPeer(Peer{TunnelIPv4: ip, PublicKey: keyA}); err != nil {
		t.Fatal(err)
	}
	old := core.PeerForIP(ip)

	err := controller.SyncPeers([]Peer{
		{TunnelIPv4: ip, PublicKey: keyA},
		{TunnelIPv4: ip, PublicKey: keyB},
	})
	if !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("SyncPeers error=%v, want ErrPeerConflict", err)
	}
	if got := core.PeerForIP(ip); got != old {
		t.Fatalf("runtime changed after rejected sync: %p, want %p", got, old)
	}
	if old.IsRevoked() {
		t.Fatal("existing peer revoked by rejected sync")
	}
}

func TestControllerSyncPeersEmptyRemovesAll(t *testing.T) {
	controller, core, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	key := testPublicKey(t, 20)
	ip := netip.MustParseAddr("10.88.0.30")
	if err := controller.SetPeer(Peer{TunnelIPv4: ip, PublicKey: key}); err != nil {
		t.Fatal(err)
	}
	old := core.PeerForIP(ip)
	if err := controller.SyncPeers(nil); err != nil {
		t.Fatal(err)
	}
	if core.HasPeers() {
		t.Fatal("Core still has peers after empty sync")
	}
	if !old.IsRevoked() {
		t.Fatal("removed peer was not revoked")
	}
	peers, err := controller.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("controller still lists peers: %#v", peers)
	}
}

func TestControllerSyncPeersRepairsRevokedCorePeer(t *testing.T) {
	controller, core, noise, rx, tx := newTestControllerWithNoise(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	key := testPublicKey(t, 40)
	ip := netip.MustParseAddr("10.88.0.40")
	desired := Peer{TunnelIPv4: ip, PublicKey: key}
	if err := controller.SetPeer(desired); err != nil {
		t.Fatal(err)
	}
	old := core.PeerForIP(ip)
	if old == nil {
		t.Fatal("initial Core peer is missing")
	}

	// Simulate runtime drift below the Controller mutation boundary. The
	// Controller still believes the desired peer exists, while Core no longer
	// publishes it and Noise still points at the revoked Core identity.
	if err := core.RevokePeer(ip, old); err != nil {
		t.Fatalf("direct Core revoke: %v", err)
	}

	if err := controller.SyncPeers([]Peer{desired}); err != nil {
		t.Fatalf("SyncPeers repair: %v", err)
	}

	repaired := core.PeerForIP(ip)
	if repaired == nil || repaired == old {
		t.Fatalf("repaired Core peer=%p, old=%p", repaired, old)
	}
	if repaired.IsRevoked() {
		t.Fatal("repaired Core peer is revoked")
	}

	// ReplaceAuthorizedPeer requires the currently authorized binding to point
	// at expected. Success here proves bulk sync repaired Noise as well as Core.
	if err := noise.ReplaceAuthorizedPeer(key, repaired, ip, repaired); err != nil {
		t.Fatalf("Noise binding was not repaired: %v", err)
	}
}

func TestControllerSyncPeersRepairsMissingNoiseAuthorizationWithoutReplacingCore(t *testing.T) {
	controller, core, noise, rx, tx := newTestControllerWithNoise(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	key := testPublicKey(t, 41)
	ip := netip.MustParseAddr("10.88.0.41")
	desired := Peer{TunnelIPv4: ip, PublicKey: key}
	if err := controller.SetPeer(desired); err != nil {
		t.Fatal(err)
	}
	corePeer := core.PeerForIP(ip)
	if corePeer == nil {
		t.Fatal("initial Core peer is missing")
	}

	// Simulate authorization drift while leaving the Core identity intact.
	noise.RemoveAuthorizedPeer(key)
	if got := core.PeerForIP(ip); got != corePeer {
		t.Fatalf("Core changed during drift setup: %p, want %p", got, corePeer)
	}

	if err := controller.SyncPeers([]Peer{desired}); err != nil {
		t.Fatalf("SyncPeers repair: %v", err)
	}
	if got := core.PeerForIP(ip); got != corePeer {
		t.Fatalf("Noise-only repair replaced Core peer: %p, want %p", got, corePeer)
	}
	if corePeer.IsRevoked() {
		t.Fatal("Noise-only repair revoked the unchanged Core peer")
	}

	if err := noise.ReplaceAuthorizedPeer(key, corePeer, ip, corePeer); err != nil {
		t.Fatalf("Noise authorization was not restored: %v", err)
	}
}
