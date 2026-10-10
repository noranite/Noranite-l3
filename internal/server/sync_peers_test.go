package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestReplacePeersPreservesKeptPeerAndRevokesRetired(t *testing.T) {
	core, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: time.Hour,
			ReceiveGrace:       time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	keepIP := netip.MustParseAddr("10.88.0.2")
	replaceIP := netip.MustParseAddr("10.88.0.3")
	keep, err := core.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	old, err := core.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.PublishPeer(keepIP, keep); err != nil {
		t.Fatal(err)
	}
	if err := core.PublishPeer(replaceIP, old); err != nil {
		t.Fatal(err)
	}

	keepSession, err := dataplane.NewSession(11, [32]byte{1}, [32]byte{2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldSession, err := dataplane.NewSession(12, [32]byte{3}, [32]byte{4}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.InstallPendingSessionForPeer(keepIP, keep, keepSession); err != nil {
		t.Fatal(err)
	}
	if err := core.InstallPendingSessionForPeer(replaceIP, old, oldSession); err != nil {
		t.Fatal(err)
	}

	replacement, err := core.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ReplacePeers(map[netip.Addr]*Peer{
		keepIP:    keep,
		replaceIP: replacement,
	}); err != nil {
		t.Fatal(err)
	}

	if got := core.PeerForIP(keepIP); got != keep {
		t.Fatalf("kept peer=%p, want %p", got, keep)
	}
	if got := core.PeerForIP(replaceIP); got != replacement {
		t.Fatalf("replacement peer=%p, want %p", got, replacement)
	}
	if keep.IsRevoked() {
		t.Fatal("kept peer was revoked")
	}
	if !old.IsRevoked() {
		t.Fatal("retired peer was not revoked")
	}
	if replacement.IsRevoked() {
		t.Fatal("replacement peer was revoked")
	}
	if binding, ok := core.sessionsByID[keepSession.ID()]; !ok || binding.peer != keep || binding.session != keepSession {
		t.Fatalf("kept session binding=%#v ok=%v", binding, ok)
	}
	if _, ok := core.sessionsByID[oldSession.ID()]; ok {
		t.Fatal("retired peer session remains indexed")
	}
}

func TestReplacePeersRejectsMovingExistingPeerPointer(t *testing.T) {
	core, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: LifecycleConfig{
			GenerationLifetime: time.Hour,
			ReceiveGrace:       time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	oldIP := netip.MustParseAddr("10.88.0.2")
	newIP := netip.MustParseAddr("10.88.0.3")
	peer, err := core.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.PublishPeer(oldIP, peer); err != nil {
		t.Fatal(err)
	}

	err = core.ReplacePeers(map[netip.Addr]*Peer{newIP: peer})
	if !errors.Is(err, dataplane.ErrInvalidConfig) {
		t.Fatalf("ReplacePeers error=%v, want ErrInvalidConfig", err)
	}
	if got := core.PeerForIP(oldIP); got != peer {
		t.Fatalf("old snapshot changed after rejected replace: %p", got)
	}
	if peer.IsRevoked() {
		t.Fatal("peer was revoked by rejected replace")
	}
}
