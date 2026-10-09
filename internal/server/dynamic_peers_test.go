package server

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestDynamicPeerCannotResurrectAfterReuse(t *testing.T) {
	c, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          LifecycleConfig{GenerationLifetime: time.Hour, ReceiveGrace: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("10.88.0.2")
	old, err := c.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PublishPeer(ip, old); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokePeer(ip, old); err != nil {
		t.Fatal(err)
	}
	fresh, err := c.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PublishPeer(ip, fresh); err != nil {
		t.Fatal(err)
	}
	if c.PeerForIP(ip) != fresh {
		t.Fatal("new peer not published")
	}
	// A handshake that authenticated the old peer must not install on fresh.
	if err := c.InstallPendingSessionForPeer(ip, old, new(dataplane.Session)); !errors.Is(err, ErrPeerRevoked) {
		t.Fatalf("stale handshake: %v", err)
	}
	if !old.IsRevoked() || fresh.IsRevoked() {
		t.Fatal("revocation applied to wrong peer")
	}
}

func TestInstallPendingSessionUnknownPeerKeepsCompatibilityError(t *testing.T) {
	c, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          LifecycleConfig{GenerationLifetime: time.Hour, ReceiveGrace: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = c.InstallPendingSession(netip.MustParseAddr("10.88.0.2"), new(dataplane.Session))
	if !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("InstallPendingSession error=%v, want ErrUnknownPeer", err)
	}
}

func TestInstallPendingSessionNilSessionKeepsCompatibilityError(t *testing.T) {
	c, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          LifecycleConfig{GenerationLifetime: time.Hour, ReceiveGrace: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = c.InstallPendingSession(netip.MustParseAddr("10.88.0.2"), nil)
	if !errors.Is(err, dataplane.ErrInvalidConfig) {
		t.Fatalf("InstallPendingSession error=%v, want ErrInvalidConfig", err)
	}
}

func TestDynamicPeerQueuesAreActivatedLazily(t *testing.T) {
	c, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          LifecycleConfig{GenerationLifetime: time.Hour, ReceiveGrace: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := c.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}

	rx, err := NewRXEngine(c, RXEngineConfig{PeerQueueSize: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	if err := rx.AddPeer(peer); err != nil {
		t.Fatal(err)
	}
	if queue := rx.peerQueues[peer]; queue != nil {
		t.Fatal("dynamic RX peer allocated an ordered queue before first submission")
	}
	rx.submitMu.Lock()
	rxQueue := rx.ensurePeerQueueLocked(peer)
	rx.submitMu.Unlock()
	if got := cap(rxQueue); got != 3 {
		t.Fatalf("dynamic RX peer queue capacity=%d, want 3", got)
	}

	tx, err := NewTXEngine(c, TXEngineConfig{PeerQueueSize: 5}, func([]TXPacket) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.AddPeer(peer); err != nil {
		t.Fatal(err)
	}
	if queue := tx.peerQueues[peer]; queue != nil {
		t.Fatal("dynamic TX peer allocated an ordered queue before first submission")
	}
	tx.submitMu.Lock()
	txQueue := tx.ensurePeerQueueLocked(peer)
	tx.submitMu.Unlock()
	if got := cap(txQueue); got != 5 {
		t.Fatalf("dynamic TX peer queue capacity=%d, want 5", got)
	}
}

func TestDynamicPeerNormalizesIPv4MappedAddress(t *testing.T) {
	c, err := New(Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle:          LifecycleConfig{GenerationLifetime: time.Hour, ReceiveGrace: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("10.88.0.2")
	mapped := netip.MustParseAddr("::ffff:10.88.0.2")
	peer, err := c.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PublishPeer(ip, peer); err != nil {
		t.Fatal(err)
	}
	if got := c.PeerForIP(mapped); got != peer {
		t.Fatalf("PeerForIP(mapped)=%p, want %p", got, peer)
	}

	session, err := dataplane.NewSession(1, [32]byte{}, [32]byte{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.InstallPendingSessionForPeer(mapped, peer, session); err != nil {
		t.Fatalf("InstallPendingSessionForPeer(mapped): %v", err)
	}
	binding, ok := c.sessionsByID[session.ID()]
	if !ok {
		t.Fatal("pending session was not indexed")
	}
	if binding.tunnelIPv4 != ip {
		t.Fatalf("session binding tunnel IPv4=%s, want %s", binding.tunnelIPv4, ip)
	}

	if err := c.RevokePeer(mapped, peer); err != nil {
		t.Fatalf("RevokePeer(mapped): %v", err)
	}
	if c.HasPeer(ip) {
		t.Fatal("peer remains published after mapped-address revoke")
	}
}
