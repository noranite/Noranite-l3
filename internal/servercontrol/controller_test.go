package servercontrol

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/server"
)

func TestControllerSetReplaceRemoveAndReuseAddress(t *testing.T) {
	controller, core, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	keyA := testPublicKey(t, 1)
	keyB := testPublicKey(t, 2)
	ipA := netip.MustParseAddr("10.88.0.2")
	ipB := netip.MustParseAddr("10.88.0.3")
	peerA := Peer{TunnelIPv4: ipA, PublicKey: keyA}

	if err := controller.SetPeer(peerA); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}
	if !core.HasPeer(ipA) {
		t.Fatal("peer was not published to Core")
	}
	if err := controller.SetPeer(peerA); err != nil {
		t.Fatalf("idempotent SetPeer: %v", err)
	}

	if err := controller.SetPeer(Peer{TunnelIPv4: ipA, PublicKey: keyB}); !errors.Is(err, ErrPeerConflict) {
		t.Fatalf("same IP with different key: %v", err)
	}

	if err := controller.SetPeer(Peer{TunnelIPv4: ipB, PublicKey: keyA}); err != nil {
		t.Fatalf("replace peer address: %v", err)
	}
	if core.HasPeer(ipA) {
		t.Fatal("old peer address remains published after replacement")
	}
	if !core.HasPeer(ipB) {
		t.Fatal("replacement peer address was not published")
	}

	peers, err := controller.ListPeers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].PublicKey != keyA || peers[0].TunnelIPv4 != ipB {
		t.Fatalf("unexpected peer snapshot: %#v", peers)
	}

	if err := controller.RemovePeer(keyA); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if core.HasPeer(ipB) {
		t.Fatal("removed peer is still published in Core")
	}
	if err := controller.RemovePeer(keyA); err != nil {
		t.Fatalf("idempotent RemovePeer: %v", err)
	}
	if err := controller.SetPeer(Peer{TunnelIPv4: ipB, PublicKey: keyB}); err != nil {
		t.Fatalf("reuse tunnel IP: %v", err)
	}
}

func TestControllerReplacementDoesNotRollBackAfterNoiseCommit(t *testing.T) {
	controller, core, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	key := testPublicKey(t, 9)
	oldIP := netip.MustParseAddr("10.88.0.20")
	newIP := netip.MustParseAddr("10.88.0.21")
	if err := controller.SetPeer(Peer{TunnelIPv4: oldIP, PublicKey: key}); err != nil {
		t.Fatalf("initial SetPeer: %v", err)
	}

	// Deliberately violate Controller's single-mutation-boundary invariant so the
	// old Core cleanup fails after Noise has already committed the replacement.
	oldCorePeer := core.PeerForIP(oldIP)
	if oldCorePeer == nil {
		t.Fatal("old Core peer is missing before test setup")
	}
	if err := core.RevokePeer(oldIP, oldCorePeer); err != nil {
		t.Fatalf("direct Core revoke: %v", err)
	}

	err := controller.SetPeer(Peer{TunnelIPv4: newIP, PublicKey: key})
	if !errors.Is(err, server.ErrPeerRevoked) {
		t.Fatalf("replacement cleanup error=%v, want ErrPeerRevoked", err)
	}
	if !core.HasPeer(newIP) {
		t.Fatal("committed replacement disappeared from Core")
	}

	peers, listErr := controller.ListPeers()
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(peers) != 1 || peers[0].PublicKey != key || peers[0].TunnelIPv4 != newIP {
		t.Fatalf("Controller rolled administrative state back after commit: %#v", peers)
	}

	// The same desired state is now idempotent even though the previous call
	// reported a post-commit cleanup error.
	if err := controller.SetPeer(Peer{TunnelIPv4: newIP, PublicKey: key}); err != nil {
		t.Fatalf("repeat committed SetPeer: %v", err)
	}
}

func TestControllerCloseRejectsMutation(t *testing.T) {
	controller, _, rx, tx := newTestController(t)
	controller.Close()
	defer rx.Close()
	defer tx.Close()

	err := controller.SetPeer(Peer{
		TunnelIPv4: netip.MustParseAddr("10.88.0.2"),
		PublicKey:  testPublicKey(t, 3),
	})
	if !errors.Is(err, ErrControllerClosed) {
		t.Fatalf("SetPeer after Close: %v", err)
	}
}

func newTestController(t *testing.T) (*Controller, *server.Core, *server.RXEngine, *server.TXEngine) {
	t.Helper()
	controller, core, _, rx, tx := newTestControllerWithNoise(t)
	return controller, core, rx, tx
}

func newTestControllerWithNoise(t *testing.T) (*Controller, *server.Core, *noisehandshake.Server, *server.RXEngine, *server.TXEngine) {
	t.Helper()
	core, err := server.New(server.Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: time.Hour,
			ReceiveGrace:       time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var private noisehandshake.PrivateKey
	for i := range private {
		private[i] = byte(33 + i)
	}
	noiseServer, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             core,
		StaticPrivateKey: private,
	})
	if err != nil {
		t.Fatal(err)
	}
	rx, err := server.NewRXEngine(core, server.RXEngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := server.NewTXEngine(core, server.TXEngineConfig{}, func([]server.TXPacket) error { return nil })
	if err != nil {
		rx.Close()
		t.Fatal(err)
	}
	controller, err := NewController(core, noiseServer, rx, tx)
	if err != nil {
		rx.Close()
		tx.Close()
		t.Fatal(err)
	}
	return controller, core, noiseServer, rx, tx
}

func testPublicKey(t *testing.T, seed byte) noisehandshake.PublicKey {
	t.Helper()
	var private noisehandshake.PrivateKey
	for i := range private {
		private[i] = seed + byte(i)
	}
	key, err := noisehandshake.PublicKeyFromPrivate(private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNewControllerRejectsNonEmptyCore(t *testing.T) {
	core, err := server.New(server.Config{
		MaxInnerPacketSize: dataplane.ReferenceTunnelMTU,
		Lifecycle: server.LifecycleConfig{
			GenerationLifetime: time.Hour,
			ReceiveGrace:       time.Second,
		},
		Peers: []server.PeerConfig{{TunnelIPv4: netip.MustParseAddr("10.88.0.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var private noisehandshake.PrivateKey
	for i := range private {
		private[i] = byte(33 + i)
	}
	noiseServer, err := noisehandshake.NewServer(noisehandshake.ServerConfig{
		Core:             core,
		StaticPrivateKey: private,
	})
	if err != nil {
		t.Fatal(err)
	}
	rx, err := server.NewRXEngine(core, server.RXEngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := server.NewTXEngine(core, server.TXEngineConfig{}, func([]server.TXPacket) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	if controller, err := NewController(core, noiseServer, rx, tx); err == nil {
		controller.Close()
		t.Fatal("NewController unexpectedly accepted a non-empty Core")
	}
}
