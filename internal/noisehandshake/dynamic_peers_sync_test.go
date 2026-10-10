package noisehandshake

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

func TestReplaceAuthorizedPeersPreservesFreshnessAndExactBinding(t *testing.T) {
	serverPrivate := testPrivateKey(33)
	clientPrivate := testPrivateKey(1)
	clientPublic, _ := PublicKeyFromPrivate(clientPrivate)
	oldIP := netip.MustParseAddr("10.66.0.2")
	newIP := netip.MustParseAddr("10.66.0.3")
	core := newNoiseTestCore(t, [32]byte{}, oldIP)
	provider, err := NewServer(ServerConfig{
		Core:             core,
		StaticPrivateKey: serverPrivate,
		Peers:            []AuthorizedPeer{{TunnelIPv4: oldIP, PublicKey: clientPublic}},
	})
	if err != nil {
		t.Fatal(err)
	}

	state := provider.peers[clientPublic]
	state.hasLatest = true
	state.latestFreshness = Freshness(100)
	oldBinding := state.binding.Load()

	provider.ReplaceAuthorizedPeers(map[PublicKey]AuthorizedPeerBinding{
		clientPublic: {TunnelIPv4: oldIP, CorePeer: oldBinding.corePeer},
	})
	if got := state.binding.Load(); got != oldBinding {
		t.Fatal("exact sync replaced an unchanged binding pointer")
	}

	replacement, err := core.PreparePeer()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ReplacePeers(map[netip.Addr]*coreserver.Peer{newIP: replacement}); err != nil {
		t.Fatal(err)
	}
	provider.ReplaceAuthorizedPeers(map[PublicKey]AuthorizedPeerBinding{
		clientPublic: {TunnelIPv4: newIP, CorePeer: replacement},
	})

	if provider.peers[clientPublic] != state {
		t.Fatal("sync replaced stable public-key state")
	}
	if state.latestFreshness != Freshness(100) {
		t.Fatalf("freshness=%d, want 100", state.latestFreshness)
	}
	newBinding := state.binding.Load()
	if newBinding == oldBinding || newBinding.tunnelIPv4 != newIP || newBinding.corePeer != replacement {
		t.Fatalf("unexpected replacement binding: %#v", newBinding)
	}

	session, err := dataplane.NewSession(99, [32]byte{1}, [32]byte{2}, 0)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := provider.commitFreshPending(state, oldBinding, Freshness(101), session)
	if !errors.Is(err, coreserver.ErrPeerRevoked) || installed {
		t.Fatalf("old bulk-sync binding commit installed=%v err=%v", installed, err)
	}

	provider.ReplaceAuthorizedPeers(nil)
	if _, exists := provider.peers[clientPublic]; exists {
		t.Fatal("removed peer remains in authorization snapshot")
	}
	if binding := state.binding.Load(); binding != nil {
		t.Fatalf("removed state binding=%#v, want nil", binding)
	}
}
