package server

import (
	"net/netip"
	"testing"
)

func TestCoreHasPeerReflectsImmutableConfiguredPeers(t *testing.T) {
	peer := testPeerTunnelIPv4()
	core, err := New(Config{
		RouteKey:           [32]byte{},
		MaxInnerPacketSize: 1380,
		Lifecycle:          testLifecycleConfig(),
		Peers:              []PeerConfig{{TunnelIPv4: peer}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !core.HasPeer(peer) {
		t.Fatalf("HasPeer(%s)=false for configured peer", peer)
	}
	unknown := netip.MustParseAddr("10.66.0.99")
	if core.HasPeer(unknown) {
		t.Fatalf("HasPeer(%s)=true for unknown peer", unknown)
	}
}
