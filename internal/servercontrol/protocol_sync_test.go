package servercontrol

import (
	"path/filepath"
	"testing"
)

func TestUnixControlPeerSyncReplacesExactRuntimeSnapshot(t *testing.T) {
	controller, _, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	path := filepath.Join(t.TempDir(), "control.sock")
	control, err := ListenUnix(path, controller)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()

	keyA := testPublicKey(t, 30)
	keyB := testPublicKey(t, 31)
	first := []WirePeer{
		{IP: "10.88.0.2", PublicKey: EncodePublicKey(keyA)},
		{IP: "10.88.0.3", PublicKey: EncodePublicKey(keyB)},
	}
	response, err := Do(path, Request{
		Operation: OperationPeerSync,
		Peers:     &first,
	})
	if err != nil || !response.OK {
		t.Fatalf("peer.sync: response=%#v err=%v", response, err)
	}

	replacement := []WirePeer{
		{IP: "10.88.0.3", PublicKey: EncodePublicKey(keyA)},
	}
	response, err = Do(path, Request{
		Operation: OperationPeerSync,
		Peers:     &replacement,
	})
	if err != nil || !response.OK {
		t.Fatalf("peer.sync replacement: response=%#v err=%v", response, err)
	}

	response, err = Do(path, Request{Operation: OperationPeerList})
	if err != nil || !response.OK {
		t.Fatalf("peer.list: response=%#v err=%v", response, err)
	}
	if len(response.Peers) != 1 ||
		response.Peers[0].IP != "10.88.0.3" ||
		response.Peers[0].PublicKey != EncodePublicKey(keyA) {
		t.Fatalf("runtime snapshot=%#v", response.Peers)
	}

	response, err = Do(path, Request{Operation: OperationPeerSync})
	if err != nil || response.OK {
		t.Fatalf("missing peer.sync snapshot: response=%#v err=%v", response, err)
	}

	empty := []WirePeer{}
	response, err = Do(path, Request{Operation: OperationPeerSync, Peers: &empty})
	if err != nil || !response.OK {
		t.Fatalf("empty peer.sync: response=%#v err=%v", response, err)
	}
	response, err = Do(path, Request{Operation: OperationPeerList})
	if err != nil || !response.OK || len(response.Peers) != 0 {
		t.Fatalf("runtime not empty after empty sync: response=%#v err=%v", response, err)
	}
}

func TestPeerSyncUsesExtendedResponseTimeout(t *testing.T) {
	if got := responseTimeout(OperationPeerSync); got != peerSyncTimeout {
		t.Fatalf("peer.sync response timeout=%v, want %v", got, peerSyncTimeout)
	}
	if peerSyncTimeout <= requestIOTimeout {
		t.Fatalf("peer.sync timeout=%v must exceed normal I/O timeout=%v", peerSyncTimeout, requestIOTimeout)
	}
	if got := responseTimeout(OperationPeerList); got != requestIOTimeout {
		t.Fatalf("peer.list response timeout=%v, want %v", got, requestIOTimeout)
	}
}
