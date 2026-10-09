package servercontrol

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixControlRoundTrip(t *testing.T) {
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

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode=%#o, want 0600", got)
	}

	key := testPublicKey(t, 7)
	response, err := Do(path, Request{
		Operation: OperationPeerSet,
		Peer: &WirePeer{
			IP:        "10.88.0.2",
			PublicKey: EncodePublicKey(key),
		},
	})
	if err != nil || !response.OK {
		t.Fatalf("peer.set: response=%#v err=%v", response, err)
	}

	conflict, err := Do(path, Request{
		Operation: OperationPeerSet,
		Peer: &WirePeer{
			IP:        "10.88.0.2",
			PublicKey: EncodePublicKey(testPublicKey(t, 8)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if conflict.OK || conflict.ErrorCode != ErrorCodePeerConflict {
		t.Fatalf("peer.set conflict response=%#v, want error_code=%q", conflict, ErrorCodePeerConflict)
	}

	response, err = Do(path, Request{Operation: OperationPeerList})
	if err != nil || !response.OK {
		t.Fatalf("peer.list: response=%#v err=%v", response, err)
	}
	if len(response.Peers) != 1 || response.Peers[0].IP != "10.88.0.2" {
		t.Fatalf("unexpected peer list: %#v", response.Peers)
	}

	response, err = Do(path, Request{Operation: OperationPeerRemove, PublicKey: EncodePublicKey(key)})
	if err != nil || !response.OK {
		t.Fatalf("peer.remove: response=%#v err=%v", response, err)
	}

	control.Close()
	control.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("control socket remains after Close: %v", err)
	}
}

func TestListenUnixReplacesStaleSocket(t *testing.T) {
	controller, _, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	path := filepath.Join(t.TempDir(), "control.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket was not left behind: %v", err)
	}

	control, err := ListenUnix(path, controller)
	if err != nil {
		t.Fatalf("ListenUnix with stale socket: %v", err)
	}
	defer control.Close()

	probe, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("replacement Unix listener is not reachable: %v", err)
	}
	_ = probe.Close()
}

func TestListenUnixDoesNotReplaceLiveSocket(t *testing.T) {
	controller, _, rx, tx := newTestController(t)
	defer func() {
		controller.Close()
		rx.Close()
		tx.Close()
	}()

	path := filepath.Join(t.TempDir(), "control.sock")
	original, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()

	if control, err := ListenUnix(path, controller); err == nil {
		control.Close()
		t.Fatal("ListenUnix unexpectedly replaced a live socket")
	}
	probe, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("original Unix listener was broken: %v", err)
	}
	_ = probe.Close()
}

func TestControlRejectsInvalidTunnelAddress(t *testing.T) {
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

	response, err := Do(path, Request{
		Operation: OperationPeerSet,
		Peer: &WirePeer{
			IP:        netip.MustParseAddr("127.0.0.2").String(),
			PublicKey: EncodePublicKey(testPublicKey(t, 9)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK {
		t.Fatalf("loopback tunnel address accepted: %#v", response)
	}
}
