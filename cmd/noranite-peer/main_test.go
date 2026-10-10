package main

import (
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/peerstore"
	"github.com/noranite/Noranite-l3/internal/servercontrol"
)

type testNetworkAddress string

func (a testNetworkAddress) Network() string { return "test" }
func (a testNetworkAddress) String() string  { return string(a) }

func TestTunnelAddressMatchesExactHostAndPrefix(t *testing.T) {
	addresses := []net.Addr{
		testNetworkAddress("10.66.0.1/16"),
		testNetworkAddress("fe80::1/64"),
	}

	if !tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/16"), addresses) {
		t.Fatal("exact tunnel address did not match")
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.2/16"), addresses) {
		t.Fatal("different host address in the same /16 unexpectedly matched")
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/24"), addresses) {
		t.Fatal("different prefix length unexpectedly matched")
	}
}

func TestTunnelAddressMatchesIgnoresMalformedAndIPv6Addresses(t *testing.T) {
	addresses := []net.Addr{
		testNetworkAddress("not-an-address"),
		testNetworkAddress("fe80::1/64"),
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/16"), addresses) {
		t.Fatal("unexpected tunnel address match")
	}
}

func TestApplyRuntimeWithResyncRecoversPointFailure(t *testing.T) {
	temp := t.TempDir()
	peersFile := filepath.Join(temp, "server.peers")
	key := noisehandshake.PublicKey{1}
	if err := peerstore.WriteAtomic(peersFile, []peerstore.Record{{
		TunnelIPv4: netip.MustParseAddr("10.66.0.2"),
		PublicKey:  key,
	}}); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(temp, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requests := make(chan servercontrol.Request, 2)
	errCh := make(chan error, 1)
	go func() {
		responses := []servercontrol.Response{
			{OK: false, Error: "synthetic point failure"},
			{OK: true},
		}
		for _, response := range responses {
			conn, err := listener.Accept()
			if err != nil {
				errCh <- err
				return
			}
			var request servercontrol.Request
			if err := json.NewDecoder(conn).Decode(&request); err != nil {
				_ = conn.Close()
				errCh <- err
				return
			}
			requests <- request
			err = json.NewEncoder(conn).Encode(response)
			_ = conn.Close()
			if err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	var stderr strings.Builder
	if err := applyRuntimeWithResync(
		socket,
		servercontrol.Request{
			Operation: servercontrol.OperationPeerSet,
			Peer: &servercontrol.WirePeer{
				IP:        "10.66.0.2",
				PublicKey: servercontrol.EncodePublicKey(key),
			},
		},
		peersFile,
		&stderr,
	); err != nil {
		t.Fatalf("applyRuntimeWithResync: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	first := <-requests
	second := <-requests
	if first.Operation != servercontrol.OperationPeerSet {
		t.Fatalf("first operation=%q, want peer.set", first.Operation)
	}
	if second.Operation != servercontrol.OperationPeerSync || second.Peers == nil || len(*second.Peers) != 1 {
		t.Fatalf("recovery request=%#v, want one-peer sync", second)
	}
	if !strings.Contains(stderr.String(), "recovered with peer sync") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRemoveWritesFileBeforeRuntimeRemove(t *testing.T) {
	temp := t.TempDir()
	peersFile := filepath.Join(temp, "server.peers")
	key := noisehandshake.PublicKey{1}
	if err := peerstore.WriteAtomic(peersFile, []peerstore.Record{{
		TunnelIPv4: netip.MustParseAddr("10.66.0.2"),
		PublicKey:  key,
	}}); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(temp, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		var request servercontrol.Request
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			errCh <- err
			return
		}
		if request.Operation != servercontrol.OperationPeerRemove {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		peers, err := peerstore.Load(peersFile)
		if err != nil {
			errCh <- err
			return
		}
		if len(peers) != 0 {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- json.NewEncoder(conn).Encode(servercontrol.Response{OK: true})
	}()

	var stdout strings.Builder
	if err := run(
		[]string{
			"remove",
			"--public-key", servercontrol.EncodePublicKey(key),
			"--peers-file", peersFile,
			"--socket", socket,
		},
		&stdout,
		io.Discard,
	); err != nil {
		t.Fatalf("run remove: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "removed_from_config=true") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	if _, err := os.Stat(peersFile); err != nil {
		t.Fatal(err)
	}
}
