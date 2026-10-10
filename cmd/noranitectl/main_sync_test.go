package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/noranite/Noranite-l3/internal/servercontrol"
)

func TestPeerSyncEmptyFileSendsExplicitEmptySnapshot(t *testing.T) {
	temp := t.TempDir()
	peersFile := filepath.Join(temp, "server.peers")
	if err := os.WriteFile(peersFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(temp, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requestCh := make(chan servercontrol.Request, 1)
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
		requestCh <- request
		errCh <- json.NewEncoder(conn).Encode(servercontrol.Response{OK: true})
	}()

	if err := run(
		[]string{"-socket", socket, "peer", "sync", "--file", peersFile},
		io.Discard,
		io.Discard,
	); err != nil {
		t.Fatalf("run peer sync: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	request := <-requestCh
	if request.Operation != servercontrol.OperationPeerSync {
		t.Fatalf("operation=%q, want %q", request.Operation, servercontrol.OperationPeerSync)
	}
	if request.Peers == nil {
		t.Fatal("empty peers file was encoded as a missing snapshot")
	}
	if len(*request.Peers) != 0 {
		t.Fatalf("empty peers file encoded %d peers", len(*request.Peers))
	}
}
