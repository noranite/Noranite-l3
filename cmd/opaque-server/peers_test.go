package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPeerSpecs(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	for i := range keyA {
		keyA[i] = byte(i + 1)
		keyB[i] = byte(0x80 + i)
	}
	path := filepath.Join(t.TempDir(), "peers.txt")
	contents := "# test peers\n" +
		"10.66.0.2 " + base64.StdEncoding.EncodeToString(keyA) + " alice-laptop\n" +
		"10.66.0.3 " + base64.StdEncoding.EncodeToString(keyB) + " # peer b\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	specs, err := loadPeerSpecs(path)
	if err != nil {
		t.Fatalf("loadPeerSpecs: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("peer count=%d, want 2", len(specs))
	}
	if got := specs[0].TunnelIPv4.String(); got != "10.66.0.2" {
		t.Fatalf("first tunnel IPv4=%s", got)
	}
	if specs[0].Name != "alice-laptop" {
		t.Fatalf("first peer name=%q", specs[0].Name)
	}
	if got := specs[1].TunnelIPv4.String(); got != "10.66.0.3" {
		t.Fatalf("second tunnel IPv4=%s", got)
	}
}

func TestLoadPeerSpecsRejectsDuplicates(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	keyA[0] = 1
	keyB[0] = 2
	encode := base64.StdEncoding.EncodeToString

	tests := []struct {
		name     string
		contents string
	}{
		{
			name: "duplicate tunnel",
			contents: "10.66.0.2 " + encode(keyA) + "\n" +
				"10.66.0.2 " + encode(keyB) + "\n",
		},
		{
			name: "duplicate key",
			contents: "10.66.0.2 " + encode(keyA) + "\n" +
				"10.66.0.3 " + encode(keyA) + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peers.txt")
			if err := os.WriteFile(path, []byte(tt.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadPeerSpecs(path); err == nil {
				t.Fatal("loadPeerSpecs unexpectedly succeeded")
			}
		})
	}
}

func TestLoadPeerSpecsRejectsInvalidTunnelAddress(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	path := filepath.Join(t.TempDir(), "peers.txt")
	contents := "127.0.0.2 " + base64.StdEncoding.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPeerSpecs(path); err == nil {
		t.Fatal("loadPeerSpecs unexpectedly accepted loopback tunnel address")
	}
}

func TestLoadPeerSpecsEmptyPathMeansNoBootstrapPeers(t *testing.T) {
	specs, err := loadPeerSpecs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 0 {
		t.Fatalf("peer count=%d, want 0", len(specs))
	}
}
