package peerstore

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
)

func TestWriteAtomicRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.peers")
	keyA := noisehandshake.PublicKey{1}
	keyB := noisehandshake.PublicKey{2}
	records := []Record{
		{Name: "alice", TunnelIPv4: netip.MustParseAddr("10.66.0.2"), PublicKey: keyA},
		{TunnelIPv4: netip.MustParseAddr("10.66.0.3"), PublicKey: keyB},
	}

	if err := WriteAtomic(path, records); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("records=%d, want %d", len(got), len(records))
	}
	for i := range records {
		if got[i] != records[i] {
			t.Fatalf("record %d=%#v, want %#v", i, got[i], records[i])
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o, want 0600", got)
	}
}
