package keyfile

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestReadBase64Key32(t *testing.T) {
	t.Parallel()

	var want [32]byte
	for i := range want {
		want[i] = byte(i + 1)
	}
	path := filepath.Join(t.TempDir(), "key")
	encoded := base64.StdEncoding.EncodeToString(want[:]) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := ReadBase64Key32(path)
	if err != nil {
		t.Fatalf("ReadBase64Key32: %v", err)
	}
	if got != want {
		t.Fatalf("key = %x, want %x", got, want)
	}
}

func TestReadBase64Key32RejectsWrongLength(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key")
	encoded := base64.StdEncoding.EncodeToString(make([]byte, 31))
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadBase64Key32(path); err == nil {
		t.Fatal("ReadBase64Key32 unexpectedly succeeded")
	}
}

func TestReadBase64Key32RejectsMalformedBase64(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("not base64!\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadBase64Key32(path); err == nil {
		t.Fatal("ReadBase64Key32 unexpectedly succeeded")
	}
}

func TestReadBase64Key32RejectsZeroKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key")
	encoded := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadBase64Key32(path); err == nil {
		t.Fatal("ReadBase64Key32 unexpectedly accepted an all-zero key")
	}
}
