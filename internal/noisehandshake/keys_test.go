package noisehandshake

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestPublicKeyFromPrivate(t *testing.T) {
	privateKey := testPrivateKey(1)
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if publicKey == (PublicKey{}) {
		t.Fatal("derived public key is zero")
	}
}

func TestParsePublicKey(t *testing.T) {
	privateKey := testPrivateKey(1)
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	encoded := base64.StdEncoding.EncodeToString(publicKey[:])
	parsed, err := ParsePublicKey(encoded)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed != publicKey {
		t.Fatal("public key round-trip mismatch")
	}
}

func TestParsePublicKeyRejectsMalformedInput(t *testing.T) {
	if _, err := ParsePublicKey("AA=="); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ParsePublicKey short error = %v, want ErrInvalidKey", err)
	}
}

func testPrivateKey(start byte) PrivateKey {
	var key PrivateKey
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}
