package noisehandshake

import (
	"encoding/base64"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

const keySize = 32

type PrivateKey [keySize]byte
type PublicKey [keySize]byte

func PublicKeyFromPrivate(privateKey PrivateKey) (PublicKey, error) {
	public, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return PublicKey{}, fmt.Errorf("derive X25519 public key: %w", err)
	}
	if len(public) != keySize {
		return PublicKey{}, fmt.Errorf("unexpected X25519 public key size: %w", ErrInvalidState)
	}

	var publicKey PublicKey
	copy(publicKey[:], public)
	return publicKey, nil
}

func ParsePublicKey(encoded string) (PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("decode public key: %w", ErrInvalidKey)
	}
	if len(raw) != keySize {
		return PublicKey{}, fmt.Errorf("public key length %d, want %d: %w", len(raw), keySize, ErrInvalidKey)
	}

	var key PublicKey
	copy(key[:], raw)
	return key, nil
}

func noiseStaticKey(privateKey PrivateKey) (noise.DHKey, error) {
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		return noise.DHKey{}, err
	}

	private := make([]byte, keySize)
	public := make([]byte, keySize)
	copy(private, privateKey[:])
	copy(public, publicKey[:])
	return noise.DHKey{Private: private, Public: public}, nil
}
