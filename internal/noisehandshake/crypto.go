package noisehandshake

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/flynn/noise"

	"github.com/noranite/Noranite-l3/internal/establishment"
)

var noiseCipherSuite = noise.NewCipherSuite(
	noise.DH25519,
	noise.CipherChaChaPoly,
	noise.HashBLAKE2s,
)

const prologuePrefix = "opaque-l3/establishment/v1"

func noisePrologue(exchangeID uint64) ([]byte, error) {
	if exchangeID == 0 {
		return nil, fmt.Errorf("exchange id is zero: %w", ErrInvalidState)
	}
	prologue := make([]byte, len(prologuePrefix)+8)
	copy(prologue, prologuePrefix)
	binary.LittleEndian.PutUint64(prologue[len(prologuePrefix):], exchangeID)
	return prologue, nil
}

func newInitiatorHandshake(
	privateKey PrivateKey,
	serverPublicKey PublicKey,
	exchangeID uint64,
	random io.Reader,
) (*noise.HandshakeState, error) {
	staticKeypair, err := noiseStaticKey(privateKey)
	if err != nil {
		return nil, err
	}
	prologue, err := noisePrologue(exchangeID)
	if err != nil {
		return nil, err
	}

	peerStatic := make([]byte, keySize)
	copy(peerStatic, serverPublicKey[:])
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite,
		Random:        random,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: staticKeypair,
		PeerStatic:    peerStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("create Noise IK initiator: %w", err)
	}
	return state, nil
}

func newResponderHandshake(
	privateKey PrivateKey,
	exchangeID uint64,
	random io.Reader,
) (*noise.HandshakeState, error) {
	staticKeypair, err := noiseStaticKey(privateKey)
	if err != nil {
		return nil, err
	}
	prologue, err := noisePrologue(exchangeID)
	if err != nil {
		return nil, err
	}

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite,
		Random:        random,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      prologue,
		StaticKeypair: staticKeypair,
	})
	if err != nil {
		return nil, fmt.Errorf("create Noise IK responder: %w", err)
	}
	return state, nil
}

func peerStaticPublicKey(state *noise.HandshakeState) (PublicKey, error) {
	if state == nil {
		return PublicKey{}, ErrInvalidState
	}
	peerStatic := state.PeerStatic()
	if len(peerStatic) != keySize {
		return PublicKey{}, fmt.Errorf("peer static key length %d, want %d: %w", len(peerStatic), keySize, ErrInvalidState)
	}

	var publicKey PublicKey
	copy(publicKey[:], peerStatic)
	return publicKey, nil
}

func trafficMaterialFromSplit(
	sessionID uint64,
	cs1, cs2 *noise.CipherState,
) (establishment.TrafficSessionMaterial, error) {
	if sessionID == 0 || cs1 == nil || cs2 == nil {
		return establishment.TrafficSessionMaterial{}, ErrInvalidState
	}

	// Noise Split order is protocol-global: first initiator->responder, then
	// responder->initiator. Roles are fixed in Opaque-L3, so that is C2S/S2C
	// on both peers. NewClientSession/NewServerSession perform local TX/RX mapping.
	return establishment.TrafficSessionMaterial{
		SessionID: sessionID,
		C2S:       cs1.UnsafeKey(),
		S2C:       cs2.UnsafeKey(),
	}, nil
}
