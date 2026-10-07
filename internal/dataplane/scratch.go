package dataplane

import (
	"encoding/binary"
	"fmt"
	"hash"
	randv2 "math/rand/v2"

	"golang.org/x/crypto/blake2s"
)

// routeMaskDomainBytes avoids converting the domain separator for every packet:
//
//	[]byte(routeMaskDomain)
var routeMaskDomainBytes = []byte(routeMaskDomain)

var establishmentEphemeralMaskDomainBytes = []byte(establishmentEphemeralMaskDomain)

// DataScratch holds reusable DATA codec state for one packet-processing
// goroutine. It is not safe for concurrent use and does not contain session
// state. Give each concurrent RX or TX worker its own instance.
type DataScratch struct {
	// routeHasher is a keyed BLAKE2s-128 hasher initialized with K_route.
	routeHasher hash.Hash

	// routeSum stores the 16-byte BLAKE2s output without an allocation.
	routeSum [RouteSize]byte

	// routeAAD — reusable plaintext routing metadata authenticated as AEAD AAD.
	// It has the exact wire-independent route_plain layout:
	//
	//	LE64(session_id) || LE64(sequence)
	routeAAD [RouteSize]byte

	// paddingRNG is worker-local mutable padding policy state. Keeping it in
	// scratch rather than Session lets multiple TX workers seal packets from the
	// same crypto generation without a Session-wide RNG mutex.
	paddingRNG *randv2.Rand

	// nonce is reusable IETF ChaCha20-Poly1305 nonce storage. Keeping it here
	// prevents the slice passed through cipher.AEAD from escaping per packet.
	nonce [NonceSize]byte
}

// NewDataScratch creates reusable DATA state for a route key. It should be
// called outside the packet hot path.
func NewDataScratch(routeKey [32]byte) (*DataScratch, error) {
	hasher, err := blake2s.New128(routeKey[:])
	if err != nil {
		return nil, fmt.Errorf(
			"create DATA route-mask hasher: %w",
			err,
		)
	}

	paddingRNG, err := newPaddingRNG()
	if err != nil {
		return nil, err
	}

	return &DataScratch{
		routeHasher: hasher,
		paddingRNG:  paddingRNG,
	}, nil
}

// routeMask computes:
//
//	BLAKE2s-128(
//	    key  = K_route,
//	    data = "opaque-l3/v1/route-mask" || seed,
//	)
//
// It reuses the keyed hasher and output buffer.
func (s *DataScratch) routeMask(
	seed []byte,
) ([RouteSize]byte, error) {
	if len(seed) != TagSize {
		return [RouteSize]byte{}, fmt.Errorf(
			"route mask: seed length %d: %w",
			len(seed),
			ErrInvalidConfig,
		)
	}

	// Reset preserves the BLAKE2s key.
	s.routeHasher.Reset()

	// The domain separator is part of the wire-level PRF definition.
	_, _ = s.routeHasher.Write(routeMaskDomainBytes)

	// A per-packet 16-byte seed completes the PRF input. DATA uses its Poly1305 tag;
	// establishment uses the final 16 bytes of its Noise message.
	_, _ = s.routeHasher.Write(seed)

	// routeSum[:0] has enough capacity for the 16-byte digest.
	sum := s.routeHasher.Sum(s.routeSum[:0])

	if len(sum) != RouteSize {
		return [RouteSize]byte{}, fmt.Errorf(
			"route mask size %d, want %d: %w",
			len(sum),
			RouteSize,
			ErrInvalidConfig,
		)
	}

	return s.routeSum, nil
}

// EstablishmentEphemeralMask derives a 32-byte mask for the cleartext Noise
// ephemeral public key from K_route and the packet's final 16-byte Noise tail.
// It intentionally reuses the keyed BLAKE2s-128 state with a separate domain
// and two counter-separated blocks.
func (s *DataScratch) EstablishmentEphemeralMask(seed []byte) ([32]byte, error) {
	var mask [32]byte
	if len(seed) != TagSize {
		return mask, fmt.Errorf(
			"establishment ephemeral mask: seed length %d: %w",
			len(seed),
			ErrInvalidConfig,
		)
	}

	var counter [1]byte
	for offset := 0; offset < len(mask); offset += RouteSize {
		s.routeHasher.Reset()
		_, _ = s.routeHasher.Write(establishmentEphemeralMaskDomainBytes)
		_, _ = s.routeHasher.Write(seed)
		counter[0] = byte(offset / RouteSize)
		_, _ = s.routeHasher.Write(counter[:])

		sum := s.routeHasher.Sum(s.routeSum[:0])
		if len(sum) != RouteSize {
			return [32]byte{}, fmt.Errorf(
				"establishment ephemeral mask block size %d, want %d: %w",
				len(sum),
				RouteSize,
				ErrInvalidConfig,
			)
		}
		copy(mask[offset:offset+RouteSize], sum)
	}

	return mask, nil
}

// nonceForSequence fills reusable nonce storage with:
//
//	0x00000000 || LE64(sequence)
//
// The returned slice remains valid until the next use of this DataScratch.
func (s *DataScratch) nonceForSequence(sequence uint64) []byte {
	// The first four bytes are always zero by protocol definition.
	clear(s.nonce[:4])

	binary.LittleEndian.PutUint64(
		s.nonce[4:],
		sequence,
	)

	return s.nonce[:]
}

// routeAADFor fills reusable AAD storage with the plaintext routing metadata
// for one packet. One scratch belongs to one packet-processing goroutine, so no
// synchronization is required.
func (s *DataScratch) routeAADFor(sessionID, sequence uint64) []byte {
	putRoutePlain(&s.routeAAD, sessionID, sequence)
	return s.routeAAD[:]
}
