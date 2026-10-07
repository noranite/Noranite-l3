package dataplane

import "encoding/binary"

// nonceFromSequence builds the IETF ChaCha20-Poly1305 nonce required by the
// wire format:
//
//	0x00000000 || LE64(sequence)
//
// The nonce is derived from the sequence recovered from the opaque route and
// is not transmitted separately.
func nonceFromSequence(sequence uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], sequence)
	return nonce
}
