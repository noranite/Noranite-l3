package prototype

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// RandomPrototypeSequence returns a random initial sequence for sessions that
// reuse static traffic keys. The high bit remains clear to leave ample room
// before uint64 wraparound.
func RandomPrototypeSequence() (uint64, error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0, fmt.Errorf("generate prototype sequence: %w", err)
	}

	sequence := binary.LittleEndian.Uint64(bytes[:])
	sequence &= 0x7fff_ffff_ffff_ffff
	return sequence, nil
}
