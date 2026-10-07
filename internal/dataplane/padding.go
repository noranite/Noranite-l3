package dataplane

import (
	cryptorand "crypto/rand"
	"fmt"
	randv2 "math/rand/v2"
)

// newPaddingRNG creates one PRNG for a packet-processing worker scratch.
//
// Padding length has no protocol semantics and does not participate in key or
// nonce derivation, but keeping the existing ChaCha8-based generator preserves
// the old sender behavior without putting mutable RNG state back into Session.
//
// The generator is NOT concurrent-safe. That is intentional: DataScratch has
// single-goroutine ownership, so a crypto worker gets its own independent RNG.
func newPaddingRNG() (*randv2.Rand, error) {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf(
			"generate padding RNG seed: %w",
			err,
		)
	}

	return randv2.New(randv2.NewChaCha8(seed)), nil
}

// nextPaddingLength returns a uniform value from the inclusive 0..max range.
// Caller must own rng exclusively; DataScratch ownership provides that contract.
func nextPaddingLength(rng *randv2.Rand, max int) int {
	if max <= 0 {
		return 0
	}
	return rng.IntN(max + 1)
}

func nextDataPaddingLength(rng *randv2.Rand) int {
	return nextPaddingLength(rng, MaxDataPadding)
}
