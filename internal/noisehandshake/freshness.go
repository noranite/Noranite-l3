package noisehandshake

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const freshnessSize = 8

type Freshness uint64

func ParseFreshness(raw []byte) (Freshness, error) {
	if len(raw) != freshnessSize {
		return 0, fmt.Errorf("freshness length %d, want %d: %w", len(raw), freshnessSize, ErrInvalidFreshness)
	}
	freshness := Freshness(binary.LittleEndian.Uint64(raw))
	if freshness == 0 {
		return 0, ErrInvalidFreshness
	}
	return freshness, nil
}

func encodeFreshness(freshness Freshness) []byte {
	raw := make([]byte, freshnessSize)
	binary.LittleEndian.PutUint64(raw, uint64(freshness))
	return raw
}

type FreshnessGenerator struct {
	mu   sync.Mutex
	last Freshness
}

func (g *FreshnessGenerator) Next(now time.Time) Freshness {
	candidate := Freshness(uint64(now.UnixNano()))
	g.mu.Lock()
	defer g.mu.Unlock()

	if candidate <= g.last {
		candidate = g.last + 1
	}
	g.last = candidate
	return candidate
}
