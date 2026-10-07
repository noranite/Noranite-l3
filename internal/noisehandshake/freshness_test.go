package noisehandshake

import (
	"errors"
	"testing"
	"time"
)

func TestFreshnessRoundTrip(t *testing.T) {
	want := testFreshness(1_700_000_000, 123_456_789)
	got, err := ParseFreshness(encodeFreshness(want))
	if err != nil {
		t.Fatalf("ParseFreshness: %v", err)
	}
	if got != want {
		t.Fatalf("freshness=%d, want %d", got, want)
	}
}

func TestParseFreshnessRejectsZero(t *testing.T) {
	if _, err := ParseFreshness(make([]byte, freshnessSize)); !errors.Is(err, ErrInvalidFreshness) {
		t.Fatalf("ParseFreshness error = %v, want ErrInvalidFreshness", err)
	}
}

func TestFreshnessGeneratorMonotonicAcrossClockRollback(t *testing.T) {
	var generator FreshnessGenerator
	base := time.Unix(1_700_000_000, 500)

	first := generator.Next(base)
	second := generator.Next(base.Add(-time.Hour))
	third := generator.Next(base)

	if second != first+1 || third != second+1 {
		t.Fatalf("generator did not stay strictly monotonic: %d %d %d", first, second, third)
	}
}

func testFreshness(seconds uint64, nanoseconds uint32) Freshness {
	return Freshness(seconds*1_000_000_000 + uint64(nanoseconds))
}
