package dataplane

import (
	"fmt"
	"testing"
)

func TestRouteEncodeDecodeRoundTrip(t *testing.T) {
	routeKey, _, _ := testKeys()
	scratch := newTestDataScratch(t, routeKey)

	tag := []byte("0123456789abcdef")

	mask, err := scratch.routeMask(tag)
	if err != nil {
		t.Fatalf("routeMask: %v", err)
	}

	const sessionID uint64 = 0x1122334455667788
	const sequence uint64 = 0x8877665544332211

	opaque := encodeRoute(
		sessionID,
		sequence,
		mask,
	)

	gotSession, gotSequence := decodeRoute(
		opaque,
		mask,
	)

	if gotSession != sessionID {
		t.Fatalf(
			"session=%#x, want %#x",
			gotSession,
			sessionID,
		)
	}

	if gotSequence != sequence {
		t.Fatalf(
			"sequence=%#x, want %#x",
			gotSequence,
			sequence,
		)
	}
}

func TestRouteMaskChangesWhenTagChanges(t *testing.T) {
	routeKey, _, _ := testKeys()
	scratch := newTestDataScratch(t, routeKey)

	tagA := []byte("0123456789abcdef")
	tagB := []byte("0123456789abcdeg")

	maskA, err := scratch.routeMask(tagA)
	if err != nil {
		t.Fatalf("routeMask A: %v", err)
	}

	maskB, err := scratch.routeMask(tagB)
	if err != nil {
		t.Fatalf("routeMask B: %v", err)
	}

	if maskA == maskB {
		t.Fatal(
			"different tags unexpectedly produced identical route masks",
		)
	}
}

func TestRouteMaskKnownVector(t *testing.T) {
	routeKey, _, _ := testKeys()
	scratch := newTestDataScratch(t, routeKey)

	tag := []byte("0123456789abcdef")

	mask, err := scratch.routeMask(tag)
	if err != nil {
		t.Fatalf("routeMask: %v", err)
	}

	// This expected value was computed independently for:
	//
	//	BLAKE2s-128(
	//	    key  = 01 02 ... 20,
	//	    data = "opaque-l3/v1/route-mask"
	//	           || "0123456789abcdef",
	//	)
	//
	// A round trip alone would not detect a symmetric codec error.
	const want = "c8ce87e63422c50cb92fc3b4fa5f4c74"

	if got := fmt.Sprintf("%x", mask); got != want {
		t.Fatalf(
			"route mask=%s, want %s",
			got,
			want,
		)
	}
}

func TestRouteMaskScratchReuseDoesNotLeakPreviousInput(t *testing.T) {
	routeKey, _, _ := testKeys()
	scratch := newTestDataScratch(t, routeKey)

	tagA := []byte("0123456789abcdef")
	tagB := []byte("fedcba9876543210")

	firstA, err := scratch.routeMask(tagA)
	if err != nil {
		t.Fatalf("first routeMask(A): %v", err)
	}

	_, err = scratch.routeMask(tagB)
	if err != nil {
		t.Fatalf("routeMask(B): %v", err)
	}

	secondA, err := scratch.routeMask(tagA)
	if err != nil {
		t.Fatalf("second routeMask(A): %v", err)
	}

	// The keyed hasher processed B between these two calculations of A.
	if firstA != secondA {
		t.Fatalf(
			"route-mask scratch reuse changed result:\nfirst=%x\nsecond=%x",
			firstA,
			secondA,
		)
	}
}
