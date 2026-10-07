package dataplane

const (
	// One uint64 stores the state of 64 sequence numbers.
	replayBitmapWordBits = 64

	// ReplayWindowSize is 4096, so the bitmap occupies:
	//
	//	4096 / 64 = 64 uint64 = 512 bytes.
	//
	// ReplayWindowSize must remain divisible by 64.
	replayBitmapWords = ReplayWindowSize / replayBitmapWordBits
)

// ReplayWindow stores receive-side replay state for one session in a circular
// bitmap. A sequence maps to:
//
//	slot = sequence % ReplayWindowSize
//
// Slots entering the window are cleared as the highest sequence advances so
// bits from an earlier rotation cannot be mistaken for current sequences.
// ReplayWindow is not safe for concurrent use; callers must serialize access.
type ReplayWindow struct {
	// initialized distinguishes an empty window from one whose highest is zero.
	initialized bool

	// highest is the greatest authenticated sequence accepted so far.
	highest uint64

	// bitmap contains one bit per sequence in the circular window.
	bitmap [replayBitmapWords]uint64
}

// Accept validates and records an authenticated sequence. advanced reports
// whether it moved the receive frontier; only such packets may update a
// session's roaming endpoint. The caller must provide exclusive access.
func (r *ReplayWindow) Accept(sequence uint64) (accepted, advanced bool) {
	// The first authenticated packet always initializes the window.
	if !r.initialized {
		r.initialized = true
		r.highest = sequence
		r.mark(sequence)
		return true, true
	}

	// The sequence advances the receive window.
	if sequence > r.highest {
		previousHighest := r.highest
		advance := sequence - previousHighest

		if advance >= ReplayWindowSize {
			// The new window does not overlap the old one.
			clear(r.bitmap[:])
		} else {
			// Clear only slots that entered the partially overlapping window.
			for offset := uint64(1); offset <= advance; offset++ {
				r.clear(previousHighest + offset)
			}
		}

		r.highest = sequence
		r.mark(sequence)
		return true, true
	}

	// A sequence ReplayWindowSize positions behind highest is outside the window.
	if r.highest-sequence >= ReplayWindowSize {
		return false, false
	}

	// A marked sequence inside the window is a duplicate.
	if r.marked(sequence) {
		return false, false
	}

	// Accept a previously unseen out-of-order packet.
	r.mark(sequence)
	return true, false
}

// mark sets the bit for sequence.
func (r *ReplayWindow) mark(sequence uint64) {
	word, mask := replayBitmapPosition(sequence)
	r.bitmap[word] |= mask
}

// clear resets a circular slot before it represents a new sequence.
func (r *ReplayWindow) clear(sequence uint64) {
	word, mask := replayBitmapPosition(sequence)
	r.bitmap[word] &^= mask
}

// marked reports whether sequence has been seen.
func (r *ReplayWindow) marked(sequence uint64) bool {
	word, mask := replayBitmapPosition(sequence)
	return r.bitmap[word]&mask != 0
}

// replayBitmapPosition maps a sequence to its bitmap word and mask. The
// compiler reduces the constant power-of-two modulo to a mask.
func replayBitmapPosition(sequence uint64) (word int, mask uint64) {
	slot := sequence % ReplayWindowSize

	word = int(slot / replayBitmapWordBits)
	bit := slot % replayBitmapWordBits

	mask = uint64(1) << bit
	return word, mask
}

// Highest returns the greatest accepted sequence and whether the window has
// accepted any packet.
func (r *ReplayWindow) Highest() (sequence uint64, ok bool) {
	return r.highest, r.initialized
}
