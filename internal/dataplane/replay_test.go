package dataplane

import "testing"

func TestReplayWindowBasicBehavior(t *testing.T) {
	var replay ReplayWindow

	accepted, advanced := replay.Accept(100)
	if !accepted || !advanced {
		t.Fatalf("first packet: accepted=%v advanced=%v", accepted, advanced)
	}

	accepted, advanced = replay.Accept(100)
	if accepted || advanced {
		t.Fatalf("duplicate: accepted=%v advanced=%v", accepted, advanced)
	}

	accepted, advanced = replay.Accept(102)
	if !accepted || !advanced {
		t.Fatalf("new highest: accepted=%v advanced=%v", accepted, advanced)
	}

	accepted, advanced = replay.Accept(101)
	if !accepted || advanced {
		t.Fatalf("out of order: accepted=%v advanced=%v", accepted, advanced)
	}

	accepted, advanced = replay.Accept(101)
	if accepted || advanced {
		t.Fatalf("out-of-order duplicate: accepted=%v advanced=%v", accepted, advanced)
	}
}

func TestReplayWindowRejectsTooOld(t *testing.T) {
	var replay ReplayWindow

	if accepted, _ := replay.Accept(0); !accepted {
		t.Fatal("sequence 0 must be accepted")
	}

	if accepted, _ := replay.Accept(ReplayWindowSize); !accepted {
		t.Fatal("new highest must be accepted")
	}

	if accepted, _ := replay.Accept(0); accepted {
		t.Fatal("sequence exactly one full window behind highest must be rejected")
	}
}

func TestReplayWindowLargeJumpIsConstantTimeSemantically(t *testing.T) {
	var replay ReplayWindow

	if accepted, _ := replay.Accept(7); !accepted {
		t.Fatal("first packet rejected")
	}

	const huge = uint64(1 << 60)
	if accepted, advanced := replay.Accept(huge); !accepted || !advanced {
		t.Fatalf("huge jump: accepted=%v advanced=%v", accepted, advanced)
	}

	if accepted, _ := replay.Accept(7); accepted {
		t.Fatal("very old sequence must be rejected after huge jump")
	}
}

func TestReplayWindowRingSlotReuse(t *testing.T) {
	var replay ReplayWindow

	// Sequence 100 occupies a physical bitmap slot.
	if accepted, advanced := replay.Accept(100); !accepted || !advanced {
		t.Fatalf("sequence 100: accepted=%v advanced=%v", accepted, advanced)
	}

	// Advance almost a full window; sequence 100 remains inside it:
	//
	//	4195 - 100 = 4095
	if accepted, advanced := replay.Accept(4195); !accepted || !advanced {
		t.Fatalf("sequence 4195: accepted=%v advanced=%v", accepted, advanced)
	}

	// It must remain a duplicate.
	if accepted, _ := replay.Accept(100); accepted {
		t.Fatal("sequence 100 unexpectedly accepted while still inside window")
	}

	// Advance once more:
	//
	//	4196 - 100 = 4096
	//
	// Sequence 100 leaves the window and sequence 4196 reuses its slot.
	if accepted, advanced := replay.Accept(4196); !accepted || !advanced {
		t.Fatalf("sequence 4196: accepted=%v advanced=%v", accepted, advanced)
	}

	if accepted, _ := replay.Accept(100); accepted {
		t.Fatal("sequence 100 accepted after leaving replay window")
	}
}
