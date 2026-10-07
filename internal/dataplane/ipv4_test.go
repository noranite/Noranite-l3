package dataplane

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	packet := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte{1, 2, 3, 4})

	header, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}

	if header.HeaderLength != 20 {
		t.Fatalf("HeaderLength=%d, want 20", header.HeaderLength)
	}
	if header.TotalLength != len(packet) {
		t.Fatalf("TotalLength=%d, want %d", header.TotalLength, len(packet))
	}
	if header.Source != netip.MustParseAddr("10.66.0.2") {
		t.Fatalf("Source=%v", header.Source)
	}
	if header.Destination != netip.MustParseAddr("10.66.0.1") {
		t.Fatalf("Destination=%v", header.Destination)
	}
}

func TestParseIPv4AllowsTrailingBytes(t *testing.T) {
	packet := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte{1, 2, 3},
	)

	originalLength := len(packet)

	// Simulate Opaque-L3 DATA padding.
	packet = append(packet, 0, 0, 0, 0, 0)

	header, err := ParseIPv4(packet)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}

	if header.TotalLength != originalLength {
		t.Fatalf(
			"TotalLength=%d, want %d",
			header.TotalLength,
			originalLength,
		)
	}
}

func TestParseIPv4RejectsTotalLengthLargerThanPlaintext(t *testing.T) {
	packet := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte{1, 2, 3},
	)

	// Claim one byte more than the available plaintext.
	packet[3]++

	if _, err := ParseIPv4(packet); !errors.Is(err, ErrInvalidIPv4) {
		t.Fatalf(
			"error=%v, want ErrInvalidIPv4",
			err,
		)
	}
}
