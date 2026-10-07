package dataplane

import (
	"bytes"
	"errors"
	"testing"
)

func TestControlKeepaliveRoundTrip(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const (
		sessionID   = uint64(0x1122334455667788)
		keepaliveID = uint64(0x8877665544332211)
		padding     = 7
	)

	sender, err := NewSession(sessionID, c2s, s2c, 3)
	if err != nil {
		t.Fatalf("NewSession(sender): %v", err)
	}
	receiver, err := NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(receiver): %v", err)
	}

	tx := newTestDataScratch(t, routeKey)
	rx := newTestDataScratch(t, routeKey)

	dst := make([]byte, 0, MaxGeneratedControlWirePacketSize)
	wire, sequence, err := sender.SealKeepaliveToWithPadding(
		tx,
		dst,
		keepaliveID,
		padding,
	)
	if err != nil {
		t.Fatalf("SealKeepaliveToWithPadding: %v", err)
	}

	if got, want := len(wire), MinControlWirePacketSize+padding; got != want {
		t.Fatalf("wire len=%d, want %d", got, want)
	}

	route, err := DecodeRoute(rx, wire)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if route.SessionID != sessionID || route.Sequence != sequence {
		t.Fatalf("route=(%#x,%d), want (%#x,%d)", route.SessionID, route.Sequence, sessionID, sequence)
	}

	plaintext, err := receiver.AuthenticateInPlace(rx, wire, sequence)
	if err != nil {
		t.Fatalf("AuthenticateInPlace: %v", err)
	}

	control, err := ParseControl(plaintext)
	if err != nil {
		t.Fatalf("ParseControl: %v", err)
	}
	if control.Type != ControlKeepalive {
		t.Fatalf("type=%d, want KEEPALIVE", control.Type)
	}
	if control.KeepaliveID != keepaliveID {
		t.Fatalf("keepalive_id=%#x, want %#x", control.KeepaliveID, keepaliveID)
	}
	if control.PaddingLength != padding {
		t.Fatalf("padding=%d, want %d", control.PaddingLength, padding)
	}

	// Reference sender zero-fills CONTROL padding. Receiver semantics do not
	// depend on these bytes, but deterministic construction is useful for tests.
	if !bytes.Equal(plaintext[ControlHeaderSize:], make([]byte, padding)) {
		t.Fatal("CONTROL padding is not zero-filled")
	}
}

func TestParseControlRejectsMalformedAndUnknownSubtype(t *testing.T) {
	for _, plaintext := range [][]byte{
		{},
		{0x00},
		make([]byte, ControlHeaderSize-1),
		{0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x00, 0xff, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		if _, err := ParseControl(plaintext); !errors.Is(err, ErrInvalidControl) {
			t.Fatalf("ParseControl(%x) error=%v, want ErrInvalidControl", plaintext, err)
		}
	}
}

func TestGeneratedControlWireRangeAndACKAntiAmplification(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	sender, err := NewSession(0x99, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	scratch := newTestDataScratch(t, routeKey)

	for i := 0; i < 256; i++ {
		keepalive, _, err := sender.SealKeepaliveTo(
			scratch,
			make([]byte, 0, MaxGeneratedControlWirePacketSize),
			uint64(i+1),
		)
		if err != nil {
			t.Fatalf("SealKeepaliveTo: %v", err)
		}
		if len(keepalive) < MinGeneratedControlWirePacketSize || len(keepalive) > MaxGeneratedControlWirePacketSize {
			t.Fatalf("KEEPALIVE len=%d, want [%d, %d]", len(keepalive), MinGeneratedControlWirePacketSize, MaxGeneratedControlWirePacketSize)
		}

		ack, _, err := sender.SealACKTo(
			scratch,
			make([]byte, 0, len(keepalive)),
			uint64(i+1),
			len(keepalive),
		)
		if err != nil {
			t.Fatalf("SealACKTo: %v", err)
		}
		if len(ack) < MinGeneratedControlWirePacketSize || len(ack) > len(keepalive) {
			t.Fatalf("ACK len=%d, want [%d, %d]", len(ack), MinGeneratedControlWirePacketSize, len(keepalive))
		}
	}
}

func TestSealControlRangeReservedStaysWithinWireBounds(t *testing.T) {
	_, c2s, s2c := testKeys()
	sender, err := NewSession(0x99, c2s, s2c, 0)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	scratch := newTestDataScratch(t, [32]byte{})

	for i := 0; i < 64; i++ {
		sequence, err := sender.ReserveTXSequence()
		if err != nil {
			t.Fatalf("ReserveTXSequence(KEEPALIVE): %v", err)
		}
		wire, err := sender.SealKeepaliveToRangeReserved(
			scratch,
			make([]byte, 0, MaxGeneratedEstablishmentWirePacketSize),
			0,
			MinGeneratedEstablishmentWirePacketSize,
			MaxGeneratedEstablishmentWirePacketSize,
			sequence,
		)
		if err != nil {
			t.Fatalf("SealKeepaliveToRangeReserved: %v", err)
		}
		if len(wire) < MinGeneratedEstablishmentWirePacketSize || len(wire) > MaxGeneratedEstablishmentWirePacketSize {
			t.Fatalf("KEEPALIVE len=%d, want [%d, %d]", len(wire), MinGeneratedEstablishmentWirePacketSize, MaxGeneratedEstablishmentWirePacketSize)
		}

		const ackMaxWireSize = 700
		sequence, err = sender.ReserveTXSequence()
		if err != nil {
			t.Fatalf("ReserveTXSequence(ACK): %v", err)
		}
		wire, err = sender.SealACKToRangeReserved(
			scratch,
			make([]byte, 0, ackMaxWireSize),
			0,
			MinGeneratedEstablishmentWirePacketSize,
			ackMaxWireSize,
			sequence,
		)
		if err != nil {
			t.Fatalf("SealACKToRangeReserved: %v", err)
		}
		if len(wire) < MinGeneratedEstablishmentWirePacketSize || len(wire) > ackMaxWireSize {
			t.Fatalf("ACK len=%d, want [%d, %d]", len(wire), MinGeneratedEstablishmentWirePacketSize, ackMaxWireSize)
		}
	}
}
