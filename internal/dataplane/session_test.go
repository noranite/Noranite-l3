package dataplane

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestSealToSmallBufferDoesNotConsumeSequence(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19
	const initialSequence uint64 = 123

	session, err := NewSession(
		sessionID,
		c2s,
		s2c,
		initialSequence,
	)
	if err != nil {
		t.Fatalf(
			"NewSession: %v",
			err,
		)
	}

	scratch := newTestDataScratch(
		t,
		routeKey,
	)

	plaintext := make([]byte, 100)

	// Leave the buffer one byte short of the worst-case sealTo requirement:
	//
	//	len(plaintext)
	//	+ DataOverhead
	//	+ MaxDataPadding.
	dst := make(
		[]byte,
		0,
		len(plaintext)+MaxDataExpansion-1,
	)

	_, _, err = session.sealTo(
		scratch,
		dst,
		plaintext,
	)
	if !errors.Is(err, ErrBufferTooSmall) {
		t.Fatalf(
			"error=%v, want ErrBufferTooSmall",
			err,
		)
	}

	// Buffer validation happens before sequence allocation.
	if got := session.TxSequence(); got != initialSequence {
		t.Fatalf(
			"tx sequence=%d after short buffer, want %d",
			got,
			initialSequence,
		)
	}
}

func TestSealToWithPaddingRejectsTooLargePaddingWithoutConsumingSequence(
	t *testing.T,
) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19
	const initialSequence uint64 = 500

	session, err := NewSession(
		sessionID,
		c2s,
		s2c,
		initialSequence,
	)
	if err != nil {
		t.Fatalf(
			"NewSession: %v",
			err,
		)
	}

	scratch := newTestDataScratch(
		t,
		routeKey,
	)

	plaintext := []byte("test")

	dst := make(
		[]byte,
		0,
		len(plaintext)+MaxDataExpansion+1,
	)

	_, _, err = session.sealToWithPadding(
		scratch,
		dst,
		plaintext,
		MaxDataPadding+1,
	)
	if !errors.Is(err, ErrInvalidPadding) {
		t.Fatalf(
			"error=%v, want ErrInvalidPadding",
			err,
		)
	}

	if got := session.TxSequence(); got != initialSequence {
		t.Fatalf(
			"invalid padding consumed sequence: got=%d want=%d",
			got,
			initialSequence,
		)
	}
}

func TestSealToUsesValidRandomPaddingAndZeroFillsIt(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19

	client, err := NewSession(
		sessionID,
		c2s,
		s2c,
		10,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(client): %v",
			err,
		)
	}

	server, err := NewSession(
		sessionID,
		s2c,
		c2s,
		0,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(server): %v",
			err,
		)
	}

	txScratch := newTestDataScratch(
		t,
		routeKey,
	)

	rxScratch := newTestDataScratch(
		t,
		routeKey,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("random padding test"),
	)

	// Exercise the random-padding path several times.
	for i := 0; i < 64; i++ {
		dst := make(
			[]byte,
			0,
			len(inner)+MaxDataExpansion,
		)

		wire, sequence, err := client.sealTo(
			txScratch,
			dst,
			inner,
		)
		if err != nil {
			t.Fatalf(
				"iteration %d sealTo: %v",
				i,
				err,
			)
		}

		sessionIDFromRoute, sequenceFromRoute, err := decodePacketRoute(
			rxScratch,
			wire,
		)
		if err != nil {
			t.Fatalf(
				"iteration %d decodePacketRoute: %v",
				i,
				err,
			)
		}

		if sessionIDFromRoute != sessionID {
			t.Fatalf(
				"iteration %d session=%#x, want %#x",
				i,
				sessionIDFromRoute,
				sessionID,
			)
		}

		if sequenceFromRoute != sequence {
			t.Fatalf(
				"iteration %d route sequence=%d, seal sequence=%d",
				i,
				sequenceFromRoute,
				sequence,
			)
		}

		opened, err := server.AuthenticateInPlace(
			rxScratch,
			wire,
			sequence,
		)
		if err != nil {
			t.Fatalf(
				"iteration %d AuthenticateInPlace: %v",
				i,
				err,
			)
		}

		header, err := ParseIPv4(opened)
		if err != nil {
			t.Fatalf(
				"iteration %d ParseIPv4: %v",
				i,
				err,
			)
		}

		if header.TotalLength != len(inner) {
			t.Fatalf(
				"iteration %d TotalLength=%d, want %d",
				i,
				header.TotalLength,
				len(inner),
			)
		}

		padding := opened[header.TotalLength:]

		if len(padding) > MaxDataPadding {
			t.Fatalf(
				"iteration %d padding=%d, max=%d",
				i,
				len(padding),
				MaxDataPadding,
			)
		}

		// Reference sender policy:
		// Padding bytes are zero; only their count is random.
		if !bytes.Equal(
			padding,
			make([]byte, len(padding)),
		) {
			t.Fatalf(
				"iteration %d padding is not zero-filled: %x",
				i,
				padding,
			)
		}
	}
}

func TestCommitAuthenticatedRXRejectsInvalidSourceWithoutConsumingReplay(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19
	const sequence uint64 = 10

	client, err := NewSession(
		sessionID,
		c2s,
		s2c,
		sequence,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(client): %v",
			err,
		)
	}

	server, err := NewSession(
		sessionID,
		s2c,
		c2s,
		0,
	)
	if err != nil {
		t.Fatalf(
			"NewSession(server): %v",
			err,
		)
	}

	txScratch := newTestDataScratch(
		t,
		routeKey,
	)
	rxScratch := newTestDataScratch(
		t,
		routeKey,
	)

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		nil,
	)

	dst := make(
		[]byte,
		0,
		len(inner)+DataOverhead,
	)

	wire, gotSequence, err := client.SealDataToWithPadding(
		txScratch,
		dst,
		inner,
		0,
	)
	if err != nil {
		t.Fatalf(
			"SealDataToWithPadding: %v",
			err,
		)
	}

	if gotSequence != sequence {
		t.Fatalf(
			"sequence=%d, want %d",
			gotSequence,
			sequence,
		)
	}

	// AuthenticateInPlace intentionally consumes the ciphertext buffer even
	// though it does NOT consume replay state. Keep a second network-equivalent
	// datagram for the retry below.
	retryWire := bytes.Clone(wire)

	opened, err := server.AuthenticateInPlace(
		rxScratch,
		wire,
		sequence,
	)
	if err != nil {
		t.Fatalf(
			"AuthenticateInPlace: %v",
			err,
		)
	}

	if !bytes.Equal(opened, inner) {
		t.Fatalf(
			"opened plaintext mismatch:\n got: %x\nwant: %x",
			opened,
			inner,
		)
	}

	// Invalid caller endpoint is a commit-time caller error. It must not mark
	// the authenticated sequence as used and must not create an endpoint.
	_, err = server.CommitAuthenticatedRX(
		sequence,
		netip.AddrPort{},
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf(
			"CommitAuthenticatedRX error=%v, want ErrInvalidConfig",
			err,
		)
	}

	if endpoint, ok := server.Endpoint(); ok {
		t.Fatalf(
			"invalid source created known endpoint: %v",
			endpoint,
		)
	}

	_, err = server.CommitAuthenticatedRX(
		sequence,
		netip.MustParseAddrPort("192.0.2.10:0"),
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf(
			"CommitAuthenticatedRX(zero port) error=%v, want ErrInvalidConfig",
			err,
		)
	}
	if endpoint, ok := server.Endpoint(); ok {
		t.Fatalf("zero-port source created known endpoint: %v", endpoint)
	}

	// Re-authenticate the same network datagram from its untouched copy.
	// This is allowed because the first AuthenticateInPlace did not mutate
	// replay state. If invalid CommitAuthenticatedRX had consumed sequence,
	// the following valid commit would return ErrReplay.
	opened, err = server.AuthenticateInPlace(
		rxScratch,
		retryWire,
		sequence,
	)
	if err != nil {
		t.Fatalf(
			"AuthenticateInPlace(retry): %v",
			err,
		)
	}

	wantEndpoint := netip.MustParseAddrPort(
		"192.0.2.10:50000",
	)

	_, err = server.CommitAuthenticatedRX(
		sequence,
		wantEndpoint,
	)
	if err != nil {
		t.Fatalf(
			"CommitAuthenticatedRX(valid endpoint): %v",
			err,
		)
	}

	if !bytes.Equal(opened, inner) {
		t.Fatalf(
			"retry plaintext mismatch:\n got: %x\nwant: %x",
			opened,
			inner,
		)
	}

	gotEndpoint, ok := server.Endpoint()
	if !ok {
		t.Fatal("valid authenticated source did not create known endpoint")
	}

	if gotEndpoint != wantEndpoint {
		t.Fatalf(
			"endpoint=%v, want %v",
			gotEndpoint,
			wantEndpoint,
		)
	}
}

func TestRoutePlainAADRejectsCiphertextReboundToDifferentSessionID(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const (
		sessionA uint64 = 0x1111111111111111
		sessionB uint64 = 0x2222222222222222
		sequence uint64 = 7
	)

	sender, err := NewSession(sessionA, c2s, s2c, sequence)
	if err != nil {
		t.Fatalf("NewSession(sender): %v", err)
	}
	// Deliberately reuse the same RX key under a different session ID. The
	// route_plain AAD must make the original ciphertext invalid for session B.
	receiverB, err := NewSession(sessionB, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(receiver B): %v", err)
	}

	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", nil)
	txScratch := newTestDataScratch(t, routeKey)
	wire, _, err := sender.SealDataToWithPadding(
		txScratch,
		make([]byte, 0, len(inner)+DataOverhead),
		inner,
		0,
	)
	if err != nil {
		t.Fatalf("SealDataToWithPadding: %v", err)
	}

	// Re-mask only routing metadata so lookup would select session B while the
	// ciphertext/tag remain byte-for-byte those produced for session A.
	rebound := bytes.Clone(wire)
	routeScratch := newTestDataScratch(t, routeKey)
	tag := rebound[len(rebound)-TagSize:]
	mask, err := routeScratch.routeMask(tag)
	if err != nil {
		t.Fatalf("routeMask: %v", err)
	}
	opaque := encodeRoute(sessionB, sequence, mask)
	copy(rebound[:RouteSize], opaque[:])

	decoded, err := DecodeRoute(routeScratch, rebound)
	if err != nil {
		t.Fatalf("DecodeRoute: %v", err)
	}
	if decoded.SessionID != sessionB || decoded.Sequence != sequence {
		t.Fatalf("rebound route=%+v, want session B sequence %d", decoded, sequence)
	}

	if _, err := receiverB.AuthenticateInPlace(
		newTestDataScratch(t, routeKey),
		rebound,
		sequence,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("rebound ciphertext error=%v, want ErrAuthentication", err)
	}
}

func TestSessionParallelTXReservesUniqueSequences(t *testing.T) {
	routeKey, c2s, s2c := testKeys()
	const (
		sessionID       uint64 = 0x71a24e9c5312bb19
		initialSequence uint64 = 1000
		packetCount            = 128
	)

	client, err := NewSession(sessionID, c2s, s2c, initialSequence)
	if err != nil {
		t.Fatalf("NewSession(client): %v", err)
	}
	server, err := NewSession(sessionID, s2c, c2s, 0)
	if err != nil {
		t.Fatalf("NewSession(server): %v", err)
	}

	inner := testIPv4Packet(
		t,
		"10.66.0.2",
		"10.66.0.1",
		[]byte("parallel tx"),
	)

	type result struct {
		sequence uint64
		wire     []byte
		err      error
	}
	results := make(chan result, packetCount)

	var wg sync.WaitGroup
	wg.Add(packetCount)
	for range packetCount {
		go func() {
			defer wg.Done()

			scratch, err := NewDataScratch(routeKey)
			if err != nil {
				results <- result{err: err}
				return
			}
			buf := make([]byte, 0, len(inner)+DataOverhead)
			wire, sequence, err := client.SealDataToWithPadding(
				scratch,
				buf,
				inner,
				0,
			)
			results <- result{
				sequence: sequence,
				wire:     bytes.Clone(wire),
				err:      err,
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[uint64][]byte, packetCount)
	for result := range results {
		if result.err != nil {
			t.Fatalf("parallel SealDataToWithPadding: %v", result.err)
		}
		if _, exists := seen[result.sequence]; exists {
			t.Fatalf("duplicate reserved sequence %d", result.sequence)
		}
		seen[result.sequence] = result.wire
	}

	if len(seen) != packetCount {
		t.Fatalf("unique sequences=%d, want %d", len(seen), packetCount)
	}
	for i := uint64(0); i < packetCount; i++ {
		sequence := initialSequence + i
		wire, ok := seen[sequence]
		if !ok {
			t.Fatalf("missing reserved sequence %d", sequence)
		}

		rxScratch := newTestDataScratch(t, routeKey)
		route, err := DecodeRoute(rxScratch, wire)
		if err != nil {
			t.Fatalf("DecodeRoute(%d): %v", sequence, err)
		}
		if route.SessionID != sessionID || route.Sequence != sequence {
			t.Fatalf(
				"route=(%#x,%d), want (%#x,%d)",
				route.SessionID,
				route.Sequence,
				sessionID,
				sequence,
			)
		}

		opened, err := server.AuthenticateInPlace(rxScratch, wire, sequence)
		if err != nil {
			t.Fatalf("AuthenticateInPlace(%d): %v", sequence, err)
		}
		if !bytes.Equal(opened, inner) {
			t.Fatalf("opened packet mismatch for sequence %d", sequence)
		}
	}

	if got := client.TxSequence(); got != initialSequence+packetCount {
		t.Fatalf("next tx sequence=%d, want %d", got, initialSequence+packetCount)
	}
}

func TestSessionReservedSequencesMaySealOutOfOrder(t *testing.T) {
	routeKey, c2s, s2c := testKeys()
	const sessionID uint64 = 0x71a24e9c5312bb19

	session, err := NewSession(sessionID, c2s, s2c, 40)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	first, err := session.ReserveTXSequence()
	if err != nil {
		t.Fatalf("ReserveTXSequence(first): %v", err)
	}
	second, err := session.ReserveTXSequence()
	if err != nil {
		t.Fatalf("ReserveTXSequence(second): %v", err)
	}
	if first != 40 || second != 41 {
		t.Fatalf("reserved=(%d,%d), want (40,41)", first, second)
	}

	inner := testIPv4Packet(t, "10.66.0.2", "10.66.0.1", []byte("ooo"))

	// Finish sequence 41 before sequence 40. Numeric sequence order is not a TX
	// scheduling invariant; replay already supports bounded reordering.
	scratchSecond := newTestDataScratch(t, routeKey)
	wireSecond, err := session.SealDataToReserved(
		scratchSecond,
		make([]byte, 0, len(inner)+MaxDataExpansion),
		inner,
		second,
	)
	if err != nil {
		t.Fatalf("SealDataToReserved(second): %v", err)
	}

	scratchFirst := newTestDataScratch(t, routeKey)
	wireFirst, err := session.SealDataToReserved(
		scratchFirst,
		make([]byte, 0, len(inner)+MaxDataExpansion),
		inner,
		first,
	)
	if err != nil {
		t.Fatalf("SealDataToReserved(first): %v", err)
	}

	for want, wire := range map[uint64][]byte{
		first:  wireFirst,
		second: wireSecond,
	} {
		route, err := DecodeRoute(newTestDataScratch(t, routeKey), wire)
		if err != nil {
			t.Fatalf("DecodeRoute(%d): %v", want, err)
		}
		if route.Sequence != want {
			t.Fatalf("route sequence=%d, want %d", route.Sequence, want)
		}
	}
}

func TestReserveTXSequenceExhaustionDoesNotWrap(t *testing.T) {
	_, c2s, s2c := testKeys()
	session, err := NewSession(0x1234, c2s, s2c, ^uint64(0)-1)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	sequence, err := session.ReserveTXSequence()
	if err != nil {
		t.Fatalf("ReserveTXSequence(last): %v", err)
	}
	if sequence != ^uint64(0)-1 {
		t.Fatalf("last sequence=%d, want %d", sequence, ^uint64(0)-1)
	}

	if _, err := session.ReserveTXSequence(); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("exhausted reservation error=%v, want ErrSequenceExhausted", err)
	}
	if got := session.TxSequence(); got != ^uint64(0) {
		t.Fatalf("exhausted tx sequence wrapped to %d", got)
	}
}
