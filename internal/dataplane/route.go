package dataplane

import (
	"encoding/binary"
	"fmt"
)

// putRoutePlain writes the canonical plaintext routing metadata used both as
// AEAD AAD and as the value hidden by the route mask.
func putRoutePlain(dst *[RouteSize]byte, sessionID, sequence uint64) {
	binary.LittleEndian.PutUint64(dst[0:8], sessionID)
	binary.LittleEndian.PutUint64(dst[8:16], sequence)
}

// encodeRoute masks routing metadata with the fixed plaintext layout:
//
//	LE64(session_id) || LE64(sequence)
func encodeRoute(sessionID, sequence uint64, mask [RouteSize]byte) [RouteSize]byte {
	var route [RouteSize]byte

	putRoutePlain(&route, sessionID, sequence)

	for i := range route {
		route[i] ^= mask[i]
	}

	return route
}

// decodeRoute reverses encodeRoute.
func decodeRoute(opaque [RouteSize]byte, mask [RouteSize]byte) (sessionID, sequence uint64) {
	var plain [RouteSize]byte

	for i := range opaque {
		plain[i] = opaque[i] ^ mask[i]
	}

	sessionID = binary.LittleEndian.Uint64(plain[0:8])
	sequence = binary.LittleEndian.Uint64(plain[8:16])
	return sessionID, sequence
}

// decodePacketRoute recovers unauthenticated routing metadata from a wire
// packet. Callers must authenticate the packet before mutating state.
func decodePacketRoute(scratch *DataScratch, packet []byte) (sessionID, sequence uint64, err error) {
	if len(packet) < MinWirePacketSize {
		return 0, 0, ErrPacketTooShort
	}

	var opaque [RouteSize]byte
	copy(opaque[:], packet[:RouteSize])

	// The common route-mask seed occupies the final 16 bytes. DATA puts its
	// Poly1305 tag there; establishment deliberately puts Noise tail bytes there.
	seed := packet[len(packet)-TagSize:]

	mask, err := scratch.routeMask(seed)
	if err != nil {
		return 0, 0, err
	}

	sessionID, sequence = decodeRoute(opaque, mask)
	return sessionID, sequence, nil
}

// WriteRoute writes opaque_route for an already-built packet.
//
// The route mask seed is always the final 16 bytes of the datagram. DATA uses
// its Poly1305 tag there. Other protocol users may use any cryptographically
// random-looking 16-byte trailer with the same routing-domain semantics.
// packet must already contain its final trailer before WriteRoute is called.
func WriteRoute(scratch *DataScratch, packet []byte, route Route) error {
	if scratch == nil {
		return fmt.Errorf("nil route scratch: %w", ErrInvalidConfig)
	}
	if len(packet) < RouteSize+TagSize {
		return ErrPacketTooShort
	}

	mask, err := scratch.routeMask(packet[len(packet)-TagSize:])
	if err != nil {
		return err
	}
	opaque := encodeRoute(route.SessionID, route.Sequence, mask)
	copy(packet[:RouteSize], opaque[:])
	return nil
}

// Route is unauthenticated routing metadata recovered from opaque_route.
// Callers MUST NOT use it to mutate authenticated state before AEAD succeeds.
type Route struct {
	SessionID uint64
	Sequence  uint64
}

// DecodeRoute recovers candidate SessionID/Sequence from one wire packet using
// the common opaque-route envelope. The result is unauthenticated.
func DecodeRoute(scratch *DataScratch, packet []byte) (Route, error) {
	sessionID, sequence, err := decodePacketRoute(scratch, packet)
	if err != nil {
		return Route{}, err
	}
	return Route{SessionID: sessionID, Sequence: sequence}, nil
}
