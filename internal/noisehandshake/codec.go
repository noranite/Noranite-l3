package noisehandshake

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const (
	initNoiseMessageSize     = 104
	responseNoiseMessageSize = 56
	noiseEphemeralSize       = keySize

	InitMinPacketSize              = dataplane.RouteSize + initNoiseMessageSize
	InitMinGeneratedPacketSize     = dataplane.MinGeneratedEstablishmentWirePacketSize
	InitMaxGeneratedPacketSize     = dataplane.MaxGeneratedEstablishmentWirePacketSize
	ResponseMinPacketSize          = dataplane.RouteSize + responseNoiseMessageSize
	ResponseMinGeneratedPacketSize = dataplane.MinGeneratedEstablishmentWirePacketSize
	ResponseMaxGeneratedPacketSize = dataplane.MaxGeneratedEstablishmentWirePacketSize

	responsePayloadSize = 8
)

type wirePacket struct {
	exchangeID uint64
	message    []byte
}

func isNoiseEstablishmentDatagram(
	route dataplane.Route,
	routeDecoded bool,
	_ []byte,
) bool {
	return routeDecoded && route.SessionID == 0
}

func appendInitPacket(
	dst []byte,
	scratch *dataplane.DataScratch,
	random io.Reader,
	exchangeID uint64,
	noiseMessage []byte,
) ([]byte, error) {
	if exchangeID == 0 {
		return nil, fmt.Errorf("exchange id is zero: %w", ErrInvalidState)
	}
	if len(noiseMessage) != initNoiseMessageSize {
		return nil, fmt.Errorf("Noise INIT length %d, want %d: %w", len(noiseMessage), initNoiseMessageSize, ErrInvalidState)
	}
	if random == nil {
		return nil, fmt.Errorf("nil random source: %w", ErrInvalidState)
	}

	packetSize, err := randomPacketSize(
		random,
		InitMinGeneratedPacketSize,
		InitMaxGeneratedPacketSize,
	)
	if err != nil {
		return nil, fmt.Errorf("generate Noise INIT packet size: %w", err)
	}
	if cap(dst) < packetSize {
		return nil, fmt.Errorf("Noise INIT buffer too small: %w", ErrInvalidState)
	}

	packet := dst[:packetSize]
	padding := packet[dataplane.RouteSize : packetSize-initNoiseMessageSize]
	if len(padding) != 0 {
		if _, err := io.ReadFull(random, padding); err != nil {
			return nil, fmt.Errorf("generate Noise INIT padding: %w", err)
		}
	}
	message := packet[packetSize-initNoiseMessageSize:]
	copy(message, noiseMessage)
	if err := maskNoiseEphemeral(scratch, message); err != nil {
		return nil, fmt.Errorf("mask Noise INIT ephemeral: %w", err)
	}

	if err := dataplane.WriteRoute(scratch, packet, dataplane.Route{
		SessionID: 0,
		Sequence:  exchangeID,
	}); err != nil {
		return nil, fmt.Errorf("encode Noise INIT route: %w", err)
	}
	return packet, nil
}

func appendGeneratedResponsePacket(
	dst []byte,
	scratch *dataplane.DataScratch,
	random io.Reader,
	exchangeID uint64,
	noiseMessage []byte,
	requestPacketSize int,
) ([]byte, error) {
	maxPacketSize := requestPacketSize
	if maxPacketSize > ResponseMaxGeneratedPacketSize {
		maxPacketSize = ResponseMaxGeneratedPacketSize
	}
	if maxPacketSize < ResponseMinPacketSize {
		return nil, fmt.Errorf("Noise RESPONSE wire limit %d is too small: %w", maxPacketSize, ErrInvalidState)
	}

	// New generated INIT packets are at least the establishment shaping minimum.
	// For an older/smaller compatible INIT, keep responding without amplification
	// by falling back to the RESPONSE parser minimum as the lower bound.
	minPacketSize := ResponseMinGeneratedPacketSize
	if maxPacketSize < minPacketSize {
		minPacketSize = ResponseMinPacketSize
	}

	packetSize, err := randomPacketSize(random, minPacketSize, maxPacketSize)
	if err != nil {
		return nil, fmt.Errorf("generate Noise RESPONSE packet size: %w", err)
	}
	return appendResponsePacket(
		dst,
		scratch,
		random,
		exchangeID,
		noiseMessage,
		packetSize,
	)
}

func appendResponsePacket(
	dst []byte,
	scratch *dataplane.DataScratch,
	random io.Reader,
	exchangeID uint64,
	noiseMessage []byte,
	packetSize int,
) ([]byte, error) {
	if exchangeID == 0 {
		return nil, fmt.Errorf("exchange id is zero: %w", ErrInvalidState)
	}
	if len(noiseMessage) != responseNoiseMessageSize {
		return nil, fmt.Errorf("Noise RESPONSE length %d, want %d: %w", len(noiseMessage), responseNoiseMessageSize, ErrInvalidState)
	}
	if packetSize < ResponseMinPacketSize {
		return nil, fmt.Errorf("Noise RESPONSE packet size %d is too small: %w", packetSize, ErrInvalidState)
	}
	if cap(dst) < packetSize {
		return nil, fmt.Errorf("Noise RESPONSE buffer too small: %w", ErrInvalidState)
	}
	if random == nil {
		return nil, fmt.Errorf("nil random source: %w", ErrInvalidState)
	}

	packet := dst[:packetSize]
	padding := packet[dataplane.RouteSize : packetSize-responseNoiseMessageSize]
	if len(padding) != 0 {
		if _, err := io.ReadFull(random, padding); err != nil {
			return nil, fmt.Errorf("generate Noise RESPONSE padding: %w", err)
		}
	}
	message := packet[packetSize-responseNoiseMessageSize:]
	copy(message, noiseMessage)
	if err := maskNoiseEphemeral(scratch, message); err != nil {
		return nil, fmt.Errorf("mask Noise RESPONSE ephemeral: %w", err)
	}

	if err := dataplane.WriteRoute(scratch, packet, dataplane.Route{
		SessionID: 0,
		Sequence:  exchangeID,
	}); err != nil {
		return nil, fmt.Errorf("encode Noise RESPONSE route: %w", err)
	}
	return packet, nil
}

func parseInitPacket(
	scratch *dataplane.DataScratch,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (wirePacket, error) {
	if !isNoiseEstablishmentDatagram(route, routeDecoded, packet) ||
		route.Sequence == 0 ||
		len(packet) < InitMinPacketSize {
		return wirePacket{}, ErrInvalidPacket
	}
	message := append([]byte(nil), packet[len(packet)-initNoiseMessageSize:]...)
	if err := maskNoiseEphemeral(scratch, message); err != nil {
		return wirePacket{}, ErrInvalidPacket
	}
	return wirePacket{
		exchangeID: route.Sequence,
		message:    message,
	}, nil
}

func parseResponsePacket(
	scratch *dataplane.DataScratch,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (wirePacket, error) {
	if !isNoiseEstablishmentDatagram(route, routeDecoded, packet) ||
		route.Sequence == 0 ||
		len(packet) < ResponseMinPacketSize {
		return wirePacket{}, ErrInvalidPacket
	}
	message := append([]byte(nil), packet[len(packet)-responseNoiseMessageSize:]...)
	if err := maskNoiseEphemeral(scratch, message); err != nil {
		return wirePacket{}, ErrInvalidPacket
	}
	return wirePacket{
		exchangeID: route.Sequence,
		message:    message,
	}, nil
}

func maskNoiseEphemeral(scratch *dataplane.DataScratch, message []byte) error {
	if scratch == nil || len(message) < noiseEphemeralSize+dataplane.TagSize {
		return ErrInvalidPacket
	}
	mask, err := scratch.EstablishmentEphemeralMask(message[len(message)-dataplane.TagSize:])
	if err != nil {
		return err
	}
	for i := 0; i < noiseEphemeralSize; i++ {
		message[i] ^= mask[i]
	}
	return nil
}

func encodeResponsePayload(sessionID uint64) ([responsePayloadSize]byte, error) {
	var payload [responsePayloadSize]byte
	if sessionID == 0 {
		return payload, fmt.Errorf("session id is zero: %w", ErrInvalidState)
	}
	binary.LittleEndian.PutUint64(payload[:], sessionID)
	return payload, nil
}

func parseResponsePayload(payload []byte) (uint64, error) {
	if len(payload) != responsePayloadSize {
		return 0, ErrInvalidPacket
	}
	sessionID := binary.LittleEndian.Uint64(payload)
	if sessionID == 0 {
		return 0, ErrInvalidPacket
	}
	return sessionID, nil
}

// randomPacketSize returns a uniform value from the inclusive min..max range
// using only io.Reader so deterministic handshake tests can inject their own
// random stream without changing production RNG ownership.
func randomPacketSize(random io.Reader, min, max int) (int, error) {
	if random == nil {
		return 0, fmt.Errorf("nil random source: %w", ErrInvalidState)
	}
	if min < 0 || max < min {
		return 0, fmt.Errorf("invalid packet-size range [%d, %d]: %w", min, max, ErrInvalidState)
	}
	span := max - min + 1
	if span > 1<<16 {
		return 0, fmt.Errorf("packet-size range [%d, %d] is too wide: %w", min, max, ErrInvalidState)
	}
	if span == 1 {
		return min, nil
	}

	limit := (1 << 16) - ((1 << 16) % span)
	var raw [2]byte
	for {
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return 0, err
		}
		value := int(binary.LittleEndian.Uint16(raw[:]))
		if value < limit {
			return min + value%span, nil
		}
	}
}
