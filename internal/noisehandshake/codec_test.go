package noisehandshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestWireCodecUsesOpaqueRouteAndVariablePadding(t *testing.T) {
	const exchangeID = uint64(0x0102030405060708)
	message := bytes.Repeat([]byte{0x5a}, initNoiseMessageSize)
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		t.Fatal(err)
	}

	wantSize := InitMinGeneratedPacketSize + 3
	wantPadding := wantSize - InitMinPacketSize
	randomBytes := append([]byte{3, 0}, bytes.Repeat([]byte{0xa1}, wantPadding)...)
	packet, err := appendInitPacket(
		make([]byte, 0, InitMaxGeneratedPacketSize),
		scratch,
		bytes.NewReader(randomBytes),
		exchangeID,
		message,
	)
	if err != nil {
		t.Fatalf("appendInitPacket: %v", err)
	}
	if got, want := len(packet), wantSize; got != want {
		t.Fatalf("INIT size=%d, want %d", got, want)
	}
	if !bytes.Equal(packet[dataplane.RouteSize:len(packet)-initNoiseMessageSize], bytes.Repeat([]byte{0xa1}, wantPadding)) {
		t.Fatal("INIT padding mismatch")
	}
	wireMessage := packet[len(packet)-initNoiseMessageSize:]
	if bytes.Equal(wireMessage[:noiseEphemeralSize], message[:noiseEphemeralSize]) {
		t.Fatal("Noise INIT ephemeral is visible on wire")
	}
	if !bytes.Equal(wireMessage[noiseEphemeralSize:], message[noiseEphemeralSize:]) {
		t.Fatal("Noise INIT non-ephemeral bytes changed")
	}

	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		t.Fatal(err)
	}
	if route.SessionID != 0 || route.Sequence != exchangeID {
		t.Fatalf("route=%+v, want reserved session/exchange", route)
	}
	parsed, err := parseInitPacket(scratch, route, true, packet)
	if err != nil {
		t.Fatalf("parseInitPacket: %v", err)
	}
	if parsed.exchangeID != exchangeID || !bytes.Equal(parsed.message, message) {
		t.Fatal("INIT round-trip mismatch")
	}
}

func TestGeneratedResponseUsesIndependentBoundedWireSize(t *testing.T) {
	const exchangeID = uint64(9)
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	initMessage := bytes.Repeat([]byte{0x11}, initNoiseMessageSize)
	initSize := InitMinGeneratedPacketSize + 200
	initPadding := initSize - InitMinPacketSize
	initPacket, err := appendInitPacket(
		make([]byte, 0, InitMaxGeneratedPacketSize),
		scratch,
		bytes.NewReader(append([]byte{200, 0}, bytes.Repeat([]byte{0x22}, initPadding)...)),
		exchangeID,
		initMessage,
	)
	if err != nil {
		t.Fatal(err)
	}

	responseMessage := bytes.Repeat([]byte{0x33}, responseNoiseMessageSize)
	responseSize := ResponseMinGeneratedPacketSize + 17
	responsePadding := responseSize - ResponseMinPacketSize
	response, err := appendGeneratedResponsePacket(
		make([]byte, 0, ResponseMaxGeneratedPacketSize),
		scratch,
		bytes.NewReader(append([]byte{17, 0}, bytes.Repeat([]byte{0x44}, responsePadding)...)),
		exchangeID,
		responseMessage,
		len(initPacket),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != responseSize {
		t.Fatalf("response size=%d, want %d", len(response), responseSize)
	}
	if len(response) >= len(initPacket) {
		t.Fatalf("response size=%d, want independently smaller than init size=%d", len(response), len(initPacket))
	}
	wireResponseMessage := response[len(response)-responseNoiseMessageSize:]
	if bytes.Equal(wireResponseMessage[:noiseEphemeralSize], responseMessage[:noiseEphemeralSize]) {
		t.Fatal("Noise RESPONSE ephemeral is visible on wire")
	}
	if !bytes.Equal(wireResponseMessage[noiseEphemeralSize:], responseMessage[noiseEphemeralSize:]) {
		t.Fatal("Noise RESPONSE non-ephemeral bytes changed")
	}
	route, err := dataplane.DecodeRoute(scratch, response)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseResponsePacket(scratch, route, true, response)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.exchangeID != exchangeID || !bytes.Equal(parsed.message, responseMessage) {
		t.Fatal("RESPONSE round-trip mismatch")
	}
}

func TestGeneratedResponseKeepsLegacySmallInitNonAmplifying(t *testing.T) {
	const exchangeID = uint64(10)
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		t.Fatal(err)
	}

	responseMessage := bytes.Repeat([]byte{0x33}, responseNoiseMessageSize)
	const responseOffset = 17
	responseSize := ResponseMinPacketSize + responseOffset
	response, err := appendGeneratedResponsePacket(
		make([]byte, 0, InitMinPacketSize),
		scratch,
		bytes.NewReader(append([]byte{responseOffset, 0}, bytes.Repeat([]byte{0x44}, responseOffset)...)),
		exchangeID,
		responseMessage,
		InitMinPacketSize,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != responseSize {
		t.Fatalf("legacy response size=%d, want %d", len(response), responseSize)
	}
	if len(response) > InitMinPacketSize {
		t.Fatalf("legacy response size=%d > request size=%d", len(response), InitMinPacketSize)
	}
}

func TestWireParserRejectsWrongNamespaceZeroExchangeAndShortPacket(t *testing.T) {
	scratch, err := dataplane.NewDataScratch([32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, InitMinPacketSize)
	copy(packet[len(packet)-initNoiseMessageSize:], bytes.Repeat([]byte{0x55}, initNoiseMessageSize))

	tests := []struct {
		name         string
		route        dataplane.Route
		routeDecoded bool
		packet       []byte
	}{
		{name: "route decode failed", route: dataplane.Route{}, routeDecoded: false, packet: packet},
		{name: "ordinary session", route: dataplane.Route{SessionID: 1, Sequence: 1}, routeDecoded: true, packet: packet},
		{name: "zero exchange", route: dataplane.Route{SessionID: 0, Sequence: 0}, routeDecoded: true, packet: packet},
		{name: "short", route: dataplane.Route{SessionID: 0, Sequence: 1}, routeDecoded: true, packet: packet[:InitMinPacketSize-1]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseInitPacket(scratch, tc.route, tc.routeDecoded, tc.packet); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("parseInitPacket error=%v, want ErrInvalidPacket", err)
			}
		})
	}
}

func TestClassifierOwnsOnlyDecodedReservedRouteNamespace(t *testing.T) {
	packet := make([]byte, ResponseMinPacketSize)
	if isNoiseEstablishmentDatagram(dataplane.Route{}, false, packet) {
		t.Fatal("undecodable route classified as establishment")
	}
	if isNoiseEstablishmentDatagram(dataplane.Route{SessionID: 1}, true, packet) {
		t.Fatal("ordinary session classified as establishment")
	}
	if !isNoiseEstablishmentDatagram(dataplane.Route{SessionID: 0, Sequence: 1}, true, packet) {
		t.Fatal("reserved route namespace not classified as establishment")
	}
}

func TestResponsePayloadCodec(t *testing.T) {
	const sessionID = uint64(0x1122334455667788)
	payload, err := encodeResponsePayload(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(payload[:]); got != sessionID {
		t.Fatalf("encoded session id=%x, want %x", got, sessionID)
	}
	got, err := parseResponsePayload(payload[:])
	if err != nil || got != sessionID {
		t.Fatalf("parseResponsePayload=%x, %v", got, err)
	}
	if _, err := parseResponsePayload(make([]byte, responsePayloadSize)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("zero session id error=%v, want ErrInvalidPacket", err)
	}
}
