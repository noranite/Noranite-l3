package dataplane

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDataWireGoldenVectors verifies the complete DATA wire format against
// independently generated vectors. Changes to expected bytes may break wire
// compatibility.
func TestDataWireGoldenVectors(t *testing.T) {
	routeKey, c2s, s2c := testKeys()

	const sessionID uint64 = 0x71a24e9c5312bb19
	const sequence uint64 = 10

	// Complete inner IPv4 packet:
	//
	//	version/IHL: 4 / 5
	//	total length: 26
	//	TTL: 64
	//	protocol: UDP
	//	source: 10.66.0.2
	//	destination: 10.66.0.1
	//	payload: "vector"
	plaintext := mustDecodeHex(
		t,
		"4500001a00000000401100000a4200020a420001766563746f72",
	)

	tests := []struct {
		name          string
		paddingLength int
		wantWireHex   string
	}{
		{
			name:          "padding 0",
			paddingLength: 0,
			wantWireHex: "" +
				"43e7b8a36210314bab721949266b880c" +
				"10c4f33c42cdfcdf7d76d71b12ad5ab0" +
				"1fc42c2f3f8611766936f09e85e79f9" +
				"ff37347d7a54b306b749b",
		},
		{
			name:          "padding 7",
			paddingLength: 7,
			wantWireHex: "" +
				"326e373566095ee7e20683024f8391b9" +
				"10c4f33c42cdfcdf7d76d71b12ad5ab0" +
				"1fc42c2f3f8611766936b3d2115f3db797" +
				"5a24aaf82d37b16a38e71a5fb131d9cb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			txScratch := newTestDataScratch(
				t,
				routeKey,
			)

			// Use fixed padding to keep the golden vector deterministic.
			dst := make(
				[]byte,
				0,
				len(plaintext)+DataOverhead+tt.paddingLength,
			)

			wire, gotSequence, err := client.sealToWithPadding(
				txScratch,
				dst,
				plaintext,
				tt.paddingLength,
			)
			if err != nil {
				t.Fatalf(
					"sealToWithPadding: %v",
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

			wantWire := mustDecodeHex(
				t,
				tt.wantWireHex,
			)

			if !bytes.Equal(wire, wantWire) {
				t.Fatalf(
					"wire mismatch:\n got: %x\nwant: %x",
					wire,
					wantWire,
				)
			}

			// Exercise the receive path with the independent golden datagram.
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

			rxScratch := newTestDataScratch(
				t,
				routeKey,
			)

			// Open mutates its input, so copy the golden bytes.
			packet := bytes.Clone(wantWire)

			gotSessionID, gotSequence, err := decodePacketRoute(
				rxScratch,
				packet,
			)
			if err != nil {
				t.Fatalf(
					"decodePacketRoute: %v",
					err,
				)
			}

			if gotSessionID != sessionID {
				t.Fatalf(
					"decoded session=%#x, want %#x",
					gotSessionID,
					sessionID,
				)
			}

			if gotSequence != sequence {
				t.Fatalf(
					"decoded sequence=%d, want %d",
					gotSequence,
					sequence,
				)
			}

			opened, err := server.AuthenticateInPlace(
				rxScratch,
				packet,
				gotSequence,
			)
			if err != nil {
				t.Fatalf(
					"AuthenticateInPlace: %v",
					err,
				)
			}

			wantPlaintext := make(
				[]byte,
				len(plaintext)+tt.paddingLength,
			)

			copy(
				wantPlaintext,
				plaintext,
			)

			// The reference sender uses zero-filled padding.
			if !bytes.Equal(opened, wantPlaintext) {
				t.Fatalf(
					"decrypted plaintext mismatch:\n got: %x\nwant: %x",
					opened,
					wantPlaintext,
				)
			}

			// IPv4 Total Length excludes DATA padding.
			header, err := ParseIPv4(opened)
			if err != nil {
				t.Fatalf(
					"ParseIPv4: %v",
					err,
				)
			}

			if header.TotalLength != len(plaintext) {
				t.Fatalf(
					"IPv4 TotalLength=%d, want %d",
					header.TotalLength,
					len(plaintext),
				)
			}
		})
	}
}

func mustDecodeHex(
	t *testing.T,
	value string,
) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf(
			"decode test vector: %v",
			err,
		)
	}

	return decoded
}
