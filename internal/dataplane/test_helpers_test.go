package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func testKeys() (route, c2s, s2c [32]byte) {
	for i := 0; i < 32; i++ {
		route[i] = byte(i + 1)
		c2s[i] = byte(0x40 + i)
		s2c[i] = byte(0x80 + i)
	}
	return route, c2s, s2c
}

func testIPv4Packet(
	t *testing.T,
	source string,
	destination string,
	payload []byte,
) []byte {
	t.Helper()
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func newTestDataScratch(t *testing.T, routeKey [32]byte) *DataScratch {
	t.Helper()
	scratch, err := NewDataScratch(routeKey)
	if err != nil {
		t.Fatalf("NewDataScratch: %v", err)
	}
	return scratch
}

func sealTestPacket(
	t *testing.T,
	session *Session,
	routeKey *[32]byte,
	plaintext []byte,
) ([]byte, uint64) {
	t.Helper()
	scratch := newTestDataScratch(t, *routeKey)
	dst := make([]byte, 0, len(plaintext)+DataOverhead+7)
	wire, sequence, err := session.sealToWithPadding(
		scratch,
		dst,
		plaintext,
		7,
	)
	if err != nil {
		t.Fatalf("sealToWithPadding: %v", err)
	}
	return wire, sequence
}
