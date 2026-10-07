package dataplane

import (
	"encoding/binary"
	"net/netip"
)

// IPv4Header contains the fields needed for tunnel authorization.
type IPv4Header struct {
	// HeaderLength is the IPv4 header size derived from IHL.
	HeaderLength int

	// TotalLength separates the inner packet from authenticated DATA padding.
	TotalLength int

	// Source is the inner source IPv4 address.
	Source netip.Addr

	// Destination is the inner destination IPv4 address.
	Destination netip.Addr
}

// ParseIPv4 performs the required Opaque-L3 v1 checks:
//   - the packet contains a 20-byte base header;
//   - version is 4;
//   - IHL is at least 5;
//   - header length does not exceed plaintext length;
//   - Total Length is at least the header length;
//   - Total Length does not exceed plaintext length.
//
// The optional IPv4 header checksum validation is left to other layers.
func ParseIPv4(packet []byte) (IPv4Header, error) {
	var header IPv4Header

	if len(packet) < 20 {
		return header, ErrInvalidIPv4
	}

	version := packet[0] >> 4
	if version != 4 {
		return header, ErrInvalidIPv4
	}

	// IHL is measured in 32-bit words.
	ihl := int(packet[0] & 0x0f)
	if ihl < 5 {
		return header, ErrInvalidIPv4
	}

	headerLength := ihl * 4
	if headerLength > len(packet) {
		return header, ErrInvalidIPv4
	}

	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength {
		return header, ErrInvalidIPv4
	}

	// Bytes after Total Length may be DATA padding; ParseDataIPv4 enforces its
	// protocol limit.
	if totalLength > len(packet) {
		return header, ErrInvalidIPv4
	}

	var sourceBytes [4]byte
	copy(sourceBytes[:], packet[12:16])

	var destinationBytes [4]byte
	copy(destinationBytes[:], packet[16:20])

	header.HeaderLength = headerLength
	header.TotalLength = totalLength
	header.Source = netip.AddrFrom4(sourceBytes)
	header.Destination = netip.AddrFrom4(destinationBytes)
	return header, nil
}

// ParseTunIPv4 validates a packet received from a TUN device. Unlike decrypted
// DATA plaintext, a TUN packet may not contain Opaque-L3 trailing padding.
func ParseTunIPv4(packet []byte, maxInnerPacketSize int) (IPv4Header, error) {
	var zero IPv4Header
	if len(packet) > maxInnerPacketSize {
		return zero, ErrPacketTooLarge
	}

	header, err := ParseIPv4(packet)
	if err != nil {
		return zero, err
	}
	if header.TotalLength != len(packet) {
		return zero, ErrInvalidIPv4
	}
	return header, nil
}

// ParseDataIPv4 validates authenticated DATA plaintext and separates the real
// inner IPv4 packet from Opaque-L3 trailing DATA padding.
func ParseDataIPv4(
	plaintext []byte,
	maxInnerPacketSize int,
) (packet []byte, header IPv4Header, err error) {
	header, err = ParseIPv4(plaintext)
	if err != nil {
		return nil, IPv4Header{}, err
	}
	if header.TotalLength > maxInnerPacketSize {
		return nil, IPv4Header{}, ErrPacketTooLarge
	}

	paddingLength := len(plaintext) - header.TotalLength
	if paddingLength > MaxDataPadding {
		return nil, IPv4Header{}, ErrInvalidPadding
	}

	return plaintext[:header.TotalLength], header, nil
}
