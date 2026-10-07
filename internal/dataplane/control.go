package dataplane

import "encoding/binary"

const (
	// ControlHeaderSize is the fixed semantic prefix of every v1 CONTROL
	// plaintext:
	//
	//	0x00 || subtype || keepalive_id(LE64)
	ControlHeaderSize = 10

	MinControlWirePacketSize = DataOverhead + ControlHeaderSize

	// Ordinary generated liveness CONTROL uses a broad sender-side wire-size
	// range so periodic KEEPALIVE/ACK traffic does not collapse to a tiny stable
	// packet shape. These are sender policy bounds, not receiver compatibility
	// limits. ACK generation is additionally bounded by the triggering KEEPALIVE.
	MinGeneratedControlWirePacketSize = 384
	MaxGeneratedControlWirePacketSize = 768
)

// ControlType identifies an encrypted CONTROL subtype.
type ControlType uint8

const (
	ControlKeepalive ControlType = 0x00
	ControlACK       ControlType = 0x01
)

// ControlMessage is the semantic portion of an authenticated CONTROL
// plaintext. Padding bytes are intentionally not exposed because they have no
// protocol meaning; only their count is useful for ACK amplification bounds.
type ControlMessage struct {
	Type          ControlType
	KeepaliveID   uint64
	PaddingLength int
}

// InboundKind is the post-authentication plaintext class surfaced by client
// and server cores to the network runtime.
type InboundKind uint8

const (
	InboundIPv4 InboundKind = iota + 1
	InboundKeepalive
	InboundACK
)

// InboundPacket is a small post-authentication event.
//
// IPv4 is populated only for InboundIPv4. KeepaliveID is populated only for
// InboundKeepalive/InboundACK. CONTROL padding is deliberately not forwarded to
// higher layers.
type InboundPacket struct {
	Kind        InboundKind
	IPv4        []byte
	KeepaliveID uint64
}

// ParseControl parses authenticated CONTROL plaintext.
//
// It intentionally does not impose a receiver-side padding limit. Resource
// bounds belong to the outer packet receive path; CONTROL padding itself has no
// semantic content.
func ParseControl(plaintext []byte) (ControlMessage, error) {
	var message ControlMessage

	if len(plaintext) < ControlHeaderSize {
		return message, ErrInvalidControl
	}
	if plaintext[0] != 0x00 {
		return message, ErrInvalidControl
	}

	switch ControlType(plaintext[1]) {
	case ControlKeepalive:
		message.Type = ControlKeepalive
	case ControlACK:
		message.Type = ControlACK
	default:
		return ControlMessage{}, ErrInvalidControl
	}

	message.KeepaliveID = binary.LittleEndian.Uint64(plaintext[2:10])
	message.PaddingLength = len(plaintext) - ControlHeaderSize
	return message, nil
}

// SealKeepaliveTo encrypts one KEEPALIVE using the ordinary generated CONTROL
// wire-size range.
func (s *Session) SealKeepaliveTo(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
) (wire []byte, sequence uint64, err error) {
	return s.sealControlToRandomWireRange(
		scratch,
		dst,
		ControlKeepalive,
		keepaliveID,
		MinGeneratedControlWirePacketSize,
		MaxGeneratedControlWirePacketSize,
	)
}

// SealKeepaliveToWithPadding is the deterministic variant used by protocol tests
// and by callers that own an explicit CONTROL padding policy. Unlike the
// default random sender policy, explicit padding is bounded only by dst capacity.
func (s *Session) SealKeepaliveToWithPadding(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	paddingLength int,
) (wire []byte, sequence uint64, err error) {
	return s.sealControlToWithPadding(
		scratch,
		dst,
		ControlKeepalive,
		keepaliveID,
		paddingLength,
	)
}

// SealACKTo encrypts an ACK while enforcing the protocol anti-amplification
// rule at the codec boundary.
//
// maxWireSize is the full Opaque-L3 UDP payload size of the triggering KEEPALIVE.
// The returned ACK is chosen independently from the KEEPALIVE size within the
// ordinary generated CONTROL range, but never exceeds the triggering packet.
func (s *Session) SealACKTo(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	maxWireSize int,
) (wire []byte, sequence uint64, err error) {
	if maxWireSize > MaxGeneratedControlWirePacketSize {
		maxWireSize = MaxGeneratedControlWirePacketSize
	}

	return s.sealControlToRandomWireRange(
		scratch,
		dst,
		ControlACK,
		keepaliveID,
		MinGeneratedControlWirePacketSize,
		maxWireSize,
	)
}

// SealACKToWithPadding is deterministic and mainly useful for vectors/tests.
// The caller is responsible for any higher-level anti-amplification bound.
func (s *Session) SealACKToWithPadding(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	paddingLength int,
) (wire []byte, sequence uint64, err error) {
	return s.sealControlToWithPadding(
		scratch,
		dst,
		ControlACK,
		keepaliveID,
		paddingLength,
	)
}

func (s *Session) sealControlToRandomWireRange(
	scratch *DataScratch,
	dst []byte,
	controlType ControlType,
	keepaliveID uint64,
	minWireSize int,
	maxWireSize int,
) (wire []byte, sequence uint64, err error) {
	if minWireSize < MinControlWirePacketSize || maxWireSize < minWireSize {
		return nil, 0, ErrInvalidPadding
	}
	if cap(dst) < maxWireSize {
		return nil, 0, ErrBufferTooSmall
	}

	sequence, err = s.ReserveTXSequence()
	if err != nil {
		return nil, 0, err
	}

	wire, err = s.sealControlToRandomWireRangeReserved(
		scratch,
		dst,
		controlType,
		keepaliveID,
		minWireSize,
		maxWireSize,
		sequence,
	)
	return wire, sequence, err
}

func (s *Session) sealControlToWithPadding(
	scratch *DataScratch,
	dst []byte,
	controlType ControlType,
	keepaliveID uint64,
	paddingLength int,
) (wire []byte, sequence uint64, err error) {
	if paddingLength < 0 {
		return nil, 0, ErrInvalidPadding
	}

	// Explicit CONTROL padding is bounded only by destination capacity. Avoid integer
	// overflow by comparing against capacity before adding sizes. The network
	// runtime still enforces its configured maximum UDP payload on receive.
	if cap(dst) < MinControlWirePacketSize ||
		paddingLength > cap(dst)-MinControlWirePacketSize {
		return nil, 0, ErrBufferTooSmall
	}

	sequence, err = s.ReserveTXSequence()
	if err != nil {
		return nil, 0, err
	}

	wire, err = s.sealControlToWithPaddingReserved(
		scratch,
		dst,
		controlType,
		keepaliveID,
		paddingLength,
		sequence,
	)
	return wire, sequence, err
}

// SealKeepaliveToReserved finishes a KEEPALIVE operation whose sequence was already
// reserved during TX admission. It exists for the parallel packet engine; the
// ordinary SealKeepaliveTo wrapper remains the safer synchronous API.
func (s *Session) SealKeepaliveToReserved(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	sequence uint64,
) ([]byte, error) {
	return s.sealControlToRandomWireRangeReserved(
		scratch,
		dst,
		ControlKeepalive,
		keepaliveID,
		MinGeneratedControlWirePacketSize,
		MaxGeneratedControlWirePacketSize,
		sequence,
	)
}

// SealKeepaliveToWithPaddingReserved is the deterministic worker-facing KEEPALIVE
// variant. The sequence must already belong to this Session operation.
func (s *Session) SealKeepaliveToWithPaddingReserved(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	paddingLength int,
	sequence uint64,
) ([]byte, error) {
	return s.sealControlToWithPaddingReserved(
		scratch,
		dst,
		ControlKeepalive,
		keepaliveID,
		paddingLength,
		sequence,
	)
}

// SealKeepaliveToRangeReserved finishes a KEEPALIVE operation whose wire size
// is chosen uniformly from the inclusive [minWireSize, maxWireSize] range. The
// sequence must already belong to this Session operation.
func (s *Session) SealKeepaliveToRangeReserved(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	minWireSize int,
	maxWireSize int,
	sequence uint64,
) ([]byte, error) {
	return s.sealControlToRandomWireRangeReserved(
		scratch,
		dst,
		ControlKeepalive,
		keepaliveID,
		minWireSize,
		maxWireSize,
		sequence,
	)
}

// SealACKToReserved is the worker-facing ACK equivalent. maxWireSize is the
// triggering KEEPALIVE wire size and therefore preserves the v1 anti-amplification
// bound even when ACK encryption happens later on another goroutine.
func (s *Session) SealACKToReserved(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	maxWireSize int,
	sequence uint64,
) ([]byte, error) {
	if maxWireSize > MaxGeneratedControlWirePacketSize {
		maxWireSize = MaxGeneratedControlWirePacketSize
	}
	return s.sealControlToRandomWireRangeReserved(
		scratch,
		dst,
		ControlACK,
		keepaliveID,
		MinGeneratedControlWirePacketSize,
		maxWireSize,
		sequence,
	)
}

// SealACKToRangeReserved is the range-policy ACK equivalent. Callers pass an
// already anti-amplification-bounded maxWireSize; the returned ACK never
// exceeds it.
func (s *Session) SealACKToRangeReserved(
	scratch *DataScratch,
	dst []byte,
	keepaliveID uint64,
	minWireSize int,
	maxWireSize int,
	sequence uint64,
) ([]byte, error) {
	return s.sealControlToRandomWireRangeReserved(
		scratch,
		dst,
		ControlACK,
		keepaliveID,
		minWireSize,
		maxWireSize,
		sequence,
	)
}

func (s *Session) sealControlToRandomWireRangeReserved(
	scratch *DataScratch,
	dst []byte,
	controlType ControlType,
	keepaliveID uint64,
	minWireSize int,
	maxWireSize int,
	sequence uint64,
) ([]byte, error) {
	if minWireSize < MinControlWirePacketSize || maxWireSize < minWireSize {
		return nil, ErrInvalidPadding
	}
	if cap(dst) < maxWireSize {
		return nil, ErrBufferTooSmall
	}

	minPadding := minWireSize - MinControlWirePacketSize
	maxPadding := maxWireSize - MinControlWirePacketSize
	paddingLength := minPadding + nextPaddingLength(scratch.paddingRNG, maxPadding-minPadding)
	return s.sealControlToWithPaddingReserved(
		scratch,
		dst,
		controlType,
		keepaliveID,
		paddingLength,
		sequence,
	)
}

// sealControlToWithPaddingReserved constructs CONTROL for an already-reserved
// sequence. Like DATA worker sealing, it mutates no Session TX state.
func (s *Session) sealControlToWithPaddingReserved(
	scratch *DataScratch,
	dst []byte,
	controlType ControlType,
	keepaliveID uint64,
	paddingLength int,
	sequence uint64,
) ([]byte, error) {
	if controlType != ControlKeepalive && controlType != ControlACK {
		return nil, ErrInvalidControl
	}
	if paddingLength < 0 {
		return nil, ErrInvalidPadding
	}

	if cap(dst) < MinControlWirePacketSize ||
		paddingLength > cap(dst)-MinControlWirePacketSize {
		return nil, ErrBufferTooSmall
	}

	required := MinControlWirePacketSize + paddingLength
	packet := dst[:required]

	plaintext := packet[RouteSize : len(packet)-TagSize]
	plaintext[0] = 0x00
	plaintext[1] = byte(controlType)
	binary.LittleEndian.PutUint64(plaintext[2:10], keepaliveID)
	clear(plaintext[ControlHeaderSize:])

	return s.sealPreparedPlaintext(
		scratch,
		packet,
		sequence,
	)
}
