package dataplane

import "errors"

// Errors are intentionally coarse. Network-facing code will normally map most
// of them to DROP SILENTLY; the distinctions are useful for tests and debug
// diagnostics.
var (
	ErrPacketTooShort    = errors.New("opaque-l3: packet is too short")
	ErrPacketTooLarge    = errors.New("opaque-l3: packet is too large")
	ErrBufferTooSmall    = errors.New("opaque-l3: destination buffer is too small")
	ErrAuthentication    = errors.New("opaque-l3: authentication failed")
	ErrReplay            = errors.New("opaque-l3: replayed or too-old packet")
	ErrInvalidIPv4       = errors.New("opaque-l3: invalid IPv4 packet")
	ErrSequenceExhausted = errors.New("opaque-l3: transmit sequence exhausted")
	ErrInvalidConfig     = errors.New("opaque-l3: invalid configuration")
	ErrInvalidPadding    = errors.New("opaque-l3: invalid padding")
	ErrInvalidControl    = errors.New("opaque-l3: invalid CONTROL plaintext")
	ErrInvalidPlaintext  = errors.New("opaque-l3: invalid authenticated plaintext")
)
