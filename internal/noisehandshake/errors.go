package noisehandshake

import "errors"

var (
	ErrInvalidKey       = errors.New("noise handshake: invalid key")
	ErrInvalidPacket    = errors.New("noise handshake: invalid packet")
	ErrInvalidFreshness = errors.New("noise handshake: invalid freshness")
	ErrInvalidState     = errors.New("noise handshake: invalid state")
)
