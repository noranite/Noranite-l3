package client

import "errors"

var (
	ErrUnknownSession          = errors.New("opaque-l3: unknown session")
	ErrSessionNotRXEligible    = errors.New("opaque-l3: session is no longer RX-eligible")
	ErrSessionNotTXEligible    = errors.New("opaque-l3: session is no longer TX-eligible")
	ErrSessionIDCollision      = errors.New("opaque-l3: session id collides with a live session")
	ErrNoCurrentSession        = errors.New("opaque-l3: peer has no current session")
	ErrUnauthorizedSource      = errors.New("opaque-l3: unauthorized inner source IPv4")
	ErrUnauthorizedDestination = errors.New("opaque-l3: unauthorized inner destination IPv4")
	ErrUnexpectedControl       = errors.New("opaque-l3: unexpected CONTROL subtype for client")
	ErrRXEngineClosed          = errors.New("opaque-l3: client RX engine is closed")
	ErrTXEngineClosed          = errors.New("opaque-l3: client TX engine is closed")
)
