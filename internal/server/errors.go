package server

import "errors"

var (
	ErrUnknownSession          = errors.New("opaque-l3: unknown session")
	ErrUnknownPeer             = errors.New("opaque-l3: unknown peer")
	ErrSessionNotRXEligible    = errors.New("opaque-l3: session is no longer RX-eligible")
	ErrSessionNotTXEligible    = errors.New("opaque-l3: session is no longer TX-eligible")
	ErrSessionIDCollision      = errors.New("opaque-l3: session id collides with a live session")
	ErrNoCurrentSession        = errors.New("opaque-l3: peer has no current session")
	ErrUnauthorizedSource      = errors.New("opaque-l3: unauthorized inner source IPv4")
	ErrUnauthorizedDestination = errors.New("opaque-l3: unknown inner destination IPv4")
	ErrNoEndpoint              = errors.New("opaque-l3: client endpoint is not known yet")
	ErrUnexpectedControl       = errors.New("opaque-l3: unexpected CONTROL subtype for server")
	ErrRXEngineClosed          = errors.New("opaque-l3: RX engine is closed")
	ErrTXEngineClosed          = errors.New("opaque-l3: TX engine is closed")
)
