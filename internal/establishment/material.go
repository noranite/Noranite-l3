package establishment

import "github.com/noranite/Noranite-l3/internal/dataplane"

// TrafficSessionMaterial is the protocol-independent output of one traffic
// generation establishment.
//
// Directional keys are named from the client's point of view. Routing-domain
// material is deliberately not part of this type: K_route has an independent
// lifetime and must not be silently treated as per-generation state.
type TrafficSessionMaterial struct {
	SessionID uint64
	C2S       [32]byte
	S2C       [32]byte
}

// NewClientSession maps establishment key directions to client dataplane roles.
// Fresh Session traffic keys start their sequence space at zero.
func NewClientSession(material TrafficSessionMaterial) (*dataplane.Session, error) {
	return dataplane.NewSession(
		material.SessionID,
		material.C2S,
		material.S2C,
		0,
	)
}

// NewServerSession maps establishment key directions to server dataplane roles.
// Fresh Session traffic keys start their sequence space at zero.
func NewServerSession(material TrafficSessionMaterial) (*dataplane.Session, error) {
	return dataplane.NewSession(
		material.SessionID,
		material.S2C,
		material.C2S,
		0,
	)
}
