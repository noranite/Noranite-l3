package establishment

import "github.com/noranite/Noranite-l3/internal/dataplane"

// DatagramClassifier identifies datagrams owned by an establishment protocol.
//
// routeDecoded reports whether route was decoded from this exact packet with the
// routing-domain key. Establishment protocols should normally claim a hidden
// route namespace, currently SessionID == 0. Explicit plaintext envelopes may
// instead ignore route and routeDecoded.
//
// Once this method returns true, the datagram belongs to establishment and must
// never fall through to encrypted dataplane admission, even if later parsing,
// authentication, freshness or authorization checks reject it.
type DatagramClassifier interface {
	IsEstablishmentDatagram(route dataplane.Route, routeDecoded bool, packet []byte) bool
}
