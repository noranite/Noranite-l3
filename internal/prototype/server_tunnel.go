package prototype

import (
	"net/netip"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
)

// ServerEstablishmentIngress is an optional cold-path establishment
// demultiplexer that runs after the common opaque route has been decoded and
// before encrypted packets enter the server RX worker engine.
//
// Datagram ownership is broader than successful parsing. Once
// IsEstablishmentDatagram returns true, the packet belongs to establishment and
// must never fall through to encrypted dataplane admission. Malformed, stale or
// unauthorized network packets are consumed with handled=true and err=nil.
// A non-nil error is reserved for local/server failures and is terminal for the
// runtime.
//
// Production execution invokes TryHandleEstablishmentDatagramInPlace from a
// small worker pool, so implementations must support concurrent calls across
// datagrams. The returned response may alias packet; the runtime keeps packet
// storage alive until synchronous response sending completes.
type ServerEstablishmentIngress interface {
	establishment.DatagramClassifier

	TryHandleEstablishmentDatagramInPlace(
		source netip.AddrPort,
		route dataplane.Route,
		routeDecoded bool,
		packet []byte,
	) (
		handled bool,
		response []byte,
		responseDestination netip.AddrPort,
		err error,
	)
}
