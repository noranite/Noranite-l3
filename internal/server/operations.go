package server

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// InboundOperation is one RX packet after route lookup + lifecycle admission
// but before expensive AEAD.
//
// It is intentionally a concrete Opaque-L3 server operation, not a generic
// protocol callback. Async engines move-copy it into one work element; the
// element's container is then published to the global decrypt queue and the
// owning Peer's ordered RX queue. The decrypt worker fills plaintext; the
// sequential consumer commits mutable effects.
type InboundOperation struct {
	binding   sessionBinding
	admission RXAdmission

	sequence        uint64
	source          netip.AddrPort
	requestWireSize int

	packet    []byte
	plaintext []byte
}

// Decrypt performs only parallel-safe crypto work. Each worker must use its own
// DataScratch. No replay, endpoint or lifecycle state changes here.
func (op *InboundOperation) Decrypt(scratch *dataplane.DataScratch) error {
	plaintext, err := op.admission.Session.AuthenticateInPlace(
		scratch,
		op.packet,
		op.sequence,
	)
	if err != nil {
		op.plaintext = nil
		return err
	}

	op.plaintext = plaintext
	return nil
}

// OutboundOperation is one TX operation after all generation-dependent state
// has been captured: Session, sequence and destination.
//
// Ownership contract: OutboundOperation is a single-use sequence reservation
// even though this type cannot enforce move-only semantics mechanically. A value
// copy is valid only as a move-style ownership transfer. Independently using
// multiple copies reuses the same (Session, sequence) reservation and can reuse
// an AEAD nonce. SealTo must be called at most once for one admitted operation;
// retry after encryption/transport failure starts from a fresh admission with a
// fresh sequence.
//
// DATA keeps a reference to the inner packet until encryption completes. ACK
// keeps only CONTROL metadata and can therefore outlive the inbound operation
// buffer that triggered it.
type OutboundOperation struct {
	// peer selects the ordered TX queue. Crypto workers never dereference it.
	peer        *Peer
	session     *dataplane.Session
	sequence    uint64
	destination netip.AddrPort

	data []byte

	ackKeepaliveID uint64
	ackMinWireSize int
	ackMaxWireSize int
}

func (op *OutboundOperation) Destination() netip.AddrPort {
	return op.destination
}

func (op *OutboundOperation) Sequence() uint64 {
	return op.sequence
}

func (op *OutboundOperation) Session() *dataplane.Session {
	return op.session
}

// MaxWireSize returns the capacity required for any valid sealing outcome of
// this already-admitted operation. Runtime buffer pools use it before handing
// storage to asynchronous crypto workers.
func (op *OutboundOperation) MaxWireSize() int {
	if op == nil {
		return 0
	}
	if op.data != nil {
		return len(op.data) + dataplane.MaxDataExpansion
	}
	return op.ackMaxWireSize
}

// SealTo is the parallel-safe TX worker body. Session/sequence/destination were
// fixed at admission and are never re-read from Peer here.
//
// SealTo consumes the caller's sole logical use of op. The method intentionally
// does not track consumption on the hot path; callers must obey OutboundOperation's
// linear-use ownership contract.
func (op *OutboundOperation) SealTo(
	scratch *dataplane.DataScratch,
	dst []byte,
) ([]byte, error) {
	if op == nil || op.session == nil {
		return nil, fmt.Errorf("nil outbound operation: %w", dataplane.ErrInvalidConfig)
	}

	if op.data != nil {
		return op.session.SealDataToReserved(
			scratch,
			dst,
			op.data,
			op.sequence,
		)
	}

	if op.ackKeepaliveID == 0 {
		return op.session.SealACKToRangeReserved(
			scratch,
			dst,
			op.ackKeepaliveID,
			op.ackMinWireSize,
			op.ackMaxWireSize,
			op.sequence,
		)
	}

	return op.session.SealACKToReserved(
		scratch,
		dst,
		op.ackKeepaliveID,
		op.ackMaxWireSize,
		op.sequence,
	)
}

// AdmitNetworkDatagram performs the sequential ingress part of RX using the
// Core clock as the admission timestamp. Runtime callers that have an outer
// protocol demultiplexer should capture a userspace UDP dequeue timestamp before
// that demux and use AdmitNetworkDatagramAt instead.
func (c *Core) AdmitNetworkDatagram(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
) (*InboundOperation, error) {
	return c.AdmitNetworkDatagramAt(scratch, source, packet, c.now())
}

// AdmitNetworkDatagramAt performs the sequential ingress part of RX:
// bounds -> opaque route decode -> global Session lookup -> lifecycle admission.
//
// receivedAt must be captured at the userspace UDP dequeue boundary, before any
// handshake/control-plane demultiplexing that may delay transport admission. It
// is not required to be the kernel packet-arrival timestamp. Generation deadlines
// are admission deadlines; local classifier latency must not turn an already
// dequeued packet into an expired one.
func (c *Core) AdmitNetworkDatagramAt(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
	receivedAt time.Time,
) (*InboundOperation, error) {

	if len(packet) < dataplane.MinWirePacketSize {
		return nil, dataplane.ErrPacketTooShort
	}
	if len(packet) > c.maxWirePacketSize() {
		return nil, dataplane.ErrPacketTooLarge
	}
	if !source.IsValid() || source.Port() == 0 {
		return nil, fmt.Errorf(
			"invalid source endpoint: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	route, err := dataplane.DecodeRoute(scratch, packet)
	if err != nil {
		return nil, err
	}

	return c.AdmitNetworkDatagramRouteAt(route, source, packet, receivedAt)
}

// AdmitNetworkDatagramRouteAt is the route-aware runtime ingress variant.
// route must have been decoded from this exact packet with Core's K_route.
// Keeping route decode outside the establishment/dataplane split lets one
// opaque-route PRF serve both namespaces without hashing ordinary DATA twice.
func (c *Core) AdmitNetworkDatagramRouteAt(
	route dataplane.Route,
	source netip.AddrPort,
	packet []byte,
	receivedAt time.Time,
) (*InboundOperation, error) {
	op := new(InboundOperation)
	if err := c.AdmitNetworkDatagramRouteAtInto(op, route, source, packet, receivedAt); err != nil {
		return nil, err
	}
	return op, nil
}

// AdmitNetworkDatagramRouteAtInto is the allocation-free route-aware admission
// variant used by the asynchronous runtime. The caller owns op until it is
// copied into RXEngine. On error op is reset to its zero value.
func (c *Core) AdmitNetworkDatagramRouteAtInto(
	op *InboundOperation,
	route dataplane.Route,
	source netip.AddrPort,
	packet []byte,
	receivedAt time.Time,
) error {
	if op == nil {
		return fmt.Errorf("nil inbound operation: %w", dataplane.ErrInvalidConfig)
	}
	*op = InboundOperation{}

	if len(packet) < dataplane.MinWirePacketSize {
		return dataplane.ErrPacketTooShort
	}
	if len(packet) > c.maxWirePacketSize() {
		return dataplane.ErrPacketTooLarge
	}
	if !source.IsValid() || source.Port() == 0 {
		return fmt.Errorf(
			"invalid source endpoint: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	binding, ok := c.lookupRXBinding(route.SessionID)
	if !ok {
		return ErrUnknownSession
	}

	admission, err := binding.peer.AdmitRX(binding.session, receivedAt)
	if err != nil {
		// RX eligibility and registry residency are intentionally different.
		// An expired pending/previous Session may still occupy a lifecycle slot
		// because an operation admitted before its deadline can still finish. The
		// binding is removed only by an actual lifecycle retirement/replacement.
		return err
	}

	*op = InboundOperation{
		binding:         binding,
		admission:       admission,
		sequence:        route.Sequence,
		source:          source,
		requestWireSize: len(packet),
		packet:          packet,
	}
	return nil
}

// CommitInbound is the race-safe synchronous compatibility surface.
//
// The asynchronous RX engine does not use this mutex path. It already owns one
// sequential consumer goroutine per Peer and calls commitInboundOwned directly.
func (c *Core) CommitInbound(
	op *InboundOperation,
	emitControlResponse bool,
) (dataplane.InboundPacket, *OutboundOperation, error) {
	var inbound dataplane.InboundPacket
	if op == nil || op.binding.peer == nil {
		return inbound, nil, ErrSessionNotRXEligible
	}

	peer := op.binding.peer
	peer.rxCompatMu.Lock()
	defer peer.rxCompatMu.Unlock()

	return c.commitInboundOwned(op, emitControlResponse)
}

// commitInboundOwned performs all stateful RX work and plaintext dispatch under
// the invariant that the caller is the sole sequential RX owner for op's Peer.
//
// This compatibility helper materializes a pointer ACK operation only when one
// is requested. The owned engine uses commitInboundOwnedInto and keeps ACK
// metadata in caller-provided storage.
func (c *Core) commitInboundOwned(
	op *InboundOperation,
	emitControlResponse bool,
) (dataplane.InboundPacket, *OutboundOperation, error) {
	var outbound OutboundOperation
	inbound, hasOutbound, err := c.commitInboundOwnedInto(
		op,
		emitControlResponse,
		&outbound,
	)
	if err != nil || !hasOutbound {
		return inbound, nil, err
	}
	return inbound, &outbound, nil
}

// commitInboundOwnedInto is the allocation-free ordered RX commit primitive.
// outbound is reset before use and is valid only when hasOutbound is true.
func (c *Core) commitInboundOwnedInto(
	op *InboundOperation,
	emitControlResponse bool,
	outbound *OutboundOperation,
) (inbound dataplane.InboundPacket, hasOutbound bool, err error) {
	if outbound == nil {
		return inbound, false, fmt.Errorf("nil outbound result storage: %w", dataplane.ErrInvalidConfig)
	}
	*outbound = OutboundOperation{}

	if op == nil || op.admission.Session == nil || op.binding.peer == nil {
		return inbound, false, ErrSessionNotRXEligible
	}
	if op.plaintext == nil {
		return inbound, false, dataplane.ErrAuthentication
	}

	result, err := op.binding.peer.commitAuthenticatedRXOwned(
		op.admission,
		op.sequence,
		op.source,
		c.now(),
	)
	if err != nil {
		return inbound, false, err
	}
	if result.retiredPrevious != nil {
		c.removeSessionIfMatch(op.binding.peer, result.retiredPrevious)
	}

	plaintext := op.plaintext
	if len(plaintext) == 0 {
		return inbound, false, dataplane.ErrInvalidPlaintext
	}

	if plaintext[0] == 0x00 {
		control, err := dataplane.ParseControl(plaintext)
		if err != nil {
			return inbound, false, err
		}
		if control.Type != dataplane.ControlKeepalive {
			return inbound, false, ErrUnexpectedControl
		}

		inbound = dataplane.InboundPacket{
			Kind:        dataplane.InboundKeepalive,
			KeepaliveID: control.KeepaliveID,
		}
		if !emitControlResponse || !result.AllowSameSessionResponse {
			return inbound, false, nil
		}

		// ACK is a new TX operation under the exact Session that authenticated the
		// KEEPALIVE. It never re-reads Peer.current or Session.endpoint.
		sequence, err := op.admission.Session.ReserveTXSequence()
		if err != nil {
			return inbound, false, err
		}

		ackMinWireSize := dataplane.MinControlWirePacketSize
		ackMaxWireSize := op.requestWireSize
		if control.KeepaliveID == 0 {
			if ackMaxWireSize > dataplane.MaxGeneratedEstablishmentWirePacketSize {
				ackMaxWireSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
			}
			ackMinWireSize = dataplane.MinGeneratedEstablishmentWirePacketSize
			if ackMinWireSize > ackMaxWireSize {
				ackMinWireSize = ackMaxWireSize
			}
		}

		*outbound = OutboundOperation{
			peer:           op.binding.peer,
			session:        op.admission.Session,
			sequence:       sequence,
			destination:    op.source,
			ackKeepaliveID: control.KeepaliveID,
			ackMinWireSize: ackMinWireSize,
			ackMaxWireSize: ackMaxWireSize,
		}
		return inbound, true, nil
	}

	inner, header, err := dataplane.ParseDataIPv4(
		plaintext,
		c.maxInnerPacketSize,
	)
	if err != nil {
		return inbound, false, err
	}
	if header.Source != op.binding.tunnelIPv4 {
		return inbound, false, ErrUnauthorizedSource
	}

	return dataplane.InboundPacket{
		Kind: dataplane.InboundIPv4,
		IPv4: inner,
	}, false, nil
}

// AdmitInnerPacket validates one server-side TUN packet and creates the complete
// outbound DATA operation before encryption starts.
func (c *Core) AdmitInnerPacket(
	packet []byte,
	outputCapacity int,
) (*OutboundOperation, error) {
	op := new(OutboundOperation)
	if err := c.AdmitInnerPacketInto(op, packet, outputCapacity); err != nil {
		return nil, err
	}
	return op, nil
}

// AdmitInnerPacketInto is the allocation-free TX admission variant used by the
// asynchronous runtime. The caller owns op until it is copied into TXEngine. On
// error op is reset to its zero value.
func (c *Core) AdmitInnerPacketInto(
	op *OutboundOperation,
	packet []byte,
	outputCapacity int,
) error {
	if op == nil {
		return fmt.Errorf("nil outbound operation: %w", dataplane.ErrInvalidConfig)
	}
	*op = OutboundOperation{}

	header, err := dataplane.ParseTunIPv4(packet, c.maxInnerPacketSize)
	if err != nil {
		return err
	}

	peer := c.lookupPeer(header.Destination)
	if peer == nil {
		return ErrUnauthorizedDestination
	}

	// Validate caller/runtime storage before sequence reservation. A fixed-size
	// packet pool can satisfy this by construction.
	if outputCapacity < len(packet)+dataplane.MaxDataExpansion {
		return dataplane.ErrBufferTooSmall
	}

	admission, err := peer.AdmitCurrentData(c.now())
	if err != nil {
		return err
	}

	*op = OutboundOperation{
		peer:        peer,
		session:     admission.Session,
		sequence:    admission.Sequence,
		destination: admission.Destination,
		data:        packet,
	}
	return nil
}

func (c *Core) maxWirePacketSize() int {
	maxWireSize := c.maxInnerPacketSize + dataplane.MaxDataExpansion
	if maxWireSize < dataplane.MaxGeneratedEstablishmentWirePacketSize {
		maxWireSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}
	return maxWireSize
}
