package client

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// InboundOperation is one client RX packet after opaque route decode and
// lifecycle admission, but before expensive AEAD.
//
// The operation pins the exact traffic generation selected at ingress. A later
// InstallInitiatorSession cannot retarget or cancel it.
type InboundOperation struct {
	peer      *Peer
	admission RXAdmission

	sequence uint64
	source   netip.AddrPort
	packet   []byte

	plaintext []byte
}

// Decrypt performs only parallel-safe crypto work. Mutable replay/lifecycle
// state is committed later by the one ordered RX owner for this Peer.
func (op *InboundOperation) Decrypt(scratch *dataplane.DataScratch) error {
	if op == nil || op.admission.Session == nil {
		return ErrSessionNotRXEligible
	}

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

type outboundKind uint8

const (
	outboundData outboundKind = iota + 1
	outboundKeepalive
)

// OutboundOperation is one client TX packet after generation selection,
// destination snapshot and sequence reservation.
//
// Ownership contract: an admitted operation is a single-use sequence
// reservation. A value copy is valid only as a move-style ownership transfer.
// Independently using multiple copies reuses the same (Session, sequence)
// reservation and can reuse an AEAD nonce. SealTo must be called at most once
// for one admitted operation; retry after encryption/transport failure starts
// with a fresh admission and sequence.
type OutboundOperation struct {
	peer        *Peer
	session     *dataplane.Session
	sequence    uint64
	destination netip.AddrPort
	kind        outboundKind

	data []byte

	keepaliveID      uint64
	keepalivePadding int
	explicitPadding  bool
}

func (op *OutboundOperation) Destination() netip.AddrPort {
	if op == nil {
		return netip.AddrPort{}
	}
	return op.destination
}

func (op *OutboundOperation) Sequence() uint64 {
	if op == nil {
		return 0
	}
	return op.sequence
}

func (op *OutboundOperation) Session() *dataplane.Session {
	if op == nil {
		return nil
	}
	return op.session
}

// MaxWireSize returns the capacity required for any valid sealing result of the
// already-admitted operation.
func (op *OutboundOperation) MaxWireSize() int {
	if op == nil {
		return 0
	}

	switch op.kind {
	case outboundData:
		return len(op.data) + dataplane.MaxDataExpansion
	case outboundKeepalive:
		if op.explicitPadding {
			return dataplane.MinControlWirePacketSize + op.keepalivePadding
		}
		if op.keepaliveID == 0 {
			return dataplane.MaxGeneratedEstablishmentWirePacketSize
		}
		return dataplane.MaxGeneratedControlWirePacketSize
	default:
		return 0
	}
}

// SealTo is the parallel-safe TX worker body. It never re-reads Peer lifecycle
// state: Session, sequence and destination were fixed at admission.
func (op *OutboundOperation) SealTo(
	scratch *dataplane.DataScratch,
	dst []byte,
) ([]byte, error) {
	if op == nil || op.session == nil {
		return nil, fmt.Errorf("nil outbound operation: %w", dataplane.ErrInvalidConfig)
	}

	switch op.kind {
	case outboundData:
		return op.session.SealDataToReserved(
			scratch,
			dst,
			op.data,
			op.sequence,
		)
	case outboundKeepalive:
		if op.explicitPadding {
			return op.session.SealKeepaliveToWithPaddingReserved(
				scratch,
				dst,
				op.keepaliveID,
				op.keepalivePadding,
				op.sequence,
			)
		}
		if op.keepaliveID == 0 {
			return op.session.SealKeepaliveToRangeReserved(
				scratch,
				dst,
				op.keepaliveID,
				dataplane.MinGeneratedEstablishmentWirePacketSize,
				dataplane.MaxGeneratedEstablishmentWirePacketSize,
				op.sequence,
			)
		}
		return op.session.SealKeepaliveToReserved(
			scratch,
			dst,
			op.keepaliveID,
			op.sequence,
		)
	default:
		return nil, fmt.Errorf("unknown outbound operation kind: %w", dataplane.ErrInvalidConfig)
	}
}

// AdmitNetworkDatagram performs client RX ingress admission before AEAD:
// bounds -> source metadata validation -> opaque route decode -> lifecycle
// lookup/admission. receivedAt is captured before those steps so local queueing
// can never extend generation lifetime.
func (c *Core) AdmitNetworkDatagram(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
) (*InboundOperation, error) {
	return c.AdmitNetworkDatagramAt(scratch, source, packet, c.now())
}

// AdmitNetworkDatagramAt is the runtime-facing RX admission variant for callers
// that captured ingress time before an outer protocol demultiplexer. This keeps
// generation deadlines tied to network arrival rather than control-plane
// classification latency.
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

// AdmitNetworkDatagramRouteAtInto is the allocation-free admission variant
// used by the asynchronous runtime. The caller owns op until it is copied into
// RXEngine. On error op is reset to its zero value.
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

	admission, err := c.peer.AdmitRX(route.SessionID, receivedAt)
	if err != nil {
		return err
	}

	*op = InboundOperation{
		peer:      c.peer,
		admission: admission,
		sequence:  route.Sequence,
		source:    source,
		packet:    packet,
	}
	return nil
}

// CommitInbound is the synchronous compatibility surface. Async RXEngine owns
// the same boundary structurally and calls commitInboundOwned from its one
// sequential consumer instead of taking rxCompatMu.
func (c *Core) CommitInbound(op *InboundOperation) (dataplane.InboundPacket, error) {
	var inbound dataplane.InboundPacket
	if op == nil || op.peer != c.peer || op.admission.Session == nil {
		return inbound, ErrSessionNotRXEligible
	}

	c.peer.rxCompatMu.Lock()
	defer c.peer.rxCompatMu.Unlock()
	return c.commitInboundOwned(op)
}

func (c *Core) commitInboundOwned(op *InboundOperation) (dataplane.InboundPacket, error) {
	var inbound dataplane.InboundPacket
	if op == nil || op.peer != c.peer || op.admission.Session == nil {
		return inbound, ErrSessionNotRXEligible
	}
	if op.plaintext == nil {
		return inbound, dataplane.ErrAuthentication
	}

	// Replay commit and lifecycle evidence happen before plaintext grammar. An
	// authenticated replay-valid malformed packet still proves possession of the
	// exact current generation.
	if _, err := c.peer.commitAuthenticatedRXOwned(
		op.admission,
		op.sequence,
		op.source,
	); err != nil {
		return inbound, err
	}

	plaintext := op.plaintext
	if len(plaintext) == 0 {
		return inbound, dataplane.ErrInvalidPlaintext
	}

	if plaintext[0] == 0x00 {
		control, err := dataplane.ParseControl(plaintext)
		if err != nil {
			return inbound, err
		}
		if control.Type != dataplane.ControlACK {
			return inbound, ErrUnexpectedControl
		}
		return dataplane.InboundPacket{
			Kind:        dataplane.InboundACK,
			KeepaliveID: control.KeepaliveID,
		}, nil
	}

	inner, header, err := dataplane.ParseDataIPv4(
		plaintext,
		c.maxInnerPacketSize,
	)
	if err != nil {
		return inbound, err
	}
	if header.Destination != c.tunnelIPv4 {
		return inbound, ErrUnauthorizedDestination
	}

	return dataplane.InboundPacket{
		Kind: dataplane.InboundIPv4,
		IPv4: inner,
	}, nil
}

// AdmitInnerPacket validates one client-side TUN packet and captures the exact
// current generation before encryption begins.
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
	if header.Source != c.tunnelIPv4 {
		return ErrUnauthorizedSource
	}

	// Caller-local errors must be rejected before sequence reservation.
	if outputCapacity < len(packet)+dataplane.MaxDataExpansion {
		return dataplane.ErrBufferTooSmall
	}

	admission, err := c.peer.AdmitCurrentTX(c.now())
	if err != nil {
		return err
	}

	*op = OutboundOperation{
		peer:        c.peer,
		session:     admission.Session,
		sequence:    admission.Sequence,
		destination: c.serverEndpoint,
		kind:        outboundData,
		data:        packet,
	}
	return nil
}

// AdmitKeepalive creates a random-padding KEEPALIVE operation. keepaliveID zero
// is the establishment activation marker and uses the wider establishment wire
// range; non-zero IDs use the ordinary CONTROL sender policy. Storage capacity
// is checked before sequence reservation.
func (c *Core) AdmitKeepalive(
	keepaliveID uint64,
	outputCapacity int,
) (*OutboundOperation, error) {
	requiredCapacity := dataplane.MaxGeneratedControlWirePacketSize
	if keepaliveID == 0 {
		requiredCapacity = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}
	if outputCapacity < requiredCapacity {
		return nil, dataplane.ErrBufferTooSmall
	}

	admission, err := c.peer.AdmitCurrentTX(c.now())
	if err != nil {
		return nil, err
	}

	return &OutboundOperation{
		peer:        c.peer,
		session:     admission.Session,
		sequence:    admission.Sequence,
		destination: c.serverEndpoint,
		kind:        outboundKeepalive,
		keepaliveID: keepaliveID,
	}, nil
}

// AdmitKeepaliveWithPadding is the deterministic test/policy variant.
func (c *Core) AdmitKeepaliveWithPadding(
	keepaliveID uint64,
	paddingLength int,
	outputCapacity int,
) (*OutboundOperation, error) {
	if paddingLength < 0 {
		return nil, dataplane.ErrInvalidPadding
	}
	if outputCapacity < dataplane.MinControlWirePacketSize ||
		paddingLength > outputCapacity-dataplane.MinControlWirePacketSize {
		return nil, dataplane.ErrBufferTooSmall
	}

	admission, err := c.peer.AdmitCurrentTX(c.now())
	if err != nil {
		return nil, err
	}

	return &OutboundOperation{
		peer:             c.peer,
		session:          admission.Session,
		sequence:         admission.Sequence,
		destination:      c.serverEndpoint,
		kind:             outboundKeepalive,
		keepaliveID:      keepaliveID,
		keepalivePadding: paddingLength,
		explicitPadding:  true,
	}, nil
}
