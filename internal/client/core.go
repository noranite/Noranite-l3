package client

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// Config describes one fixed-role client Peer.
//
// Session is the optional initial current traffic generation. Production
// establishment may construct Core without it and install the first generation
// later through InstallInitiatorSession.
type Config struct {
	RouteKey [32]byte

	TunnelIPv4     netip.Addr
	ServerEndpoint netip.AddrPort

	MaxInnerPacketSize int
	Lifecycle          LifecycleConfig

	Session *dataplane.Session
}

// Core contains client routing/authorization policy and exactly one fixed-role
// Peer lifecycle. It performs no socket or TUN I/O.
type Core struct {
	routeKey [32]byte

	tunnelIPv4     netip.Addr
	serverEndpoint netip.AddrPort

	maxInnerPacketSize int
	peer               *Peer

	// now exists only to make admission/deadline tests deterministic without
	// sleeping. Production construction always uses time.Now.
	now func() time.Time
}

func New(config Config) (*Core, error) {
	if !config.TunnelIPv4.IsValid() || !config.TunnelIPv4.Is4() {
		return nil, fmt.Errorf(
			"client tunnel address must be IPv4: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	if !config.ServerEndpoint.IsValid() ||
		!config.ServerEndpoint.Addr().Is4() ||
		config.ServerEndpoint.Port() == 0 {
		return nil, fmt.Errorf(
			"server endpoint must be valid IPv4 UDP endpoint: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	if config.MaxInnerPacketSize < dataplane.MinTunnelMTU || config.MaxInnerPacketSize > dataplane.MaxTunnelMTU {
		return nil, fmt.Errorf(
			"max inner packet size %d must be in [%d, %d]: %w",
			config.MaxInnerPacketSize,
			dataplane.MinTunnelMTU,
			dataplane.MaxTunnelMTU,
			dataplane.ErrInvalidConfig,
		)
	}

	now := time.Now
	peer, err := NewPeer(config.Session, config.Lifecycle, now())
	if err != nil {
		return nil, err
	}

	return &Core{
		routeKey:           config.RouteKey,
		tunnelIPv4:         config.TunnelIPv4,
		serverEndpoint:     config.ServerEndpoint,
		maxInnerPacketSize: config.MaxInnerPacketSize,
		peer:               peer,
		now:                now,
	}, nil
}

// HandleInnerPacketTo is the synchronous surface over the TX admission and
// sealing boundary.
func (c *Core) HandleInnerPacketTo(
	scratch *dataplane.DataScratch,
	dst []byte,
	packet []byte,
) (wire []byte, destination netip.AddrPort, err error) {
	op, err := c.AdmitInnerPacket(packet, cap(dst))
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	wire, err = op.SealTo(scratch, dst)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return wire, op.Destination(), nil
}

// HandleKeepaliveTo creates one encrypted client -> server KEEPALIVE through the same
// TX admission boundary as ordinary DATA.
func (c *Core) HandleKeepaliveTo(
	scratch *dataplane.DataScratch,
	dst []byte,
	keepaliveID uint64,
) (wire []byte, destination netip.AddrPort, err error) {
	op, err := c.AdmitKeepalive(keepaliveID, cap(dst))
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	wire, err = op.SealTo(scratch, dst)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return wire, op.Destination(), nil
}

// HandleKeepaliveToWithPadding is the deterministic variant used by protocol tests.
func (c *Core) HandleKeepaliveToWithPadding(
	scratch *dataplane.DataScratch,
	dst []byte,
	keepaliveID uint64,
	paddingLength int,
) (wire []byte, destination netip.AddrPort, err error) {
	op, err := c.AdmitKeepaliveWithPadding(keepaliveID, paddingLength, cap(dst))
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	wire, err = op.SealTo(scratch, dst)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return wire, op.Destination(), nil
}

// HandleDatagramInPlace is the DATA-only compatibility surface. Authenticated
// ACK is consumed and returns (nil, nil); callers that need the CONTROL event
// use HandleNetworkDatagramInPlace.
func (c *Core) HandleDatagramInPlace(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
) ([]byte, error) {
	inbound, _, _, err := c.HandleNetworkDatagramInPlace(
		scratch,
		source,
		packet,
	)
	if err != nil {
		return nil, err
	}
	if inbound.Kind != dataplane.InboundIPv4 {
		return nil, nil
	}
	return inbound.IPv4, nil
}

// HandleNetworkDatagramInPlace is the synchronous compatibility RX surface.
// Client never creates an immediate response: v1 ACK is server -> client only.
func (c *Core) HandleNetworkDatagramInPlace(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
) (
	inbound dataplane.InboundPacket,
	response []byte,
	responseDestination netip.AddrPort,
	err error,
) {
	op, err := c.AdmitNetworkDatagram(scratch, source, packet)
	if err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}

	if err := op.Decrypt(scratch); err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}

	inbound, err = c.CommitInbound(op)
	if err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}
	return inbound, nil, netip.AddrPort{}, nil
}

// InstallInitiatorSession makes a freshly established initiator generation
// current immediately and moves the old current to previous.
func (c *Core) InstallInitiatorSession(session *dataplane.Session) (*dataplane.Session, error) {
	return c.peer.InstallInitiatorSession(session, c.now())
}

// Session exposes the current traffic generation for compatibility with older
// tests/diagnostics. Packet TX must use admission APIs instead.
func (c *Core) Session() *dataplane.Session {
	return c.peer.CurrentSession()
}

func (c *Core) ServerEndpoint() netip.AddrPort {
	return c.serverEndpoint
}

func (c *Core) TunnelIPv4() netip.Addr {
	return c.tunnelIPv4
}

func (c *Core) NewDataScratch() (*dataplane.DataScratch, error) {
	return dataplane.NewDataScratch(c.routeKey)
}

func (c *Core) maxWirePacketSize() int {
	maxWireSize := c.maxInnerPacketSize + dataplane.MaxDataExpansion
	if maxWireSize < dataplane.MaxGeneratedEstablishmentWirePacketSize {
		maxWireSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}
	return maxWireSize
}
