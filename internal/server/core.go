package server

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// PeerConfig describes one statically configured server Peer.
//
// TunnelIPv4 is the exact inner IPv4 identity authorized for this Peer.
// InitialSession is optional: a production server may start a Peer without a
// Session and install the first pending Session after handshake.
type PeerConfig struct {
	TunnelIPv4     netip.Addr
	InitialSession *dataplane.Session
}

// Config describes one server runtime.
//
// K_route is runtime-wide, therefore all Peers share the same RouteKey and the
// same sessionsByID index. Lifecycle policy is also runtime policy in this
// implementation; DATA/CONTROL wire semantics do not depend on these values.
type Config struct {
	RouteKey           [32]byte
	MaxInnerPacketSize int
	Lifecycle          LifecycleConfig
	Peers              []PeerConfig
}

// sessionBinding is one immutable entry of the global RX index.
//
// The map answers only one question: which configured Peer owns this numeric
// session_id and which dataplane Session can authenticate it? Lifecycle truth
// remains in Peer.pending/current/previous and is consulted by RX admission
// before AEAD work is handed to the decrypt path.
type sessionBinding struct {
	peer       *Peer
	tunnelIPv4 netip.Addr
	session    *dataplane.Session
}

// Core contains server routing, authorization and multi-Peer runtime indexes.
// It performs no socket or TUN I/O.
type Core struct {
	routeKey           [32]byte
	maxInnerPacketSize int
	// sessionsMu protects the mutable global RX index only. It is intentionally
	// NOT held during AEAD, replay commit or DATA encryption.
	//
	// sessionsByID is an accelerator/ownership registry, not lifecycle truth:
	// Peer slots remain authoritative for pending/current/grace eligibility.
	sessionsMu sync.RWMutex

	// RX path:
	//
	//	opaque route
	//	-> session_id
	//	-> O(1) sessionsByID lookup
	//	-> Peer lifecycle admission
	sessionsByID map[uint64]sessionBinding

	// TX path:
	//
	//	inner IPv4 destination
	//	-> exact O(1) tunnel IPv4 lookup
	//	-> Peer current Session
	//
	// This map is immutable after New returns, so concurrent readers need no
	// global lock. Peer owns synchronization for its mutable lifecycle state.
	peersByTunnelIPv4 map[netip.Addr]*Peer

	// now exists only to make lifecycle boundary tests deterministic without
	// sleeping. Production construction always uses time.Now.
	now func() time.Time
}

func New(config Config) (*Core, error) {
	if config.MaxInnerPacketSize < dataplane.MinTunnelMTU || config.MaxInnerPacketSize > dataplane.MaxTunnelMTU {
		return nil, fmt.Errorf(
			"max inner packet size %d must be in [%d, %d]: %w",
			config.MaxInnerPacketSize,
			dataplane.MinTunnelMTU,
			dataplane.MaxTunnelMTU,
			dataplane.ErrInvalidConfig,
		)
	}
	if err := config.Lifecycle.validate(); err != nil {
		return nil, err
	}
	if len(config.Peers) == 0 {
		return nil, fmt.Errorf(
			"server must configure at least one peer: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	core := &Core{
		routeKey:           config.RouteKey,
		maxInnerPacketSize: config.MaxInnerPacketSize,
		sessionsByID:       make(map[uint64]sessionBinding, len(config.Peers)),
		peersByTunnelIPv4:  make(map[netip.Addr]*Peer, len(config.Peers)),
		now:                time.Now,
	}

	for i, peerConfig := range config.Peers {
		if !peerConfig.TunnelIPv4.IsValid() || !peerConfig.TunnelIPv4.Is4() {
			return nil, fmt.Errorf(
				"peer %d tunnel address must be IPv4: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if _, exists := core.peersByTunnelIPv4[peerConfig.TunnelIPv4]; exists {
			return nil, fmt.Errorf(
				"duplicate peer tunnel IPv4 %s: %w",
				peerConfig.TunnelIPv4,
				dataplane.ErrInvalidConfig,
			)
		}

		peer, err := newPeerAt(
			peerConfig.InitialSession,
			config.Lifecycle,
			core.now(),
		)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", peerConfig.TunnelIPv4, err)
		}

		core.peersByTunnelIPv4[peerConfig.TunnelIPv4] = peer

		if peerConfig.InitialSession == nil {
			continue
		}

		id := peerConfig.InitialSession.ID()
		if _, exists := core.sessionsByID[id]; exists {
			return nil, fmt.Errorf(
				"initial session %#x: %w",
				id,
				ErrSessionIDCollision,
			)
		}

		core.sessionsByID[id] = sessionBinding{
			peer:       peer,
			tunnelIPv4: peerConfig.TunnelIPv4,
			session:    peerConfig.InitialSession,
		}
	}

	return core, nil
}

// HandleDatagramInPlace is the DATA-only compatibility surface used by the
// existing core tests and simple callers.
//
// Authenticated CONTROL is still parsed and committed, but this method does not
// create a network response. Production UDP runtime uses
// HandleNetworkDatagramInPlace so a valid KEEPALIVE can produce its bounded ACK.
func (c *Core) HandleDatagramInPlace(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
) ([]byte, error) {
	inbound, _, _, err := c.handleDatagramInPlace(
		scratch,
		source,
		packet,
		false,
	)
	if err != nil {
		return nil, err
	}
	if inbound.Kind != dataplane.InboundIPv4 {
		return nil, nil
	}
	return inbound.IPv4, nil
}

// HandleNetworkDatagramInPlace is the full UDP receive surface.
//
// For IPv4 DATA it returns inbound.Kind == InboundIPv4 and no response.
// For accepted KEEPALIVE it returns InboundKeepalive plus an encrypted ACK through the
// same authenticated Session. ACK is a response to that KEEPALIVE, not ordinary
// current-Session TX.
// For ACK on the server role it returns ErrUnexpectedControl.
//
// response may alias packet: CONTROL is fully parsed before ACK encryption
// overwrites the reusable UDP receive buffer.
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
	return c.handleDatagramInPlace(
		scratch,
		source,
		packet,
		true,
	)
}

func (c *Core) handleDatagramInPlace(
	scratch *dataplane.DataScratch,
	source netip.AddrPort,
	packet []byte,
	emitControlResponse bool,
) (
	inbound dataplane.InboundPacket,
	response []byte,
	responseDestination netip.AddrPort,
	err error,
) {
	// Keep the synchronous path on the same admission, crypto, and commit
	// boundaries as the worker runtime.
	op, err := c.AdmitNetworkDatagram(
		scratch,
		source,
		packet,
	)
	if err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}

	if err := op.Decrypt(scratch); err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}

	inbound, outbound, err := c.CommitInbound(op, emitControlResponse)
	if err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}
	if outbound == nil {
		return inbound, nil, netip.AddrPort{}, nil
	}

	// CONTROL is fully parsed, so the synchronous path may reuse the receive
	// buffer for the ACK.
	response, err = outbound.SealTo(scratch, packet[:0])
	if err != nil {
		return inbound, nil, netip.AddrPort{}, err
	}

	return inbound, response, outbound.Destination(), nil
}

// HandleInnerPacketTo processes one IPv4 packet from the server-side TUN and
// writes a ready UDP payload into dst.
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

// CurrentSession exposes a peer's current session for diagnostics and tests.
func (c *Core) CurrentSession(tunnelIPv4 netip.Addr) *dataplane.Session {
	peer := c.lookupPeer(tunnelIPv4)
	if peer == nil {
		return nil
	}
	return peer.CurrentSession()
}

// HasPeer reports whether tunnelIPv4 names one statically configured Peer.
//
// The peer map is immutable after Core construction, so this is a cheap
// lock-free configuration validation hook for establishment providers. It does
// not expose lifecycle state and does not make Core aware of handshake
// credentials.
func (c *Core) HasPeer(tunnelIPv4 netip.Addr) bool {
	return c.lookupPeer(tunnelIPv4) != nil
}

// InstallPendingSession hands fresh session material from establishment to a
// configured peer.
//
// Freshness ordering belongs to the establishment layer. Core intentionally
// does not know handshake epochs/nonces, so a caller must never let a delayed
// older establishment completion invoke this method after a newer generation
// has already been accepted for the same Peer. A successful call is treated as
// the freshest authoritative pending generation and may supersede the previous
// pending slot.
//
// Global session_id collision checking and Peer pending replacement happen
// before the method returns, so a successful handshake response can expose the
// new session_id only after the RX index is ready.
func (c *Core) InstallPendingSession(
	tunnelIPv4 netip.Addr,
	session *dataplane.Session,
) error {
	if session == nil {
		return fmt.Errorf(
			"pending session is nil: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	// peersByTunnelIPv4 is immutable after Core construction, so this lookup
	// does not contend with packet RX/TX on a global lock.
	peer := c.peersByTunnelIPv4[tunnelIPv4]
	if peer == nil {
		return fmt.Errorf("peer %s: %w", tunnelIPv4, ErrUnknownPeer)
	}

	// sessionsMu serializes global collision checks with insertion/removal.
	// It may nest into Peer.mu here. No receive/TX path holds Peer.mu while
	// acquiring sessionsMu, so this lock order has no reverse edge.
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()

	id := session.ID()
	now := c.now()
	if !c.sessionIDAvailableLocked(id) {
		return ErrSessionIDCollision
	}

	transition, err := peer.installPending(
		session,
		now,
	)
	if err != nil {
		return err
	}

	// installPending can drop an expired previous and always supersedes an older
	// pending. Remove those exact bindings before publishing the new one.
	c.removeSessionLocked(peer, transition.retiredPending)
	c.removeSessionLocked(peer, transition.retiredPrevious)

	c.sessionsByID[id] = sessionBinding{
		peer:       peer,
		tunnelIPv4: tunnelIPv4,
		session:    transition.installed,
	}

	return nil
}

// NewDataScratch creates worker-local DATA scratch keyed with the server's
// runtime K_route.
func (c *Core) NewDataScratch() (*dataplane.DataScratch, error) {
	return dataplane.NewDataScratch(c.routeKey)
}

func (c *Core) lookupPeer(tunnelIPv4 netip.Addr) *Peer {
	// peersByTunnelIPv4 is immutable after New returns. Concurrent map reads are
	// safe as long as no goroutine mutates the map, which Core never does.
	return c.peersByTunnelIPv4[tunnelIPv4]
}

func (c *Core) lookupRXBinding(sessionID uint64) (sessionBinding, bool) {
	c.sessionsMu.RLock()
	binding, ok := c.sessionsByID[sessionID]
	c.sessionsMu.RUnlock()
	return binding, ok
}

// sessionIDAvailableLocked checks collision against lifecycle-slot residency,
// not instantaneous RX eligibility.
//
// An expired pending/previous Session still blocks numeric ID reuse while it
// occupies a Peer slot. An operation admitted before its deadline may still
// complete after the deadline, and pending may still promote. Reusing the ID
// before actual retirement would make the global RX index ambiguous/stale.
//
// Caller holds sessionsMu for writing. The helper may briefly read Peer slots;
// no path holds Peer.mu while waiting for sessionsMu.
func (c *Core) sessionIDAvailableLocked(sessionID uint64) bool {
	binding, exists := c.sessionsByID[sessionID]
	if !exists {
		return true
	}

	if binding.peer.hasSession(binding.session) {
		return false
	}

	// A binding whose exact Session no longer occupies any lifecycle slot is stale
	// and can be reclaimed. Normal lifecycle transitions remove it eagerly; this
	// branch is defense in depth for the cold install path.
	delete(c.sessionsByID, sessionID)
	return true
}

func (c *Core) removeSessionIfMatch(peer *Peer, session *dataplane.Session) {
	if session == nil {
		return
	}

	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	c.removeSessionLocked(peer, session)
}

// removeSessionLocked deletes only the exact Peer+Session binding. Numeric IDs
// may eventually be reused, so deleting by ID alone after an asynchronous
// lifecycle transition would be incorrect.
func (c *Core) removeSessionLocked(peer *Peer, session *dataplane.Session) {
	if session == nil {
		return
	}

	current, ok := c.sessionsByID[session.ID()]
	if !ok {
		return
	}
	if current.peer != peer || current.session != session {
		return
	}
	delete(c.sessionsByID, session.ID())
}
