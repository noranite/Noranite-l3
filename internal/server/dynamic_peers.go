package server

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// ErrPeerRevoked is an expected control-plane race, not a fatal dataplane error.
var ErrPeerRevoked = errors.New("peer was removed")
var ErrPeerAlreadyExists = errors.New("peer already exists")

// PeerForIP returns the exact peer object, including its identity. A stale
// handshake must never locate a replacement peer by looking up an IP again.
func (c *Core) PeerForIP(ip netip.Addr) *Peer { return c.lookupPeer(ip) }

// HasPeers reports whether the live peer registry is non-empty. It is intended
// for construction-time validation of components that require exclusive
// ownership of peer mutations.
func (c *Core) HasPeers() bool {
	snapshot := c.peerSnapshots.Load()
	return snapshot != nil && len(*snapshot) != 0
}

// PreparePeer constructs a detached peer. Callers register its identity with
// RX/TX engines before publishing it to Core and Noise.
func (c *Core) PreparePeer() (*Peer, error) {
	return newPeerAt(nil, c.lifecycle, c.now())
}

// PublishPeer has no I/O and no allocation of per-peer worker resources.
// The control plane serializes administrative operations and validates first.
func (c *Core) PublishPeer(ip netip.Addr, peer *Peer) error {
	ip = ip.Unmap()
	if err := ValidateTunnelIPv4(ip); err != nil {
		return err
	}
	if peer == nil || peer.IsRevoked() {
		return fmt.Errorf("invalid peer: %w", dataplane.ErrInvalidConfig)
	}
	c.peerEditMu.Lock()
	defer c.peerEditMu.Unlock()
	old := c.peerSnapshots.Load()
	next := make(map[netip.Addr]*Peer, len(*old)+1)
	for address, p := range *old {
		next[address] = p
	}
	if _, exists := next[ip]; exists {
		return ErrPeerAlreadyExists
	}
	next[ip] = peer
	c.peerSnapshots.Store(&next)
	return nil
}

// RevokePeer invalidates the registry identity and all session IDs. Operations
// already admitted into a worker may finish using their retained pointers.
func (c *Core) RevokePeer(ip netip.Addr, expected *Peer) error {
	ip = ip.Unmap()
	c.peerEditMu.Lock()
	defer c.peerEditMu.Unlock()
	old := c.peerSnapshots.Load()
	if expected == nil || (*old)[ip] != expected {
		return ErrPeerRevoked
	}

	// Lock order: sessionsMu -> Peer.mu. The rekey path uses the same order.
	c.sessionsMu.Lock()
	expected.revoke()
	for id, binding := range c.sessionsByID {
		if binding.peer == expected {
			delete(c.sessionsByID, id)
		}
	}
	next := make(map[netip.Addr]*Peer, len(*old)-1)
	for address, p := range *old {
		if address != ip {
			next[address] = p
		}
	}
	c.peerSnapshots.Store(&next)
	c.sessionsMu.Unlock()
	return nil
}

// InstallPendingSessionForPeer pins establishment to the *exact* authenticated
// peer, not merely its IP. This prevents stale INIT(A) from resurrecting after
// Remove(A) + Add(B) on the same address.
func (c *Core) InstallPendingSessionForPeer(
	ip netip.Addr, expected *Peer, session *dataplane.Session,
) error {
	ip = ip.Unmap()
	if session == nil {
		return fmt.Errorf("nil session: %w", dataplane.ErrInvalidConfig)
	}
	if expected == nil {
		return ErrPeerRevoked
	}

	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.lookupPeer(ip) != expected || expected.IsRevoked() {
		return ErrPeerRevoked
	}
	if !c.sessionIDAvailableLocked(session.ID()) {
		return ErrSessionIDCollision
	}
	transition, err := expected.installPending(session, c.now())
	if err != nil {
		return err
	}
	c.removeSessionLocked(expected, transition.retiredPending)
	c.removeSessionLocked(expected, transition.retiredPrevious)
	c.sessionsByID[session.ID()] = sessionBinding{
		peer: expected, tunnelIPv4: ip, session: transition.installed,
	}
	return nil
}
