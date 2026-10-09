package servercontrol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/noranite/Noranite-l3/internal/noisehandshake"
	"github.com/noranite/Noranite-l3/internal/server"
)

var (
	ErrPeerConflict     = errors.New("peer public key or tunnel IPv4 already in use")
	ErrControllerClosed = errors.New("peer controller is closed")
)

// Peer is the complete runtime configuration of one peer. It deliberately
// contains no provisioning metadata: names, address pools and private keys live
// outside the runtime control plane.
type Peer struct {
	TunnelIPv4 netip.Addr
	PublicKey  noisehandshake.PublicKey
}

type peerState struct {
	Peer
	corePeer *server.Peer
}

// Controller is the single mutation boundary for runtime peer state. It is the
// equivalent of a low-level interface configuration API: callers provide an
// already chosen tunnel address and the peer public identity. Persistence and
// provisioning are intentionally outside this type.
type Controller struct {
	mu     sync.Mutex
	closed bool

	core  *server.Core
	noise *noisehandshake.Server
	rx    *server.RXEngine
	tx    *server.TXEngine

	byKey map[noisehandshake.PublicKey]*peerState
	byIP  map[netip.Addr]*peerState
}

func NewController(
	core *server.Core,
	noise *noisehandshake.Server,
	rx *server.RXEngine,
	tx *server.TXEngine,
) (*Controller, error) {
	if core == nil || noise == nil || rx == nil || tx == nil {
		return nil, fmt.Errorf("peer controller dependency is nil")
	}
	if core.HasPeers() {
		return nil, fmt.Errorf("peer controller requires an empty server core")
	}
	return &Controller{
		core:  core,
		noise: noise,
		rx:    rx,
		tx:    tx,
		byKey: make(map[noisehandshake.PublicKey]*peerState),
		byIP:  make(map[netip.Addr]*peerState),
	}, nil
}

// SetPeer adds or replaces the runtime configuration for PublicKey. Repeating
// the same configuration is a no-op. Changing the address replaces the peer
// identity and therefore intentionally drops its active sessions.
//
// Replacement has one commit point: once Noise accepts the new binding, the
// Controller only moves forward. A failure while retiring the old Core identity
// is reported to the caller, but does not roll the authoritative binding back.
func (c *Controller) SetPeer(peer Peer) error {
	peer.TunnelIPv4 = peer.TunnelIPv4.Unmap()
	if err := server.ValidateTunnelIPv4(peer.TunnelIPv4); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrControllerClosed
	}

	existing := c.byKey[peer.PublicKey]
	if existing != nil && existing.TunnelIPv4 == peer.TunnelIPv4 {
		return nil
	}
	if owner := c.byIP[peer.TunnelIPv4]; owner != nil && owner != existing {
		return ErrPeerConflict
	}

	if existing == nil {
		return c.addPeerLocked(peer)
	}
	return c.replacePeerLocked(existing, peer)
}

func (c *Controller) addPeerLocked(peer Peer) error {
	if err := c.noise.ValidateAuthorizedPeer(peer.TunnelIPv4, peer.PublicKey); err != nil {
		return err
	}

	corePeer, err := c.stagePeerLocked(peer.TunnelIPv4)
	if err != nil {
		return err
	}
	if err := c.noise.AddAuthorizedPeer(peer.TunnelIPv4, peer.PublicKey, corePeer); err != nil {
		c.discardStagedPeerLocked(peer.TunnelIPv4, corePeer)
		return err
	}

	c.installPeerStateLocked(nil, peer, corePeer)
	return nil
}

func (c *Controller) replacePeerLocked(existing *peerState, peer Peer) error {
	corePeer, err := c.stagePeerLocked(peer.TunnelIPv4)
	if err != nil {
		return err
	}

	// This is the commit point. Before it, the replacement is only a staged Core
	// identity and can be discarded. After it, restoring the old Noise binding
	// would create a second transaction with its own failure modes, so cleanup is
	// deliberately forward-only.
	if err := c.noise.ReplaceAuthorizedPeer(
		peer.PublicKey,
		existing.corePeer,
		peer.TunnelIPv4,
		corePeer,
	); err != nil {
		c.discardStagedPeerLocked(peer.TunnelIPv4, corePeer)
		return err
	}

	// Administrative state follows the committed Noise binding before cleanup.
	// If cleanup unexpectedly fails, repeating SetPeer remains idempotent instead
	// of trying to reconstruct the previous configuration.
	c.installPeerStateLocked(existing, peer, corePeer)

	err = c.core.RevokePeer(existing.TunnelIPv4, existing.corePeer)
	c.retirePeerLocked(existing.corePeer)
	if err != nil {
		return fmt.Errorf("peer replacement committed; revoke previous Core peer: %w", err)
	}
	return nil
}

func (c *Controller) stagePeerLocked(ip netip.Addr) (*server.Peer, error) {
	corePeer, err := c.preparePeerLocked()
	if err != nil {
		return nil, err
	}
	if err := c.core.PublishPeer(ip, corePeer); err != nil {
		c.retirePeerLocked(corePeer)
		return nil, err
	}
	return corePeer, nil
}

// discardStagedPeerLocked is only used before the Noise commit point. The peer
// was published by this Controller while c.mu is held, so revoke failure would
// indicate an internal invariant violation; there is no useful rollback beyond
// best-effort removal of the staged identity.
func (c *Controller) discardStagedPeerLocked(ip netip.Addr, peer *server.Peer) {
	_ = c.core.RevokePeer(ip, peer)
	c.retirePeerLocked(peer)
}

func (c *Controller) installPeerStateLocked(previous *peerState, peer Peer, corePeer *server.Peer) {
	if previous != nil {
		delete(c.byIP, previous.TunnelIPv4)
	}
	state := &peerState{Peer: peer, corePeer: corePeer}
	c.byKey[peer.PublicKey] = state
	c.byIP[peer.TunnelIPv4] = state
}

func (c *Controller) preparePeerLocked() (*server.Peer, error) {
	peer, err := c.core.PreparePeer()
	if err != nil {
		return nil, err
	}
	if err := c.rx.AddPeer(peer); err != nil {
		return nil, err
	}
	if err := c.tx.AddPeer(peer); err != nil {
		c.rx.RetirePeer(peer)
		return nil, err
	}
	return peer, nil
}

func (c *Controller) retirePeerLocked(peer *server.Peer) {
	c.rx.RetirePeer(peer)
	c.tx.RetirePeer(peer)
}

// RemovePeer is idempotent. Operations admitted before revocation may still
// complete; removal only prevents future lookup/admission for this identity.
func (c *Controller) RemovePeer(key noisehandshake.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrControllerClosed
	}

	state, ok := c.byKey[key]
	if !ok {
		return nil
	}
	if err := c.core.RevokePeer(state.TunnelIPv4, state.corePeer); err != nil {
		return err
	}
	c.noise.RemoveAuthorizedPeer(key)
	c.retirePeerLocked(state.corePeer)
	delete(c.byKey, key)
	delete(c.byIP, state.TunnelIPv4)
	return nil
}

func (c *Controller) ListPeers() ([]Peer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrControllerClosed
	}

	peers := make([]Peer, 0, len(c.byKey))
	for _, state := range c.byKey {
		peers = append(peers, state.Peer)
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].TunnelIPv4 != peers[j].TunnelIPv4 {
			return peers[i].TunnelIPv4.Less(peers[j].TunnelIPv4)
		}
		return EncodePublicKey(peers[i].PublicKey) < EncodePublicKey(peers[j].PublicKey)
	})
	return peers, nil
}

// Close gates future administrative operations and waits for any active
// mutation by taking the same mutex. Engine shutdown may safely follow it.
func (c *Controller) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func EncodePublicKey(key noisehandshake.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key[:])
}
