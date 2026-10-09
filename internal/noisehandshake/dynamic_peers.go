package noisehandshake

import (
	"fmt"
	"net/netip"

	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

// ValidateAuthorizedPeer runs the same key validation as startup, without
// exposing the peer to concurrent establishment workers.
func (s *Server) ValidateAuthorizedPeer(ip netip.Addr, key PublicKey) error {
	ip = ip.Unmap()
	if err := coreserver.ValidateTunnelIPv4(ip); err != nil {
		return fmt.Errorf("invalid tunnel IPv4: %w", ErrInvalidState)
	}
	if _, err := noiseCipherSuite.DH(s.staticPrivateKey[:], key[:]); err != nil {
		return fmt.Errorf("invalid client public key: %w", ErrInvalidKey)
	}
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	for existingKey, peer := range s.peers {
		binding := peer.binding.Load()
		if existingKey == key || binding != nil && binding.tunnelIPv4 == ip {
			return fmt.Errorf("duplicate authorized peer: %w", ErrInvalidKey)
		}
	}
	return nil
}

// AddAuthorizedPeer publishes a prevalidated, already-Core-published peer.
func (s *Server) AddAuthorizedPeer(ip netip.Addr, key PublicKey, peer *coreserver.Peer) error {
	ip = ip.Unmap()
	if peer == nil || s.core.PeerForIP(ip) != peer || peer.IsRevoked() {
		return coreserver.ErrPeerRevoked
	}
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	if _, exists := s.peers[key]; exists {
		return ErrInvalidKey
	}
	for _, state := range s.peers {
		binding := state.binding.Load()
		if binding != nil && binding.tunnelIPv4 == ip {
			return ErrInvalidKey
		}
	}
	state := &serverPeerState{}
	state.binding.Store(&serverPeerBinding{tunnelIPv4: ip, corePeer: peer})
	s.peers[key] = state
	return nil
}

// ReplaceAuthorizedPeer atomically changes the binding of an existing public
// identity while preserving its freshness history. Establishment workers pin
// the immutable binding pointer they observed; a worker using the old binding
// is rejected by commitFreshPending after this swap.
func (s *Server) ReplaceAuthorizedPeer(
	key PublicKey,
	expected *coreserver.Peer,
	ip netip.Addr,
	replacement *coreserver.Peer,
) error {
	ip = ip.Unmap()
	if replacement == nil || s.core.PeerForIP(ip) != replacement || replacement.IsRevoked() {
		return coreserver.ErrPeerRevoked
	}

	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	state := s.peers[key]
	if state == nil {
		return coreserver.ErrPeerRevoked
	}
	current := state.binding.Load()
	if current == nil || current.corePeer != expected {
		return coreserver.ErrPeerRevoked
	}
	for existingKey, other := range s.peers {
		if existingKey == key {
			continue
		}
		binding := other.binding.Load()
		if binding != nil && binding.tunnelIPv4 == ip {
			return ErrInvalidKey
		}
	}
	state.binding.Store(&serverPeerBinding{tunnelIPv4: ip, corePeer: replacement})
	return nil
}

// A concurrent worker may retain the old state/binding pointers. Clearing the
// binding invalidates those workers at the Noise commit boundary; Core's
// pinned-peer guard remains the second line of defense.
func (s *Server) RemoveAuthorizedPeer(key PublicKey) {
	s.peersMu.Lock()
	if state := s.peers[key]; state != nil {
		state.binding.Store(nil)
		delete(s.peers, key)
	}
	s.peersMu.Unlock()
}
