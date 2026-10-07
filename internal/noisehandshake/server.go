package noisehandshake

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
	coreserver "github.com/noranite/Noranite-l3/internal/server"
)

const maxZeroSessionIDAttempts = 8

// AuthorizedPeer binds one authenticated Noise static public key to the
// logical tunnel Peer already configured in server.Core.
//
// The tunnel address is configuration, never packet input. UDP source addresses
// are response destinations only and are not identities.
type AuthorizedPeer struct {
	TunnelIPv4 netip.Addr
	PublicKey  PublicKey
}

// ServerConfig configures the production Noise IK server establishment
// provider.
type ServerConfig struct {
	Core             *coreserver.Core
	StaticPrivateKey PrivateKey
	Peers            []AuthorizedPeer

	// Random exists for deterministic tests. nil uses crypto/rand.Reader. Calls
	// are serialized internally because establishment workers invoke Server
	// concurrently and arbitrary injected io.Reader implementations need not be
	// concurrency-safe.
	Random io.Reader
}

type serverPeerState struct {
	tunnelIPv4 netip.Addr

	// mu protects the establishment ordering transaction only. Noise crypto and
	// RNG must never execute while this mutex is held.
	mu              sync.Mutex
	hasLatest       bool
	latestFreshness Freshness
}

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (r *lockedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Read(p)
}

// Server authenticates Noise IK initiators and installs the resulting traffic
// generation as pending in server.Core. It owns only establishment identity and
// freshness ordering; transport lifecycle remains in Core.
type Server struct {
	core             *coreserver.Core
	staticPrivateKey PrivateKey
	random           *lockedReader
	routeMu          sync.Mutex
	routeScratch     *dataplane.DataScratch
	peers            map[PublicKey]*serverPeerState
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.Core == nil {
		return nil, fmt.Errorf("server core is nil: %w", ErrInvalidState)
	}
	if len(config.Peers) == 0 {
		return nil, fmt.Errorf("authorized peer list is empty: %w", ErrInvalidState)
	}

	if config.StaticPrivateKey == (PrivateKey{}) {
		return nil, fmt.Errorf("server static private key is zero: %w", ErrInvalidKey)
	}

	// Derive once at construction so any impossible local static-key state is a
	// startup error rather than a packet-triggered runtime failure.
	if _, err := PublicKeyFromPrivate(config.StaticPrivateKey); err != nil {
		return nil, fmt.Errorf("validate server static private key: %w", err)
	}

	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	routeScratch, err := config.Core.NewDataScratch()
	if err != nil {
		return nil, fmt.Errorf("create Noise route scratch: %w", err)
	}

	peers := make(map[PublicKey]*serverPeerState, len(config.Peers))
	tunnels := make(map[netip.Addr]struct{}, len(config.Peers))
	for i, peer := range config.Peers {
		tunnelIPv4 := peer.TunnelIPv4.Unmap()
		if !tunnelIPv4.IsValid() || !tunnelIPv4.Is4() {
			return nil, fmt.Errorf("authorized peer %d tunnel address must be IPv4: %w", i, ErrInvalidState)
		}
		if !config.Core.HasPeer(tunnelIPv4) {
			return nil, fmt.Errorf("authorized peer %d tunnel IPv4 %s is not configured in server core: %w", i, tunnelIPv4, coreserver.ErrUnknownPeer)
		}
		if _, exists := peers[peer.PublicKey]; exists {
			return nil, fmt.Errorf("duplicate authorized client public key at index %d: %w", i, ErrInvalidKey)
		}
		if _, exists := tunnels[tunnelIPv4]; exists {
			return nil, fmt.Errorf("duplicate authorized tunnel IPv4 %s: %w", tunnelIPv4, ErrInvalidState)
		}

		// Validate that the configured public key is a usable X25519 point for
		// the server static key. This catches low-order/invalid public keys at
		// startup instead of turning them into permanent handshake failures.
		if _, err := noiseCipherSuite.DH(config.StaticPrivateKey[:], peer.PublicKey[:]); err != nil {
			return nil, fmt.Errorf("authorized peer %d public key: %w", i, ErrInvalidKey)
		}

		peers[peer.PublicKey] = &serverPeerState{tunnelIPv4: tunnelIPv4}
		tunnels[tunnelIPv4] = struct{}{}
	}

	return &Server{
		core:             config.Core,
		staticPrivateKey: config.StaticPrivateKey,
		random:           &lockedReader{r: random},
		routeScratch:     routeScratch,
		peers:            peers,
	}, nil
}

func (s *Server) IsEstablishmentDatagram(
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) bool {
	return isNoiseEstablishmentDatagram(route, routeDecoded, packet)
}

// TryHandleEstablishmentDatagramInPlace implements the generic server
// establishment ingress contract.
//
// Once the hidden Noise route namespace matches, all network-originated rejection is consumed
// with handled=true, err=nil. A non-nil error means a local/server failure.
// RESPONSE is returned only after Core has successfully installed the pending
// Session and freshness has been committed.
func (s *Server) TryHandleEstablishmentDatagramInPlace(
	source netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (
	handled bool,
	response []byte,
	responseDestination netip.AddrPort,
	err error,
) {
	if !isNoiseEstablishmentDatagram(route, routeDecoded, packet) {
		return false, nil, netip.AddrPort{}, nil
	}

	if !source.IsValid() || !source.Addr().Unmap().Is4() || source.Port() == 0 {
		return true, nil, netip.AddrPort{}, nil
	}

	s.routeMu.Lock()
	wire, err := parseInitPacket(s.routeScratch, route, routeDecoded, packet)
	s.routeMu.Unlock()
	if err != nil {
		return true, nil, netip.AddrPort{}, nil
	}

	handshake, err := newResponderHandshake(s.staticPrivateKey, wire.exchangeID, s.random)
	if err != nil {
		return true, nil, netip.AddrPort{}, fmt.Errorf("create Noise responder: %w", err)
	}

	freshnessPayload, _, _, err := handshake.ReadMessage(nil, wire.message)
	if err != nil {
		// The INIT is untrusted. Authentication/DH/payload failures are packet
		// rejection, not local runtime failures.
		return true, nil, netip.AddrPort{}, nil
	}

	clientPublicKey, err := peerStaticPublicKey(handshake)
	if err != nil {
		// A successful IK ReadMessage must expose the initiator static key.
		return true, nil, netip.AddrPort{}, fmt.Errorf("read authenticated client static key: %w", err)
	}
	peer := s.peers[clientPublicKey]
	if peer == nil {
		return true, nil, netip.AddrPort{}, nil
	}

	freshness, err := ParseFreshness(freshnessPayload)
	if err != nil {
		return true, nil, netip.AddrPort{}, nil
	}

	// Cheap first check: reject already-known stale authenticated INITs before
	// generating a session ID, responder ephemeral, response AEAD and dataplane
	// Session. This is only an optimization; the final check below is decisive.
	if !peer.preliminaryFresh(freshness) {
		return true, nil, netip.AddrPort{}, nil
	}

	sessionID, err := s.generateSessionID()
	if err != nil {
		return true, nil, netip.AddrPort{}, err
	}
	responsePayload, err := encodeResponsePayload(sessionID)
	if err != nil {
		return true, nil, netip.AddrPort{}, fmt.Errorf("encode Noise response payload: %w", err)
	}

	responseMessage, cs1, cs2, err := handshake.WriteMessage(nil, responsePayload[:])
	if err != nil {
		// After successful INIT authentication all inputs to WriteMessage are local
		// state plus RNG, so failure is a server/runtime error.
		return true, nil, netip.AddrPort{}, fmt.Errorf("write Noise response: %w", err)
	}
	material, err := trafficMaterialFromSplit(sessionID, cs1, cs2)
	if err != nil {
		return true, nil, netip.AddrPort{}, fmt.Errorf("derive traffic material: %w", err)
	}
	session, err := establishment.NewServerSession(material)
	if err != nil {
		return true, nil, netip.AddrPort{}, fmt.Errorf("create server traffic session: %w", err)
	}

	installed, err := s.commitFreshPending(peer, freshness, session)
	if err != nil {
		if errors.Is(err, coreserver.ErrSessionIDCollision) {
			// Collision invalidates this whole exchange. Do not publish RESPONSE and
			// do not advance freshness; a normal client retry gets a new exchange.
			return true, nil, netip.AddrPort{}, nil
		}
		return true, nil, netip.AddrPort{}, fmt.Errorf("install Noise pending session: %w", err)
	}
	if !installed {
		// A newer authenticated exchange committed while crypto for this one was
		// running. Its already-built response must never resurrect an old pending
		// generation on the client.
		return true, nil, netip.AddrPort{}, nil
	}

	s.routeMu.Lock()
	response, err = appendGeneratedResponsePacket(
		packet[:0],
		s.routeScratch,
		s.random,
		wire.exchangeID,
		responseMessage,
		len(packet),
	)
	s.routeMu.Unlock()
	if err != nil {
		return true, nil, netip.AddrPort{}, fmt.Errorf("encode Noise response packet: %w", err)
	}
	return true, response, source, nil
}

func (p *serverPeerState) preliminaryFresh(incoming Freshness) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.hasLatest || incoming > p.latestFreshness
}

// commitFreshPending is the authoritative ordering transaction. The final
// freshness re-check, Core pending installation and latestFreshness update are
// one critical section so older crypto completions cannot supersede newer ones.
func (s *Server) commitFreshPending(
	peer *serverPeerState,
	freshness Freshness,
	session *dataplane.Session,
) (bool, error) {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	if peer.hasLatest && freshness <= peer.latestFreshness {
		return false, nil
	}

	if err := s.core.InstallPendingSession(peer.tunnelIPv4, session); err != nil {
		return false, err
	}

	// Advance only after Core has atomically published the pending Session and
	// global session_id registry entry. Failed installation remains retryable.
	peer.latestFreshness = freshness
	peer.hasLatest = true
	return true, nil
}

func (s *Server) generateSessionID() (uint64, error) {
	for attempt := 0; attempt < maxZeroSessionIDAttempts; attempt++ {
		var raw [8]byte
		if _, err := io.ReadFull(s.random, raw[:]); err != nil {
			return 0, fmt.Errorf("generate session id: %w", err)
		}
		sessionID := binary.LittleEndian.Uint64(raw[:])
		if sessionID != 0 {
			return sessionID, nil
		}
	}
	return 0, fmt.Errorf("random source produced zero session id %d times: %w", maxZeroSessionIDAttempts, ErrInvalidState)
}
