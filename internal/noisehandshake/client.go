package noisehandshake

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/flynn/noise"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const maxZeroExchangeIDAttempts = 8

// ClientConfig configures the production Noise IK client establishment
// provider. Static identity and the responder public key are long-lived
// configuration; every Start/Retry creates a fresh Noise exchange.
type ClientConfig struct {
	ServerEndpoint   netip.AddrPort
	RouteKey         [32]byte
	StaticPrivateKey PrivateKey
	ServerPublicKey  PublicKey

	// Random exists for deterministic tests. nil uses crypto/rand.Reader. Calls
	// are serialized internally so arbitrary injected io.Reader implementations
	// need not be concurrency-safe.
	Random io.Reader
}

// Client is the lifetime-scoped client establishment factory. Freshness belongs
// here rather than to an individual attempt so a completed/failed attempt does
// not reset the monotonic establishment ordering sequence.
type Client struct {
	serverEndpoint   netip.AddrPort
	staticPrivateKey PrivateKey
	serverPublicKey  PublicKey
	random           *lockedReader
	routeScratch     *dataplane.DataScratch
	freshness        FreshnessGenerator
}

var _ coreclient.EstablishmentFactory = (*Client)(nil)

func NewClient(config ClientConfig) (*Client, error) {
	serverEndpoint := normalizeClientServerEndpoint(config.ServerEndpoint)
	if !serverEndpoint.IsValid() {
		return nil, fmt.Errorf("server endpoint must be IPv4 with a non-zero port: %w", ErrInvalidState)
	}

	if config.StaticPrivateKey == (PrivateKey{}) {
		return nil, fmt.Errorf("client static private key is zero: %w", ErrInvalidKey)
	}

	// Derive once at construction so invalid local identity is a startup error.
	if _, err := PublicKeyFromPrivate(config.StaticPrivateKey); err != nil {
		return nil, fmt.Errorf("validate client static private key: %w", err)
	}

	// IK requires the responder static key before the first message. Validate the
	// configured point now rather than turning a permanent configuration error
	// into repeated runtime establishment failures.
	if _, err := noiseCipherSuite.DH(config.StaticPrivateKey[:], config.ServerPublicKey[:]); err != nil {
		return nil, fmt.Errorf("validate server static public key: %w", ErrInvalidKey)
	}

	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	routeScratch, err := dataplane.NewDataScratch(config.RouteKey)
	if err != nil {
		return nil, fmt.Errorf("create Noise route scratch: %w", err)
	}

	return &Client{
		serverEndpoint:   serverEndpoint,
		staticPrivateKey: config.StaticPrivateKey,
		serverPublicKey:  config.ServerPublicKey,
		random:           &lockedReader{r: random},
		routeScratch:     routeScratch,
	}, nil
}

func (c *Client) IsEstablishmentDatagram(
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) bool {
	return isNoiseEstablishmentDatagram(route, routeDecoded, packet)
}

func (c *Client) Start(now time.Time) (
	coreclient.EstablishmentAttempt,
	coreclient.EstablishmentUpdate,
	error,
) {
	if c == nil || c.random == nil || !c.serverEndpoint.IsValid() {
		return nil, coreclient.EstablishmentUpdate{}, fmt.Errorf("Noise client factory is invalid: %w", ErrInvalidState)
	}

	attempt := &clientAttempt{client: c}
	update, err := attempt.startExchange(now)
	if err != nil {
		return nil, coreclient.EstablishmentUpdate{}, err
	}
	return attempt, update, nil
}

type clientAttempt struct {
	client *Client

	exchangeID uint64
	handshake  *noise.HandshakeState
}

var _ coreclient.EstablishmentAttempt = (*clientAttempt)(nil)

func (a *clientAttempt) Retry(now time.Time) (coreclient.EstablishmentUpdate, error) {
	if a == nil || a.client == nil {
		return coreclient.EstablishmentUpdate{}, fmt.Errorf("Noise client attempt is invalid: %w", ErrInvalidState)
	}
	return a.startExchange(now)
}

func (a *clientAttempt) HandleDatagram(
	_ time.Time,
	_ netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (bool, coreclient.EstablishmentUpdate, error) {
	if a == nil || a.client == nil || a.exchangeID == 0 || a.handshake == nil {
		return false, coreclient.EstablishmentUpdate{}, fmt.Errorf("Noise client attempt is invalid: %w", ErrInvalidState)
	}

	if !isNoiseEstablishmentDatagram(route, routeDecoded, packet) {
		return false, coreclient.EstablishmentUpdate{}, nil
	}

	wire, err := parseResponsePacket(a.client.routeScratch, route, routeDecoded, packet)
	if err != nil {
		return true, coreclient.EstablishmentUpdate{}, nil
	}
	if wire.exchangeID != a.exchangeID {
		// Correlation is checked before any Noise work so delayed RESPONSE(H1)
		// during H2 is cheap and cannot mutate the current handshake state.
		return true, coreclient.EstablishmentUpdate{}, nil
	}

	payload, cs1, cs2, err := a.handshake.ReadMessage(nil, wire.message)
	if err != nil {
		// Some flynn/noise failure paths can mutate the HandshakeState. This is
		// deliberately tolerated: the current attempt may be lost, and the normal
		// controller retry creates a completely fresh Noise exchange.
		return true, coreclient.EstablishmentUpdate{}, nil
	}

	sessionID, err := parseResponsePayload(payload)
	if err != nil {
		return true, coreclient.EstablishmentUpdate{}, nil
	}
	material, err := trafficMaterialFromSplit(sessionID, cs1, cs2)
	if err != nil {
		// Successful completion of fixed two-message IK must return both split
		// states. Anything else is a local/library invariant failure.
		return true, coreclient.EstablishmentUpdate{}, fmt.Errorf("derive client traffic material: %w", err)
	}

	return true, coreclient.EstablishmentUpdate{Material: &material}, nil
}

func (a *clientAttempt) startExchange(now time.Time) (coreclient.EstablishmentUpdate, error) {
	exchangeID, err := a.client.generateExchangeID()
	if err != nil {
		return coreclient.EstablishmentUpdate{}, err
	}
	freshness := a.client.freshness.Next(now)

	handshake, err := newInitiatorHandshake(
		a.client.staticPrivateKey,
		a.client.serverPublicKey,
		exchangeID,
		a.client.random,
	)
	if err != nil {
		return coreclient.EstablishmentUpdate{}, fmt.Errorf("create Noise initiator: %w", err)
	}
	initMessage, cs1, cs2, err := handshake.WriteMessage(nil, encodeFreshness(freshness))
	if err != nil {
		return coreclient.EstablishmentUpdate{}, fmt.Errorf("write Noise INIT: %w", err)
	}
	if cs1 != nil || cs2 != nil || len(initMessage) != initNoiseMessageSize {
		return coreclient.EstablishmentUpdate{}, fmt.Errorf("unexpected Noise IK INIT result: %w", ErrInvalidState)
	}

	packet, err := appendInitPacket(
		make([]byte, 0, InitMaxGeneratedPacketSize),
		a.client.routeScratch,
		a.client.random,
		exchangeID,
		initMessage,
	)
	if err != nil {
		return coreclient.EstablishmentUpdate{}, fmt.Errorf("encode Noise INIT packet: %w", err)
	}

	// Publish the new exchange only after every local operation needed to emit its
	// INIT succeeded. Retry therefore atomically replaces the old correlation
	// state from the controller's point of view.
	a.exchangeID = exchangeID
	a.handshake = handshake

	return coreclient.EstablishmentUpdate{
		Outbound: []coreclient.EstablishmentDatagram{{
			Packet:      packet,
			Destination: a.client.serverEndpoint,
		}},
	}, nil
}

func (c *Client) generateExchangeID() (uint64, error) {
	for attempt := 0; attempt < maxZeroExchangeIDAttempts; attempt++ {
		var raw [8]byte
		if _, err := io.ReadFull(c.random, raw[:]); err != nil {
			return 0, fmt.Errorf("generate exchange id: %w", err)
		}
		exchangeID := binary.LittleEndian.Uint64(raw[:])
		if exchangeID != 0 {
			return exchangeID, nil
		}
	}
	return 0, fmt.Errorf("random source produced zero exchange id %d times: %w", maxZeroExchangeIDAttempts, ErrInvalidState)
}

func normalizeClientServerEndpoint(endpoint netip.AddrPort) netip.AddrPort {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}
	}
	addr := endpoint.Addr().Unmap()
	if !addr.Is4() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr, endpoint.Port())
}
