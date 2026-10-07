package noranite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/noisehandshake"
)

const (
	// DefaultMTU is the current reference inner IPv4 MTU for embedded clients.
	DefaultMTU = dataplane.ReferenceTunnelMTU

	// MinTunnelMTU is the minimum inner IPv4 header size.
	MinTunnelMTU = dataplane.MinTunnelMTU

	// MaxTunnelMTU is the absolute inner IPv4 MTU supported by the current
	// IPv4/UDP outer transport after worst-case Opaque-L3 DATA expansion.
	MaxTunnelMTU = dataplane.MaxTunnelMTU

	defaultGenerationLifetime = 24 * time.Hour
	defaultReceiveGrace       = 5 * time.Second
	defaultSoftRekeyAfter     = 12 * time.Hour

	defaultEstablishmentRetryMin = 2500 * time.Millisecond
	defaultEstablishmentRetryMax = 3500 * time.Millisecond

	defaultKeepaliveIntervalMin = 25 * time.Second
	defaultKeepaliveIntervalMax = 35 * time.Second
	defaultKeepaliveTimeout     = 2 * time.Second
)

var (
	ErrClientStarted = errors.New("opaque client already started")
	ErrClientClosed  = errors.New("opaque client is closed")
	ErrClientStopped = errors.New("opaque client stopped before becoming ready")
)

// PacketDevice is the portable L3 packet boundary required by the embedded
// client. Read and Write intentionally use the wireguard-go batch-shaped API,
// but the embedded runtime always supplies exactly one buffer at a time.
//
// Read must place one inner IPv4 packet into bufs[0] starting at offset and set
// sizes[0] to the packet length. Write receives one or more buffers whose inner
// IPv4 packet begins at offset. The Client owns the device after NewClient
// succeeds and closes it during shutdown.
type PacketDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	Close() error
}

// ClientConfig contains protocol identity and fixed peer addressing only.
// Runtime queue sizes, worker counts and batching are implementation details.
type ClientConfig struct {
	TunnelIPv4     netip.Addr
	ServerEndpoint netip.AddrPort
	MTU            int // Must be in [MinTunnelMTU, MaxTunnelMTU].

	RouteKey         [32]byte // Required; must not be all zero.
	StaticPrivateKey [32]byte
	ServerPublicKey  [32]byte
}

// TransportFailure reports loss of the currently published outer transport.
// Generation is monotonically increasing for the lifetime of a Client. Err is
// the underlying connected-datagram read/write failure that invalidated it.
// Notifications are edge-triggered and may be coalesced; integrations should
// use them to request a fresh transport, not as a packet-loss accounting API.
type TransportFailure struct {
	Generation uint64
	Err        error
}

// Client is the portable embedded Opaque-L3 client. It owns its PacketDevice,
// optional connected datagram transport, packet runtime and SessionController.
//
// A non-nil transport must be a connected datagram net.Conn to ServerEndpoint.
// A nil initial transport is a normal recoverable state: Run may start offline
// and a host integration can publish a socket later with ReplaceTransport. This
// is the boundary sing-box can satisfy with its own dialer; Opaque does not
// create or bind platform sockets itself.
type Client struct {
	runtime    *embeddedRuntime
	controller *coreclient.SessionController

	runMu   sync.Mutex
	started bool
	closed  bool
}

func NewClient(config ClientConfig, device PacketDevice, transport net.Conn) (*Client, error) {
	if device == nil {
		return nil, fmt.Errorf("packet device is nil: %w", dataplane.ErrInvalidConfig)
	}
	if config.RouteKey == ([32]byte{}) {
		return nil, fmt.Errorf("route key must not be all zero: %w", dataplane.ErrInvalidConfig)
	}
	if config.MTU < MinTunnelMTU || config.MTU > MaxTunnelMTU {
		return nil, fmt.Errorf(
			"invalid tunnel MTU %d, want [%d, %d]: %w",
			config.MTU,
			MinTunnelMTU,
			MaxTunnelMTU,
			dataplane.ErrInvalidConfig,
		)
	}

	serverEndpoint := normalizeServerEndpoint(config.ServerEndpoint)
	if !serverEndpoint.IsValid() {
		return nil, fmt.Errorf("server endpoint must be a valid IPv4 UDP endpoint: %w", dataplane.ErrInvalidConfig)
	}

	core, err := coreclient.New(coreclient.Config{
		RouteKey:           config.RouteKey,
		TunnelIPv4:         config.TunnelIPv4,
		ServerEndpoint:     serverEndpoint,
		MaxInnerPacketSize: config.MTU,
		Lifecycle: coreclient.LifecycleConfig{
			GenerationLifetime: defaultGenerationLifetime,
			ReceiveGrace:       defaultReceiveGrace,
		},
		Session: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("create client core: %w", err)
	}

	factory, err := noisehandshake.NewClient(noisehandshake.ClientConfig{
		ServerEndpoint:   serverEndpoint,
		RouteKey:         config.RouteKey,
		StaticPrivateKey: noisehandshake.PrivateKey(config.StaticPrivateKey),
		ServerPublicKey:  noisehandshake.PublicKey(config.ServerPublicKey),
	})
	if err != nil {
		return nil, fmt.Errorf("create Noise establishment factory: %w", err)
	}

	runtime, err := newEmbeddedRuntime(device, transport, core, serverEndpoint, config.MTU)
	if err != nil {
		return nil, err
	}

	controller, err := coreclient.NewSessionController(
		core,
		runtime,
		factory,
		coreclient.SessionControllerConfig{
			SoftRekeyAfter:        defaultSoftRekeyAfter,
			EstablishmentRetryMin: defaultEstablishmentRetryMin,
			EstablishmentRetryMax: defaultEstablishmentRetryMax,
			KeepaliveIntervalMin:  defaultKeepaliveIntervalMin,
			KeepaliveIntervalMax:  defaultKeepaliveIntervalMax,
			KeepaliveTimeout:      defaultKeepaliveTimeout,
		},
	)
	if err != nil {
		runtime.disposeConstructionFailure()
		return nil, fmt.Errorf("create Session controller: %w", err)
	}
	runtime.demux = controller
	runtime.eventSink = controller

	return &Client{
		runtime:    runtime,
		controller: controller,
	}, nil
}

// Run starts the embedded packet runtime and SessionController and blocks until
// shutdown or a terminal local/runtime failure. Run may be called only once.
func (c *Client) Run(ctx context.Context) error {
	if c == nil || c.runtime == nil || c.controller == nil {
		return fmt.Errorf("opaque client is nil: %w", dataplane.ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.runMu.Lock()
	if c.closed {
		c.runMu.Unlock()
		return ErrClientClosed
	}
	if c.started {
		c.runMu.Unlock()
		return ErrClientStarted
	}
	c.started = true
	c.runMu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	controllerDone := make(chan error, 1)
	go func() {
		err := c.controller.Run(runCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			c.runtime.requestClose()
		}
		controllerDone <- err
	}()

	cancelWatcherDone := make(chan struct{})
	go func() {
		defer close(cancelWatcherDone)
		select {
		case <-runCtx.Done():
			c.runtime.requestClose()
		case <-c.runtime.Done():
		}
	}()

	runtimeErr := c.runtime.Run()
	cancel()
	controllerErr := <-controllerDone
	<-cancelWatcherDone

	if controllerErr != nil && !errors.Is(controllerErr, context.Canceled) {
		return controllerErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runtimeErr == nil || errors.Is(runtimeErr, os.ErrClosed) || errors.Is(runtimeErr, net.ErrClosed) {
		return nil
	}
	return runtimeErr
}

// WaitReady waits until the first traffic Session has been established. The
// signal is one-way: once initial readiness succeeds, later rekey/recovery gaps
// do not make the Client unready again. Integrations should wait here before
// exposing a newly created PacketDevice to application traffic.
func (c *Client) WaitReady(ctx context.Context) error {
	if c == nil || c.runtime == nil || c.controller == nil {
		return fmt.Errorf("opaque client is nil: %w", dataplane.ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.runMu.Lock()
	closed := c.closed
	c.runMu.Unlock()
	if closed {
		return ErrClientClosed
	}

	ready := c.controller.Ready()
	select {
	case <-ready:
		return nil
	default:
	}

	select {
	case <-ready:
		return nil
	case <-c.runtime.Done():
		select {
		case <-ready:
			return nil
		default:
		}
		c.runMu.Lock()
		closed = c.closed
		c.runMu.Unlock()
		if closed {
			return ErrClientClosed
		}
		return ErrClientStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TransportFailures reports loss of the currently published outer transport.
// The channel is intentionally not closed; callers should stop watching it
// when their Client Run context is canceled or Run returns.
func (c *Client) TransportFailures() <-chan TransportFailure {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.transportFailures
}

// ReplaceTransport atomically publishes a replacement connected datagram
// transport without changing traffic Session state. On success it returns the
// monotonically increasing transport generation ID, Client owns the new
// transport, and the previous generation is closed. A running Client notifies
// SessionController only after the new transport has been published, causing
// immediate path liveness/re-establishment work on the replacement path.
//
// On error the returned generation is zero and ownership remains with the caller.
func (c *Client) ReplaceTransport(transport net.Conn) (uint64, error) {
	if c == nil || c.runtime == nil || c.controller == nil {
		return 0, fmt.Errorf("opaque client is nil: %w", dataplane.ErrInvalidConfig)
	}
	if transport == nil {
		return 0, fmt.Errorf("replacement datagram transport is nil: %w", dataplane.ErrInvalidConfig)
	}

	c.runMu.Lock()
	defer c.runMu.Unlock()
	if c.closed {
		return 0, ErrClientClosed
	}
	generation, err := c.runtime.replaceTransport(transport)
	if err != nil {
		return 0, err
	}
	if c.started {
		c.controller.TransportRebound()
	}
	return generation, nil
}

// Close requests shutdown. It is idempotent. NewClient transfers ownership of
// the device and any non-nil initial transport to Client, so callers must not
// close them separately after NewClient succeeds. Replacement transports
// transfer ownership only after ReplaceTransport succeeds.
func (c *Client) Close() error {
	if c == nil || c.runtime == nil {
		return nil
	}

	c.runMu.Lock()
	if c.closed {
		c.runMu.Unlock()
		return nil
	}
	c.closed = true
	started := c.started
	c.runMu.Unlock()

	if !started {
		return c.runtime.disposeUnstarted()
	}
	return c.runtime.requestClose()
}

func normalizeServerEndpoint(endpoint netip.AddrPort) netip.AddrPort {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}
	}
	addr := endpoint.Addr().Unmap()
	if !addr.Is4() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr, endpoint.Port())
}
