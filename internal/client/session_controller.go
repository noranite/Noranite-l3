package client

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
)

const keepaliveTimeoutsBeforeRekey = 3

// SessionControllerConfig is orchestration policy above the fixed
// current/previous crypto lifecycle.
//
// SoftRekeyAfter is measured from the installation time of the current traffic
// generation. Establishment retry and periodic keepalive schedules choose a fresh
// uniform delay inside their inclusive [Min, Max] ranges after each successful
// scheduling point. Provider-local/internal failures are terminal and are surfaced
// to the runtime; only network loss/rejection is represented by an update with no
// completion.
type SessionControllerConfig struct {
	SoftRekeyAfter time.Duration

	EstablishmentRetryMin time.Duration
	EstablishmentRetryMax time.Duration

	// KeepaliveIntervalMin/Max and KeepaliveTimeout are an optional liveness
	// policy for the installed traffic generation. All zero disables it. When
	// enabled, three consecutive missed authenticated ACKs start normal fresh
	// establishment. ACK never confirms, rolls back or otherwise changes
	// generation lifecycle state.
	KeepaliveIntervalMin time.Duration
	KeepaliveIntervalMax time.Duration
	KeepaliveTimeout     time.Duration
}

func (c SessionControllerConfig) validate(generationLifetime time.Duration) error {
	if c.SoftRekeyAfter <= 0 {
		return fmt.Errorf("soft rekey interval must be positive: %w", dataplane.ErrInvalidConfig)
	}
	if c.EstablishmentRetryMin <= 0 || c.EstablishmentRetryMax <= 0 ||
		c.EstablishmentRetryMin > c.EstablishmentRetryMax {
		return fmt.Errorf(
			"invalid establishment retry range [%s, %s]: %w",
			c.EstablishmentRetryMin,
			c.EstablishmentRetryMax,
			dataplane.ErrInvalidConfig,
		)
	}
	keepaliveDisabled := c.KeepaliveIntervalMin == 0 &&
		c.KeepaliveIntervalMax == 0 &&
		c.KeepaliveTimeout == 0
	if !keepaliveDisabled {
		if c.KeepaliveIntervalMin <= 0 || c.KeepaliveIntervalMax <= 0 ||
			c.KeepaliveIntervalMin > c.KeepaliveIntervalMax || c.KeepaliveTimeout <= 0 {
			return fmt.Errorf(
				"invalid keepalive policy interval=[%s, %s] timeout=%s: %w",
				c.KeepaliveIntervalMin,
				c.KeepaliveIntervalMax,
				c.KeepaliveTimeout,
				dataplane.ErrInvalidConfig,
			)
		}
	}
	if c.SoftRekeyAfter >= generationLifetime {
		return fmt.Errorf(
			"soft rekey interval %s must be shorter than generation lifetime %s: %w",
			c.SoftRekeyAfter,
			generationLifetime,
			dataplane.ErrInvalidConfig,
		)
	}
	return nil
}

// SessionControllerRuntime is the runtime-owned same-socket I/O boundary used
// by lifecycle orchestration. Raw handshake datagrams bypass traffic-generation
// nonce space; encrypted control traffic uses the shared TX engine.
type SessionControllerRuntime interface {
	SendProtocolDatagram(packet []byte, destination netip.AddrPort) error
	SubmitProtocolTransport(op *OutboundOperation) error
	Ready() <-chan struct{}
	Done() <-chan struct{}
}

// EstablishmentDatagram is one raw control-plane datagram emitted by an
// establishment attempt.
type EstablishmentDatagram struct {
	Packet      []byte
	Destination netip.AddrPort
}

// EstablishmentUpdate is one state-machine output from an establishment
// provider. Material being non-nil completes the attempt successfully.
//
// Outbound datagrams are sent before session installation so the control-plane
// exchange can finish before the traffic generation becomes current.
type EstablishmentUpdate struct {
	Outbound []EstablishmentDatagram
	Material *establishment.TrafficSessionMaterial
}

// EstablishmentAttempt is one event-driven client establishment attempt.
//
// HandleDatagram must not retain packet: runtime receive storage is reusable.
// handled=false means the datagram was not understood by this active attempt.
// SessionController still consults the factory's lifetime classifier before
// allowing any packet to fall through to encrypted transport admission.
//
// A non-nil error means a local/internal provider failure. Network-originated
// rejection (source policy/version/exchange, malformed/authentication failure,
// stale response) must be consumed with err=nil so an unauthenticated packet
// cannot restart or terminate establishment.
type EstablishmentAttempt interface {
	HandleDatagram(
		now time.Time,
		source netip.AddrPort,
		route dataplane.Route,
		routeDecoded bool,
		packet []byte,
	) (handled bool, update EstablishmentUpdate, err error)

	Retry(now time.Time) (EstablishmentUpdate, error)
}

// EstablishmentFactory creates a fresh attempt and its initial wire output.
// This is intentionally event-driven rather than a blocking Establish() API: the
// runtime remains the sole owner of UDP receive.
//
// DatagramClassifier is lifetime-scoped: it remains authoritative even when no
// attempt is active, so delayed plaintext establishment traffic can never fall
// through to encrypted dataplane admission.
type EstablishmentFactory interface {
	establishment.DatagramClassifier
	Start(now time.Time) (EstablishmentAttempt, EstablishmentUpdate, error)
}

// SessionControllerTimer/Clock keep timer policy deterministic in tests while
// production uses wall clock time.
type SessionControllerTimer interface {
	C() <-chan time.Time
	Stop()
}

type SessionControllerClock interface {
	Now() time.Time
	NewTimer(d time.Duration) SessionControllerTimer
}

type wallSessionControllerClock struct{}

type wallSessionControllerTimer struct {
	t *time.Timer
}

func (wallSessionControllerClock) Now() time.Time { return time.Now() }
func (wallSessionControllerClock) NewTimer(d time.Duration) SessionControllerTimer {
	return &wallSessionControllerTimer{t: time.NewTimer(d)}
}
func (t *wallSessionControllerTimer) C() <-chan time.Time { return t.t.C }
func (t *wallSessionControllerTimer) Stop()               { t.t.Stop() }

// SessionController owns rekey/retry/activation orchestration only. It never
// owns replay, key slots, sequence counters or UDP receive.
type SessionController struct {
	core    *Core
	runtime SessionControllerRuntime
	factory EstablishmentFactory
	config  SessionControllerConfig
	clock   SessionControllerClock

	mu sync.Mutex

	attempt    EstablishmentAttempt
	nextAction time.Time

	nextKeepalive     time.Time
	keepaliveID       uint64
	keepaliveDeadline time.Time
	keepaliveTimeouts int
	nextKeepaliveID   uint64

	ready       chan struct{}
	readyClosed bool
	wake        chan struct{}
}

func NewSessionController(
	core *Core,
	runtime SessionControllerRuntime,
	factory EstablishmentFactory,
	config SessionControllerConfig,
) (*SessionController, error) {
	return newSessionController(core, runtime, factory, config, wallSessionControllerClock{})
}

func newSessionController(
	core *Core,
	runtime SessionControllerRuntime,
	factory EstablishmentFactory,
	config SessionControllerConfig,
	clock SessionControllerClock,
) (*SessionController, error) {
	if core == nil || core.peer == nil || runtime == nil || factory == nil || clock == nil {
		return nil, fmt.Errorf("invalid session controller input: %w", dataplane.ErrInvalidConfig)
	}
	if err := config.validate(core.peer.lifecycle.GenerationLifetime); err != nil {
		return nil, err
	}

	now := clock.Now()
	next := now
	var nextKeepalive time.Time
	hasCurrent := false
	if installedAt, ok := core.peer.currentInstalledAt(); ok {
		hasCurrent = true
		next = installedAt.Add(config.SoftRekeyAfter)
		if next.Before(now) {
			next = now
		}
		if config.KeepaliveIntervalMin > 0 {
			nextKeepalive = now.Add(randomDuration(config.KeepaliveIntervalMin, config.KeepaliveIntervalMax))
		}
	}

	controller := &SessionController{
		core:            core,
		runtime:         runtime,
		factory:         factory,
		config:          config,
		clock:           clock,
		nextAction:      next,
		nextKeepalive:   nextKeepalive,
		nextKeepaliveID: 1,
		ready:           make(chan struct{}),
		wake:            make(chan struct{}, 1),
	}
	if hasCurrent {
		close(controller.ready)
		controller.readyClosed = true
	}
	return controller, nil
}

// Ready closes after the first traffic Session becomes current. It is a
// one-way initial-readiness signal: later rekey/recovery gaps do not reopen it.
func (c *SessionController) Ready() <-chan struct{} {
	if c == nil {
		ch := make(chan struct{})
		return ch
	}
	return c.ready
}

// RequestRekey coalesces with an already-active establishment attempt. If no
// attempt is active, it moves the next establishment start to now.
func (c *SessionController) RequestRekey() {
	if c == nil {
		return
	}

	now := c.clock.Now()
	c.mu.Lock()
	if c.attempt == nil && c.nextAction.After(now) {
		c.nextAction = now
	}
	c.mu.Unlock()
	c.signalWake()
}

// TransportRebound reports that the runtime has successfully replaced or
// rebound the outer transport after a network change. Protocol state survives:
// an active establishment attempt retries immediately with a fresh exchange;
// otherwise a still-usable current generation sends an immediate KEEPALIVE so
// the server can learn the new authenticated endpoint. If current is absent or
// hard-expired, normal fresh establishment starts immediately.
//
// Any outstanding KEEPALIVE belongs to the old path and is forgotten without
// counting it as a liveness failure. Call this only after the replacement
// transport is ready to send.
func (c *SessionController) TransportRebound() {
	if c == nil {
		return
	}

	now := c.clock.Now()
	c.mu.Lock()
	c.keepaliveID = 0
	c.keepaliveDeadline = time.Time{}
	c.keepaliveTimeouts = 0

	switch {
	case c.attempt != nil:
		c.nextKeepalive = time.Time{}
		c.nextAction = now
	case c.core.peer.currentTXEligible(now):
		if c.keepaliveEnabledLocked() {
			c.nextKeepalive = now
		}
	default:
		c.nextKeepalive = time.Time{}
		c.nextAction = now
	}
	c.mu.Unlock()
	c.signalWake()
}

// HandleAuthenticatedACK consumes an already-authenticated ACK as a liveness
// signal only. It intentionally has no authority over traffic-generation
// installation, promotion or rollback.
func (c *SessionController) HandleAuthenticatedACK(keepaliveID uint64) {
	if c == nil || keepaliveID == 0 {
		return
	}

	now := c.clock.Now()
	matched := false
	c.mu.Lock()
	if c.keepaliveID == keepaliveID {
		matched = true
		c.keepaliveID = 0
		c.keepaliveDeadline = time.Time{}
		c.keepaliveTimeouts = 0
		if c.keepaliveEnabledLocked() && c.attempt == nil {
			c.nextKeepalive = now.Add(c.nextKeepaliveDelay())
		}
	}
	c.mu.Unlock()
	if matched {
		c.signalWake()
	}
}

// HandleDatagram implements the runtime same-socket demux seam.
//
// Establishment ownership is lifetime-scoped. Once the factory classifier owns
// a packet, it is consumed even if there is no active attempt or the active
// attempt rejects the packet. This prevents delayed/malformed plaintext
// establishment traffic from ever reaching encrypted transport admission.
func (c *SessionController) HandleDatagram(
	source netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (bool, error) {
	if c == nil {
		return false, nil
	}

	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.factory.IsEstablishmentDatagram(route, routeDecoded, packet) {
		return false, nil
	}
	if c.attempt == nil {
		return true, nil
	}

	handled, update, err := c.attempt.HandleDatagram(now, source, route, routeDecoded, packet)
	if err != nil {
		return true, fmt.Errorf("handle establishment datagram: %w", err)
	}
	if !handled {
		// The lifetime classifier already assigned ownership to establishment.
		// Provider-specific non-recognition is therefore a silent consume/drop,
		// never permission to enter the encrypted dataplane classifier.
		return true, nil
	}
	if err := c.applyUpdateLocked(now, update); err != nil {
		return true, err
	}
	c.signalWake()
	return true, nil
}

// Run drives time-based rekey and establishment retry. Runtime owns socket
// lifetime; when runtime Done closes, controller exits without generating more
// protocol traffic.
func (c *SessionController) Run(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("session controller is nil: %w", dataplane.ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-c.runtime.Ready():
	case <-c.runtime.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	for {
		now := c.clock.Now()

		c.mu.Lock()
		next := c.nextDueLocked()
		c.mu.Unlock()

		if !next.After(now) {
			if err := c.runDue(now); err != nil {
				return err
			}
			continue
		}

		timer := c.clock.NewTimer(next.Sub(now))
		select {
		case <-timer.C():
		case <-c.wake:
			timer.Stop()
		case <-c.runtime.Done():
			timer.Stop()
			return nil
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (c *SessionController) runDue(now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A missing ACK is evidence that the installed generation may no longer
	// exist at the peer or that packets are being lost. Protocol recovery is the
	// ordinary fresh-establishment path; socket lifetime remains runtime policy.
	if !c.keepaliveDeadline.IsZero() && !c.keepaliveDeadline.After(now) {
		c.keepaliveID = 0
		c.keepaliveDeadline = time.Time{}
		c.keepaliveTimeouts++
		if c.keepaliveTimeouts >= keepaliveTimeoutsBeforeRekey {
			c.nextKeepalive = time.Time{}
			c.keepaliveTimeouts = 0
			if c.attempt == nil && c.nextAction.After(now) {
				c.nextAction = now
			}
		} else if c.keepaliveEnabledLocked() && c.attempt == nil {
			// A single lost UDP KEEPALIVE or ACK must not force a Noise exchange. Retry
			// liveness immediately with a fresh KEEPALIVE/sequence; only consecutive
			// timeouts escalate to establishment.
			c.nextKeepalive = now
		}
	}

	if !c.nextAction.After(now) {
		if c.attempt == nil {
			c.clearKeepaliveLocked()
			attempt, update, err := c.factory.Start(now)
			if err != nil {
				return fmt.Errorf("start establishment: %w", err)
			}
			if attempt == nil && update.Material == nil {
				return fmt.Errorf(
					"establishment factory returned neither attempt nor material: %w",
					dataplane.ErrInvalidConfig,
				)
			}
			c.attempt = attempt
			if err := c.applyUpdateLocked(now, update); err != nil {
				return err
			}
			if c.attempt != nil {
				c.nextAction = now.Add(c.nextEstablishmentRetryDelay())
			}
			return nil
		}

		update, err := c.attempt.Retry(now)
		if err != nil {
			return fmt.Errorf("retry establishment: %w", err)
		}
		if err := c.applyUpdateLocked(now, update); err != nil {
			return err
		}
		if c.attempt != nil {
			c.nextAction = now.Add(c.nextEstablishmentRetryDelay())
		}
		return nil
	}

	if c.keepaliveEnabledLocked() &&
		c.attempt == nil &&
		c.keepaliveID == 0 &&
		!c.nextKeepalive.IsZero() &&
		!c.nextKeepalive.After(now) {
		keepaliveID := c.nextKeepaliveIDLocked()
		op, err := c.core.AdmitKeepalive(keepaliveID, dataplane.MaxGeneratedControlWirePacketSize)
		if err != nil {
			return fmt.Errorf("admit keepalive: %w", err)
		}
		if err := c.runtime.SubmitProtocolTransport(op); err != nil {
			return fmt.Errorf("submit keepalive: %w", err)
		}
		c.keepaliveID = keepaliveID
		c.keepaliveDeadline = now.Add(c.config.KeepaliveTimeout)
		c.nextKeepalive = time.Time{}
	}

	return nil
}

func (c *SessionController) applyUpdateLocked(
	now time.Time,
	update EstablishmentUpdate,
) error {
	for i, datagram := range update.Outbound {
		if len(datagram.Packet) == 0 ||
			!datagram.Destination.IsValid() ||
			datagram.Destination.Port() == 0 {
			return fmt.Errorf(
				"invalid establishment datagram %d: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if err := c.runtime.SendProtocolDatagram(datagram.Packet, datagram.Destination); err != nil {
			return fmt.Errorf("send establishment datagram %d: %w", i, err)
		}
	}

	if update.Material == nil {
		return nil
	}

	session, err := establishment.NewClientSession(*update.Material)
	if err != nil {
		return fmt.Errorf("build established client session: %w", err)
	}
	if _, err := c.core.InstallInitiatorSession(session); err != nil {
		return fmt.Errorf("install established client session: %w", err)
	}

	// Activation is unconditional and independent of application DATA. ACK is
	// not consulted for lifecycle correctness; loss of this packet is recovered
	// by later DATA/keepalive/re-establishment rather than rollback. keepalive_id
	// zero is reserved for this establishment activation so its traffic-shaping
	// policy can differ from ordinary liveness KEEPALIVE/ACK without a new wire
	// subtype.
	op, err := c.core.AdmitKeepalive(
		0,
		dataplane.MaxGeneratedEstablishmentWirePacketSize,
	)
	if err != nil {
		return fmt.Errorf("admit activation transport: %w", err)
	}
	if err := c.runtime.SubmitProtocolTransport(op); err != nil {
		return fmt.Errorf("submit activation transport: %w", err)
	}

	c.attempt = nil
	installedAt, ok := c.core.peer.currentInstalledAt()
	if !ok {
		return fmt.Errorf("installed current session is missing: %w", dataplane.ErrInvalidConfig)
	}
	c.nextAction = installedAt.Add(c.config.SoftRekeyAfter)
	c.clearKeepaliveLocked()
	if c.keepaliveEnabledLocked() {
		c.nextKeepalive = now.Add(c.nextKeepaliveDelay())
	}
	if !c.readyClosed {
		close(c.ready)
		c.readyClosed = true
	}
	return nil
}

func (c *SessionController) keepaliveEnabledLocked() bool {
	return c.config.KeepaliveIntervalMin > 0
}

func (c *SessionController) clearKeepaliveLocked() {
	c.nextKeepalive = time.Time{}
	c.keepaliveID = 0
	c.keepaliveDeadline = time.Time{}
	c.keepaliveTimeouts = 0
}

func (c *SessionController) nextKeepaliveIDLocked() uint64 {
	id := c.nextKeepaliveID
	if id == 0 {
		id = 1
	}
	c.nextKeepaliveID = id + 1
	if c.nextKeepaliveID == 0 {
		c.nextKeepaliveID = 1
	}
	return id
}

func (c *SessionController) nextEstablishmentRetryDelay() time.Duration {
	return randomDuration(c.config.EstablishmentRetryMin, c.config.EstablishmentRetryMax)
}

func (c *SessionController) nextKeepaliveDelay() time.Duration {
	return randomDuration(c.config.KeepaliveIntervalMin, c.config.KeepaliveIntervalMax)
}

func randomDuration(minimum, maximum time.Duration) time.Duration {
	if minimum == maximum {
		return minimum
	}
	return minimum + time.Duration(rand.Int64N(int64(maximum-minimum)+1))
}

func (c *SessionController) nextDueLocked() time.Time {
	next := c.nextAction
	for _, candidate := range [...]time.Time{c.nextKeepalive, c.keepaliveDeadline} {
		if !candidate.IsZero() && (next.IsZero() || candidate.Before(next)) {
			next = candidate
		}
	}
	return next
}

func (c *SessionController) signalWake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
