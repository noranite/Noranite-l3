package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/establishment"
)

const (
	keepaliveTimeoutsBeforeRekey       = 2
	activityProbeIdle                  = 30 * time.Second
	defaultActivityProbeTimeout        = 5 * time.Second
	defaultEstablishmentAttemptTimeout = 90 * time.Second
	maxPostAbandonDemandCooldown       = 5 * time.Second
)

// SessionControllerConfig is orchestration policy above the fixed
// current/previous crypto lifecycle.
//
// SoftRekeyAfter is measured from the installation time of the current traffic
// generation. Without persistent keepalive, crossing it only marks the Session
// for rekey: the next application DATA starts make-before-break establishment.
// Establishment retry and periodic keepalive schedules choose a fresh uniform
// delay inside their inclusive [Min, Max] ranges after each successful scheduling
// point. Provider-local/internal failures are terminal and are surfaced to the
// runtime; only network loss/rejection is represented by an update with no
// completion.
type SessionControllerConfig struct {
	SoftRekeyAfter time.Duration

	EstablishmentRetryMin time.Duration
	EstablishmentRetryMax time.Duration
	// EstablishmentAttemptTimeout bounds one continuous establishment cycle.
	// Zero uses defaultEstablishmentAttemptTimeout. After the budget is exhausted,
	// ordinary DATA is briefly suppressed so queued device backlog cannot
	// immediately start another full cycle. Explicit rekey and transport rebound
	// bypass that suppression.
	EstablishmentAttemptTimeout time.Duration

	// KeepaliveIntervalMin/Max are an optional persistent keepalive policy for
	// keeping an idle NAT mapping open. When no usable Session exists, enabling
	// this policy also permits background bounded establishment cycles at the same
	// cadence. All zero disables persistent keepalive.
	//
	// KeepaliveTimeout is required when persistent keepalive is enabled. Activity-
	// driven liveness probes remain enabled even when periodic keepalive is off;
	// in that case their timeout defaults to defaultActivityProbeTimeout.
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
	if c.EstablishmentAttemptTimeout < 0 {
		return fmt.Errorf(
			"establishment attempt timeout must not be negative: %w",
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

	attempt               EstablishmentAttempt
	attemptStartedAt      time.Time
	nextAction            time.Time
	demandRetryAfter      time.Time
	usable                chan struct{}
	usableOpen            bool
	demandAbandoned       chan struct{}
	demandAbandonedClosed bool

	nextKeepalive          time.Time
	keepaliveProofBaseline time.Time
	outstandingProbeID     uint64
	probeStartedAt         time.Time
	lastProbeQueuedAt      time.Time
	keepaliveDeadline      time.Time
	keepaliveTimeouts      int
	nextKeepaliveID        uint64
	lastPeerProof          time.Time
	pathNeedsProof         bool

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
	var next time.Time
	var nextKeepalive time.Time
	var lastPeerProof time.Time
	hasCurrent := false
	if installedAt, ok := core.peer.currentInstalledAt(); ok {
		hasCurrent = true
		lastPeerProof = installedAt
		if config.KeepaliveIntervalMin > 0 {
			next = installedAt.Add(config.SoftRekeyAfter)
			if next.Before(now) {
				next = now
			}
			nextKeepalive = now.Add(randomDuration(config.KeepaliveIntervalMin, config.KeepaliveIntervalMax))
		}
	} else if config.KeepaliveIntervalMin > 0 {
		// Persistent keepalive is an explicit request for background connectivity,
		// so it also activates the first Session without waiting for application DATA.
		next = now
	}
	usable := make(chan struct{})
	usableOpen := true
	if core.peer.currentTXEligible(now) {
		close(usable)
		usableOpen = false
	}

	controller := &SessionController{
		core:                   core,
		runtime:                runtime,
		factory:                factory,
		config:                 config,
		clock:                  clock,
		nextAction:             next,
		usable:                 usable,
		usableOpen:             usableOpen,
		demandAbandoned:        make(chan struct{}),
		nextKeepalive:          nextKeepalive,
		keepaliveProofBaseline: lastPeerProof,
		nextKeepaliveID:        1,
		lastPeerProof:          lastPeerProof,
		ready:                  make(chan struct{}),
		wake:                   make(chan struct{}, 1),
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

// OutboundDemandWait describes the outcome of one outbound demand cycle.
// Usable closes when a current Session can carry DATA. Abandoned closes when a
// bounded establishment cycle ends without producing one. Callers holding a
// packet should drop that packet on Abandoned. Immediately queued DATA may also
// be abandoned during the short post-cycle cool-off; later demand can start a
// fresh cycle.
type OutboundDemandWait struct {
	Usable    <-chan struct{}
	Abandoned <-chan struct{}
}

// RequestRekey coalesces with an already-active establishment attempt. If no
// attempt is active, it moves the next establishment start to now.
func (c *SessionController) RequestRekey() {
	if c == nil {
		return
	}

	now := c.clock.Now()
	c.mu.Lock()
	c.demandRetryAfter = time.Time{}
	if c.attempt == nil && (c.nextAction.IsZero() || c.nextAction.After(now)) {
		c.nextAction = now
	}
	c.mu.Unlock()
	c.signalWake()
}

// TransportRebound reports that the runtime has successfully replaced or
// rebound the outer transport after a network change. Protocol state survives.
// Active establishment retries immediately on the new path. An idle usable
// Session stays silent; ordinary DATA will teach the server the new endpoint.
// Persistent keepalive remains background-active when explicitly configured.
//
// Any outstanding KEEPALIVE belongs to the old path and is forgotten without
// counting it as a liveness failure. Call this only after the replacement
// transport is ready to send.
func (c *SessionController) TransportRebound() {
	if c == nil {
		return
	}

	now := c.clock.Now()
	wake := false
	c.mu.Lock()
	c.demandRetryAfter = time.Time{}
	activityRecovery := !c.keepaliveEnabledLocked() && c.activityRecoveryActiveLocked()
	c.outstandingProbeID = 0
	c.probeStartedAt = time.Time{}
	c.lastProbeQueuedAt = time.Time{}
	c.keepaliveDeadline = time.Time{}
	c.keepaliveTimeouts = 0

	switch {
	case c.attempt != nil:
		c.nextKeepalive = time.Time{}
		c.keepaliveProofBaseline = time.Time{}
		// A replacement transport is a materially new network condition. Give the
		// active attempt a fresh bounded budget rather than letting an old-path
		// deadline immediately discard the first retry on the new path.
		c.attemptStartedAt = now
		c.nextAction = now
		wake = true
	case c.keepaliveEnabledLocked() && c.core.peer.currentTXEligible(now):
		// Persistent keepalive explicitly asks for background reachability. On a
		// new outer path, refresh the mapping/endpoint immediately.
		c.nextKeepalive = now
		c.keepaliveProofBaseline = c.refreshLastPeerProofLocked()
		c.pathNeedsProof = false
		wake = true
	case c.keepaliveEnabledLocked():
		c.nextKeepalive = time.Time{}
		c.keepaliveProofBaseline = time.Time{}
		c.pathNeedsProof = false
		c.nextAction = now
		wake = true
	case c.core.peer.currentTXEligible(now):
		// Rebound invalidates knowledge about the outer path, but an idle Session
		// must remain silent. The next admitted DATA will request proof. If DATA had
		// already activated recovery on the old path, preserve that demand and probe
		// immediately on the replacement transport.
		c.pathNeedsProof = true
		if activityRecovery {
			c.nextKeepalive = now
			wake = true
		} else {
			c.nextKeepalive = time.Time{}
		}
	default:
		c.nextKeepalive = time.Time{}
		c.keepaliveProofBaseline = time.Time{}
		c.pathNeedsProof = false
	}
	c.mu.Unlock()
	if wake {
		c.signalWake()
	}
}

// HandleOutboundDemand is called before admitting one application DATA packet.
// It keeps a usable current Session on the fast path, starts first-use or
// hard-expiry establishment when needed, and turns soft rekey into a demand-
// driven make-before-break operation when persistent keepalive is disabled.
// The returned wait closes Usable when DATA may be admitted through current, or
// Abandoned if a bounded no-current establishment cycle ends first.
func (c *SessionController) HandleOutboundDemand() OutboundDemandWait {
	if c == nil {
		return OutboundDemandWait{}
	}

	now := c.clock.Now()
	wake := false
	c.mu.Lock()
	if c.core.peer.currentTXEligible(now) {
		c.closeUsableLocked()
		c.openDemandAbandonedLocked()
		if c.attempt == nil && c.softRekeyDueLocked(now) &&
			(c.nextAction.IsZero() || c.nextAction.After(now)) {
			c.nextAction = now
			wake = true
		}
	} else {
		c.openUsableLocked()
		if c.attempt == nil && !c.demandRetryAfter.IsZero() && now.Before(c.demandRetryAfter) {
			// A just-exhausted no-current cycle may have left a device/TUN backlog.
			// Drop that backlog without allowing each queued packet to buy another
			// complete establishment budget. No timer is needed: the first DATA after
			// the cool-off will activate a new cycle normally.
			c.closeDemandAbandonedLocked()
		} else if c.attempt == nil {
			c.demandRetryAfter = time.Time{}
			c.openDemandAbandonedLocked()
		}
		c.clearKeepaliveLocked()
		if c.attempt == nil && !c.demandAbandonedClosed &&
			(c.nextAction.IsZero() || c.nextAction.After(now)) {
			c.nextAction = now
			wake = true
		}
	}
	wait := OutboundDemandWait{
		Usable:    c.usable,
		Abandoned: c.demandAbandoned,
	}
	c.mu.Unlock()
	if wake {
		c.signalWake()
	}
	return wait
}

// HandleOutboundActivity reports one admitted ordinary DATA transmission.
// If the current generation has not produced authenticated reverse traffic for
// activityProbeIdle, the controller schedules one immediate liveness probe.
// Further DATA does not create additional probes while one is outstanding.
func (c *SessionController) HandleOutboundActivity() {
	if c == nil {
		return
	}

	now := c.clock.Now()
	wake := false
	c.mu.Lock()
	if c.attempt == nil && c.outstandingProbeID == 0 {
		lastProof := c.refreshLastPeerProofLocked()
		if c.pathNeedsProof || lastProof.IsZero() || now.Sub(lastProof) >= activityProbeIdle {
			if c.nextKeepalive.IsZero() || c.nextKeepalive.After(now) {
				c.nextKeepalive = now
				c.keepaliveProofBaseline = lastProof
				wake = true
			}
		} else if c.keepaliveEnabledLocked() {
			// Ordinary DATA already refreshes the outer NAT mapping, so periodic
			// keepalive is measured from this real traffic rather than emitted on
			// top of an active tunnel.
			c.schedulePersistentKeepaliveLocked(now)
		}
	}
	c.mu.Unlock()
	if wake {
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

// Run drives scheduled establishment retry and optional persistent keepalive.
// With persistent keepalive disabled, an idle usable Session has no timer here;
// first use and soft rekey are activated by HandleOutboundDemand. Runtime owns
// socket lifetime; when runtime Done closes, controller exits without generating
// more protocol traffic.
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

		if next.IsZero() {
			select {
			case <-c.wake:
			case <-c.runtime.Done():
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}

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

	// Missing authenticated current-generation RX after a probe is evidence that
	// the installed generation may no longer exist at the peer or that the path
	// is losing traffic. Protocol recovery is ordinary fresh establishment;
	// socket lifetime remains runtime policy.
	if !c.keepaliveDeadline.IsZero() && !c.keepaliveDeadline.After(now) {
		lastProof := c.refreshLastPeerProofLocked()
		if !c.probeStartedAt.IsZero() && lastProof.After(c.probeStartedAt) {
			lastProbeAt := c.lastProbeQueuedAt
			c.outstandingProbeID = 0
			c.probeStartedAt = time.Time{}
			c.lastProbeQueuedAt = time.Time{}
			c.keepaliveDeadline = time.Time{}
			c.keepaliveTimeouts = 0
			if c.keepaliveEnabledLocked() && c.attempt == nil {
				c.schedulePersistentKeepaliveLocked(lastProbeAt)
				if c.nextKeepalive.Before(now) {
					c.nextKeepalive = now
				}
			} else {
				c.nextKeepalive = time.Time{}
			}
		} else {
			c.outstandingProbeID = 0
			c.lastProbeQueuedAt = time.Time{}
			c.keepaliveDeadline = time.Time{}
			c.keepaliveTimeouts++
		}

		if c.keepaliveTimeouts >= keepaliveTimeoutsBeforeRekey {
			c.nextKeepalive = time.Time{}
			c.probeStartedAt = time.Time{}
			c.keepaliveTimeouts = 0
			if c.attempt == nil && (c.nextAction.IsZero() || c.nextAction.After(now)) {
				c.nextAction = now
			}
		} else if c.keepaliveTimeouts > 0 && c.attempt == nil {
			// One probe without authenticated reverse traffic must not force a Noise
			// exchange. Retry liveness once with a fresh KEEPALIVE/sequence.
			c.nextKeepalive = now
		}
	}

	if !c.nextAction.IsZero() && !c.nextAction.After(now) {
		if c.attempt == nil {
			c.clearKeepaliveLocked()
			c.openDemandAbandonedLocked()
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
			if c.attempt != nil {
				c.attemptStartedAt = now
			}
			if err := c.applyUpdateLocked(now, update); err != nil {
				return err
			}
			if c.attempt != nil {
				c.scheduleNextEstablishmentActionLocked(now)
			}
			return nil
		}

		if c.establishmentAttemptExpiredLocked(now) {
			c.abandonEstablishmentLocked(now)
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
			c.scheduleNextEstablishmentActionLocked(now)
		}
		return nil
	}

	if c.attempt == nil &&
		c.outstandingProbeID == 0 &&
		!c.nextKeepalive.IsZero() &&
		!c.nextKeepalive.After(now) {
		if c.keepaliveEnabledLocked() && c.probeStartedAt.IsZero() && c.keepaliveTimeouts == 0 {
			lastProof := c.refreshLastPeerProofLocked()
			if lastProof.After(c.keepaliveProofBaseline) {
				c.schedulePersistentKeepaliveLocked(lastProof)
				if c.nextKeepalive.After(now) {
					return nil
				}
			}
		}
		keepaliveID := c.nextKeepaliveIDLocked()
		op, err := c.core.AdmitKeepalive(keepaliveID, dataplane.MaxGeneratedControlWirePacketSize)
		if err != nil {
			if errors.Is(err, ErrNoCurrentSession) || errors.Is(err, ErrSessionNotTXEligible) {
				c.clearKeepaliveLocked()
				if c.attempt == nil && (c.nextAction.IsZero() || c.nextAction.After(now)) {
					c.nextAction = now
				}
				return nil
			}
			return fmt.Errorf("admit keepalive: %w", err)
		}
		if err := c.runtime.SubmitProtocolTransport(op); err != nil {
			return fmt.Errorf("submit keepalive: %w", err)
		}
		queuedAt := c.clock.Now()
		c.outstandingProbeID = keepaliveID
		if c.probeStartedAt.IsZero() {
			c.probeStartedAt = queuedAt
		}
		c.lastProbeQueuedAt = queuedAt
		c.keepaliveDeadline = queuedAt.Add(c.keepaliveTimeoutLocked())
		c.nextKeepalive = time.Time{}
		c.pathNeedsProof = false
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
	c.attemptStartedAt = time.Time{}
	installedAt, ok := c.core.peer.currentInstalledAt()
	if !ok {
		return fmt.Errorf("installed current session is missing: %w", dataplane.ErrInvalidConfig)
	}
	c.nextAction = time.Time{}
	c.demandRetryAfter = time.Time{}
	c.lastPeerProof = installedAt
	c.pathNeedsProof = false
	c.clearKeepaliveLocked()
	if c.keepaliveEnabledLocked() {
		c.nextAction = installedAt.Add(c.config.SoftRekeyAfter)
		c.schedulePersistentKeepaliveLocked(installedAt)
	}
	c.closeUsableLocked()
	c.openDemandAbandonedLocked()
	if !c.readyClosed {
		close(c.ready)
		c.readyClosed = true
	}
	return nil
}

func (c *SessionController) keepaliveEnabledLocked() bool {
	return c.config.KeepaliveIntervalMin > 0
}

func (c *SessionController) activityRecoveryActiveLocked() bool {
	return c.outstandingProbeID != 0 ||
		!c.probeStartedAt.IsZero() ||
		!c.keepaliveDeadline.IsZero() ||
		c.keepaliveTimeouts > 0 ||
		!c.nextKeepalive.IsZero()
}

func (c *SessionController) keepaliveTimeoutLocked() time.Duration {
	if c.config.KeepaliveTimeout > 0 {
		return c.config.KeepaliveTimeout
	}
	return defaultActivityProbeTimeout
}

func (c *SessionController) refreshLastPeerProofLocked() time.Time {
	if lastRX := c.core.peer.lastAuthenticatedCurrentRX(); lastRX.After(c.lastPeerProof) {
		c.lastPeerProof = lastRX
	}
	return c.lastPeerProof
}

func (c *SessionController) softRekeyDueLocked(now time.Time) bool {
	installedAt, ok := c.core.peer.currentInstalledAt()
	return ok && !now.Before(installedAt.Add(c.config.SoftRekeyAfter))
}

func (c *SessionController) establishmentAttemptTimeoutLocked() time.Duration {
	if c.config.EstablishmentAttemptTimeout > 0 {
		return c.config.EstablishmentAttemptTimeout
	}
	return defaultEstablishmentAttemptTimeout
}

func (c *SessionController) postAbandonDemandCooldownLocked() time.Duration {
	if c.config.EstablishmentRetryMax < maxPostAbandonDemandCooldown {
		return c.config.EstablishmentRetryMax
	}
	return maxPostAbandonDemandCooldown
}

func (c *SessionController) establishmentAttemptExpiredLocked(now time.Time) bool {
	return c.attempt != nil &&
		!c.attemptStartedAt.IsZero() &&
		!now.Before(c.attemptStartedAt.Add(c.establishmentAttemptTimeoutLocked()))
}

func (c *SessionController) scheduleNextEstablishmentActionLocked(now time.Time) {
	deadline := c.attemptStartedAt.Add(c.establishmentAttemptTimeoutLocked())
	next := now.Add(c.nextEstablishmentRetryDelay())
	if next.After(deadline) {
		next = deadline
	}
	c.nextAction = next
}

func (c *SessionController) abandonEstablishmentLocked(now time.Time) {
	c.attempt = nil
	c.attemptStartedAt = time.Time{}
	c.nextAction = time.Time{}
	c.clearKeepaliveLocked()

	if c.core.peer.currentTXEligible(now) {
		c.closeUsableLocked()
		if c.keepaliveEnabledLocked() {
			// The bounded Noise cycle itself produced recent outbound traffic. Resume
			// the explicitly requested idle keepalive policy from here, but do not
			// immediately start another establishment cycle.
			c.schedulePersistentKeepaliveLocked(now)
		}
		return
	}

	// A packet waiting for first-use/hard-expiry establishment must not keep one
	// failed demand alive forever. Wake its owner so that packet can be dropped.
	// Suppress ordinary DATA briefly so already-queued device backlog cannot
	// immediately start another complete establishment budget. Persistent
	// keepalive is explicit background-connectivity demand, so after an exhausted
	// cycle it may start a fresh bounded cycle at its normal cadence.
	c.demandRetryAfter = now.Add(c.postAbandonDemandCooldownLocked())
	c.openUsableLocked()
	c.closeDemandAbandonedLocked()
	if c.keepaliveEnabledLocked() {
		c.nextAction = now.Add(c.nextKeepaliveDelay())
	}
}

func (c *SessionController) openUsableLocked() {
	if c.usableOpen {
		return
	}
	c.usable = make(chan struct{})
	c.usableOpen = true
}

func (c *SessionController) openDemandAbandonedLocked() {
	if !c.demandAbandonedClosed {
		return
	}
	c.demandAbandoned = make(chan struct{})
	c.demandAbandonedClosed = false
}

func (c *SessionController) closeDemandAbandonedLocked() {
	if c.demandAbandonedClosed {
		return
	}
	close(c.demandAbandoned)
	c.demandAbandonedClosed = true
}

func (c *SessionController) closeUsableLocked() {
	if !c.usableOpen {
		return
	}
	close(c.usable)
	c.usableOpen = false
}

func (c *SessionController) clearKeepaliveLocked() {
	c.nextKeepalive = time.Time{}
	c.keepaliveProofBaseline = time.Time{}
	c.outstandingProbeID = 0
	c.probeStartedAt = time.Time{}
	c.lastProbeQueuedAt = time.Time{}
	c.keepaliveDeadline = time.Time{}
	c.keepaliveTimeouts = 0
}

func (c *SessionController) schedulePersistentKeepaliveLocked(base time.Time) {
	c.keepaliveProofBaseline = c.refreshLastPeerProofLocked()
	c.nextKeepalive = base.Add(c.nextKeepaliveDelay())
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
