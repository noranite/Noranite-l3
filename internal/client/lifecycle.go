package client

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// LifecycleConfig is client runtime policy, not wire protocol.
// GenerationLifetime is the hard admission lifetime of one traffic generation.
// ReceiveGrace is the optional shorter RX lifetime of previous after reverse
// traffic proves that the server has reached current (or a later generation).
type LifecycleConfig struct {
	GenerationLifetime time.Duration
	ReceiveGrace       time.Duration
}

func (c LifecycleConfig) validate() error {
	if c.GenerationLifetime <= 0 {
		return fmt.Errorf("generation lifetime must be positive: %w", dataplane.ErrInvalidConfig)
	}
	if c.ReceiveGrace <= 0 {
		return fmt.Errorf("receive grace must be positive: %w", dataplane.ErrInvalidConfig)
	}
	return nil
}

type sessionSlot struct {
	session *dataplane.Session

	rejectAt      time.Time
	shortRejectAt time.Time
}

// RXAdmission pins the exact generation selected before AEAD. Later rotation or
// deadline expiry cannot revoke this already-started operation.
type RXAdmission struct {
	Session    *dataplane.Session
	ReceivedAt time.Time
}

// TXAdmission pins the exact current generation and a unique sequence before
// parallel encryption begins.
type TXAdmission struct {
	Session  *dataplane.Session
	Sequence uint64
}

// RXCommitResult reports lifecycle effects of ordered authenticated RX commit.
type RXCommitResult struct {
	ArmedPreviousGrace bool
}

// Peer owns the fixed-role initiator lifecycle: current + previous only.
type Peer struct {
	mu sync.RWMutex

	// Direct callers are serialized; the RX engine uses its ordered owner path.
	rxCompatMu sync.Mutex

	lifecycle LifecycleConfig
	current   sessionSlot
	previous  sessionSlot
}

func NewPeer(
	initialCurrent *dataplane.Session,
	lifecycle LifecycleConfig,
	installedAt time.Time,
) (*Peer, error) {
	if err := lifecycle.validate(); err != nil {
		return nil, err
	}
	peer := &Peer{lifecycle: lifecycle}
	if initialCurrent != nil {
		peer.current = sessionSlot{
			session:  initialCurrent,
			rejectAt: installedAt.Add(lifecycle.GenerationLifetime),
		}
	}
	return peer, nil
}

// InstallInitiatorSession atomically performs old previous -> retired,
// old current -> previous, new -> current. Short grace for the new previous is
// deliberately unarmed until authenticated reverse transport arrives on current.
func (p *Peer) InstallInitiatorSession(
	session *dataplane.Session,
	now time.Time,
) (*dataplane.Session, error) {
	if session == nil {
		return nil, fmt.Errorf("session is nil: %w", dataplane.ErrInvalidConfig)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.current.session != nil && p.current.session.ID() == session.ID() {
		return nil, ErrSessionIDCollision
	}
	if p.previous.session != nil && p.previous.session.ID() == session.ID() {
		return nil, ErrSessionIDCollision
	}

	retired := p.previous.session
	p.previous = p.current
	p.previous.shortRejectAt = time.Time{}
	p.current = sessionSlot{
		session:  session,
		rejectAt: now.Add(p.lifecycle.GenerationLifetime),
	}
	return retired, nil
}

// AdmitRX performs lookup and lifecycle admission atomically and returns the
// exact Session capability to be used by the operation.
func (p *Peer) AdmitRX(sessionID uint64, receivedAt time.Time) (RXAdmission, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.current.session != nil && p.current.session.ID() == sessionID {
		if receivedAt.Before(p.current.rejectAt) {
			return RXAdmission{Session: p.current.session, ReceivedAt: receivedAt}, nil
		}
		return RXAdmission{}, ErrSessionNotRXEligible
	}

	if p.previous.session != nil && p.previous.session.ID() == sessionID {
		if receivedAt.Before(p.previous.rejectAt) &&
			(p.previous.shortRejectAt.IsZero() || receivedAt.Before(p.previous.shortRejectAt)) {
			return RXAdmission{Session: p.previous.session, ReceivedAt: receivedAt}, nil
		}
		return RXAdmission{}, ErrSessionNotRXEligible
	}

	return RXAdmission{}, ErrUnknownSession
}

// CommitAuthenticatedRX is the synchronous compatibility commit. AEAD must have
// succeeded before this call. Replay commit happens before lifecycle grace
// arming, matching the server/WireGuard ordering invariant.
func (p *Peer) CommitAuthenticatedRX(
	admission RXAdmission,
	sequence uint64,
	source netip.AddrPort,
) (RXCommitResult, error) {
	p.rxCompatMu.Lock()
	defer p.rxCompatMu.Unlock()
	return p.commitAuthenticatedRXOwned(admission, sequence, source)
}

func (p *Peer) commitAuthenticatedRXOwned(
	admission RXAdmission,
	sequence uint64,
	source netip.AddrPort,
) (RXCommitResult, error) {
	candidate := admission.Session
	if candidate == nil {
		return RXCommitResult{}, ErrSessionNotRXEligible
	}

	if _, err := candidate.CommitAuthenticatedRX(sequence, source); err != nil {
		return RXCommitResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Exact identity is the stale-completion guard. A packet admitted on B but
	// committed after Install(C) may update B's Session-local replay/endpoint
	// state, but it cannot arm retirement of B while C is current.
	if p.current.session != candidate ||
		p.previous.session == nil ||
		!p.previous.shortRejectAt.IsZero() {
		return RXCommitResult{}, nil
	}

	p.previous.shortRejectAt = admission.ReceivedAt.Add(p.lifecycle.ReceiveGrace)
	return RXCommitResult{ArmedPreviousGrace: true}, nil
}

// AdmitCurrentTX checks hard generation lifetime before sequence reservation.
// Rejected expiry therefore consumes no nonce/sequence value.
func (p *Peer) AdmitCurrentTX(now time.Time) (TXAdmission, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.current.session == nil {
		return TXAdmission{}, ErrNoCurrentSession
	}
	if !now.Before(p.current.rejectAt) {
		return TXAdmission{}, ErrSessionNotTXEligible
	}

	sequence, err := p.current.session.ReserveTXSequence()
	if err != nil {
		return TXAdmission{}, err
	}
	return TXAdmission{Session: p.current.session, Sequence: sequence}, nil
}

func (p *Peer) CurrentSession() *dataplane.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current.session
}

// currentTXEligible reports whether current exists and is still inside its hard
// generation lifetime without reserving a sequence number. It is used only by
// orchestration decisions such as transport migration.
func (p *Peer) currentTXEligible(now time.Time) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current.session != nil && now.Before(p.current.rejectAt)
}

// currentInstalledAt returns the installation time of current, derived from the
// immutable generation hard deadline. It is used only by orchestration to place
// the soft rekey trigger relative to the actual generation lifetime.
func (p *Peer) currentInstalledAt() (time.Time, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.current.session == nil {
		return time.Time{}, false
	}
	return p.current.rejectAt.Add(-p.lifecycle.GenerationLifetime), true
}

// LookupRX is a diagnostic/test helper; production RX should use AdmitRX.
func (p *Peer) LookupRX(sessionID uint64, receivedAt time.Time) *dataplane.Session {
	admission, err := p.AdmitRX(sessionID, receivedAt)
	if err != nil {
		return nil
	}
	return admission.Session
}
