package server

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// LifecycleConfig is server runtime policy, not wire protocol.
//
// GenerationLifetime is the hard admission lifetime of every traffic
// generation regardless of whether it currently occupies pending, current or
// previous. ReceiveGrace is an additional shorter RX admission bound for the
// previous generation after promotion.
type LifecycleConfig struct {
	GenerationLifetime time.Duration
	ReceiveGrace       time.Duration
}

func (c LifecycleConfig) validate() error {
	if c.GenerationLifetime <= 0 {
		return fmt.Errorf(
			"generation lifetime must be positive: %w",
			dataplane.ErrInvalidConfig,
		)
	}
	if c.ReceiveGrace <= 0 {
		return fmt.Errorf(
			"receive grace must be positive: %w",
			dataplane.ErrInvalidConfig,
		)
	}
	return nil
}

type sessionSlot struct {
	session  *dataplane.Session
	rejectAt time.Time
}

// RXAdmission is an immutable capability for one already-started RX operation.
//
// MayPromote records that the Session was pending at admission. Promotion is
// still conditional at commit: a newer handshake may replace pending before the
// crypto worker finishes, in which case the old admitted packet may complete but
// cannot resurrect its Session as current.
type RXAdmission struct {
	Session    *dataplane.Session
	MayPromote bool
}

// TXDataAdmission is the complete generation-dependent snapshot required by an
// ordinary outbound DATA operation.
type TXDataAdmission struct {
	Session     *dataplane.Session
	Sequence    uint64
	Destination netip.AddrPort
}

// RXCommitResult contains lifecycle side effects that Core mirrors into the
// global sessionsByID index after Peer.mu is released.
type RXCommitResult struct {
	Promoted bool

	// AllowSameSessionResponse is true when it is safe for a response caused by
	// this inbound operation to use the exact admitted Session. In particular,
	// an operation admitted while pending must not produce reverse transport if
	// that generation was superseded before ever becoming active.
	AllowSameSessionResponse bool

	retiredPrevious *dataplane.Session
}

type pendingInstallResult struct {
	installed       *dataplane.Session
	retiredPending  *dataplane.Session
	retiredPrevious *dataplane.Session
}

// Peer owns Session generation placement for one configured client.
// Deadlines are admission deadlines, not cancellation deadlines.
type Peer struct {
	mu      sync.RWMutex
	revoked atomic.Bool

	// Compatibility serialization for direct/synchronous callers only.
	rxCompatMu sync.Mutex

	lifecycle LifecycleConfig

	pending  sessionSlot
	current  sessionSlot
	previous sessionSlot

	// Additional RX-only deadline for previous. Zero means no previous slot.
	previousUntil time.Time
}

func NewPeer(initialCurrent *dataplane.Session, lifecycle LifecycleConfig) (*Peer, error) {
	return newPeerAt(initialCurrent, lifecycle, time.Now())
}

func newPeerAt(
	initialCurrent *dataplane.Session,
	lifecycle LifecycleConfig,
	now time.Time,
) (*Peer, error) {
	if err := lifecycle.validate(); err != nil {
		return nil, err
	}

	peer := &Peer{lifecycle: lifecycle}
	if initialCurrent != nil {
		peer.current = sessionSlot{
			session:  initialCurrent,
			rejectAt: now.Add(lifecycle.GenerationLifetime),
		}
	}
	return peer, nil
}

func (p *Peer) LookupRX(sessionID uint64, receivedAt time.Time) *dataplane.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.revoked.Load() {
		return nil
	}

	if slotRXEligible(p.pending, sessionID, receivedAt) {
		return p.pending.session
	}
	if slotRXEligible(p.current, sessionID, receivedAt) {
		return p.current.session
	}
	if slotRXEligible(p.previous, sessionID, receivedAt) &&
		receivedAt.Before(p.previousUntil) {
		return p.previous.session
	}
	return nil
}

func slotRXEligible(slot sessionSlot, sessionID uint64, receivedAt time.Time) bool {
	return slot.session != nil &&
		slot.session.ID() == sessionID &&
		receivedAt.Before(slot.rejectAt)
}

func (p *Peer) AdmitRX(
	candidate *dataplane.Session,
	receivedAt time.Time,
) (RXAdmission, error) {
	if candidate == nil {
		return RXAdmission{}, ErrSessionNotRXEligible
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.revoked.Load() {
		return RXAdmission{}, ErrPeerRevoked
	}

	if p.pending.session == candidate && receivedAt.Before(p.pending.rejectAt) {
		return RXAdmission{Session: candidate, MayPromote: true}, nil
	}
	if p.current.session == candidate && receivedAt.Before(p.current.rejectAt) {
		return RXAdmission{Session: candidate}, nil
	}
	if p.previous.session == candidate &&
		receivedAt.Before(p.previous.rejectAt) &&
		receivedAt.Before(p.previousUntil) {
		return RXAdmission{Session: candidate}, nil
	}
	return RXAdmission{}, ErrSessionNotRXEligible
}

func (p *Peer) InstallPending(
	session *dataplane.Session,
	now time.Time,
) (*dataplane.Session, error) {
	transition, err := p.installPending(session, now)
	if err != nil {
		return nil, err
	}
	return transition.installed, nil
}

func (p *Peer) installPending(
	session *dataplane.Session,
	now time.Time,
) (pendingInstallResult, error) {
	if session == nil {
		return pendingInstallResult{}, fmt.Errorf(
			"pending session is nil: %w",
			dataplane.ErrInvalidConfig,
		)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked.Load() {
		return pendingInstallResult{}, ErrPeerRevoked
	}

	expiredPending, expiredPrevious := p.dropExpiredLocked(now)

	if p.current.session != nil && p.current.session.ID() == session.ID() {
		return pendingInstallResult{}, ErrSessionIDCollision
	}
	if p.pending.session != nil && p.pending.session.ID() == session.ID() {
		return pendingInstallResult{}, ErrSessionIDCollision
	}
	if p.previous.session != nil && p.previous.session.ID() == session.ID() {
		return pendingInstallResult{}, ErrSessionIDCollision
	}

	retiredPending := expiredPending
	if p.pending.session != nil {
		retiredPending = p.pending.session
	}

	p.pending = sessionSlot{
		session:  session,
		rejectAt: now.Add(p.lifecycle.GenerationLifetime),
	}

	return pendingInstallResult{
		installed:       session,
		retiredPending:  retiredPending,
		retiredPrevious: expiredPrevious,
	}, nil
}

func (p *Peer) CommitAuthenticatedRX(
	admission RXAdmission,
	sequence uint64,
	source netip.AddrPort,
	committedAt time.Time,
) (RXCommitResult, error) {
	p.rxCompatMu.Lock()
	defer p.rxCompatMu.Unlock()
	return p.commitAuthenticatedRXOwned(admission, sequence, source, committedAt)
}

func (p *Peer) commitAuthenticatedRXOwned(
	admission RXAdmission,
	sequence uint64,
	source netip.AddrPort,
	committedAt time.Time,
) (RXCommitResult, error) {
	candidate := admission.Session
	if candidate == nil {
		return RXCommitResult{}, ErrSessionNotRXEligible
	}

	if _, err := candidate.CommitAuthenticatedRX(sequence, source); err != nil {
		return RXCommitResult{}, err
	}

	// A packet admitted as current/previous is proof that this generation had
	// already been active. A causally-generated response may therefore keep using
	// the exact pinned Session even if later rotations happen before commit.
	if !admission.MayPromote {
		return RXCommitResult{AllowSameSessionResponse: true}, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.revoked.Load() {
		return RXCommitResult{}, ErrPeerRevoked
	}

	if p.pending.session != candidate {
		// Another packet may already have promoted candidate. In that case a
		// same-session response is still valid. If candidate is neither current nor
		// previous, conservatively suppress the response: a superseded pending must
		// never manufacture reverse-traffic evidence for a generation that may have
		// never become active.
		allowResponse := p.current.session == candidate || p.previous.session == candidate
		return RXCommitResult{AllowSameSessionResponse: allowResponse}, nil
	}

	oldCurrent := p.current
	oldPrevious := p.previous

	p.current = p.pending // preserve generation rejectAt across promotion
	p.pending = sessionSlot{}

	p.previous = sessionSlot{}
	p.previousUntil = time.Time{}
	if oldCurrent.session != nil {
		p.previous = oldCurrent // preserve old generation rejectAt
		p.previousUntil = committedAt.Add(p.lifecycle.ReceiveGrace)
	}

	return RXCommitResult{
		Promoted:                 true,
		AllowSameSessionResponse: true,
		retiredPrevious:          oldPrevious.session,
	}, nil
}

func (p *Peer) IsRevoked() bool { return p.revoked.Load() }

func (p *Peer) revoke() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked.Store(true)
	p.pending = sessionSlot{}
	p.current = sessionSlot{}
	p.previous = sessionSlot{}
	p.previousUntil = time.Time{}
}

func (p *Peer) hasSession(candidate *dataplane.Session) bool {
	if candidate == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pending.session == candidate ||
		p.current.session == candidate ||
		p.previous.session == candidate
}

// AdmitCurrentData snapshots ordinary TX state. Hard generation expiry is
// checked before reserving a sequence, so a rejected admission consumes no
// nonce/sequence value.
func (p *Peer) AdmitCurrentData(now time.Time) (TXDataAdmission, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.revoked.Load() {
		return TXDataAdmission{}, ErrPeerRevoked
	}

	current := p.current
	if current.session == nil {
		return TXDataAdmission{}, ErrNoCurrentSession
	}
	if !now.Before(current.rejectAt) {
		return TXDataAdmission{}, ErrSessionNotTXEligible
	}

	endpoint, ok := current.session.Endpoint()
	if !ok {
		return TXDataAdmission{}, ErrNoEndpoint
	}

	sequence, err := current.session.ReserveTXSequence()
	if err != nil {
		return TXDataAdmission{}, err
	}

	return TXDataAdmission{
		Session:     current.session,
		Sequence:    sequence,
		Destination: endpoint,
	}, nil
}

func (p *Peer) SealCurrentDataTo(
	scratch *dataplane.DataScratch,
	dst []byte,
	plaintext []byte,
	now time.Time,
) (wire []byte, destination netip.AddrPort, err error) {
	if cap(dst) < len(plaintext)+dataplane.MaxDataExpansion {
		return nil, netip.AddrPort{}, dataplane.ErrBufferTooSmall
	}

	admission, err := p.AdmitCurrentData(now)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	wire, err = admission.Session.SealDataToReserved(
		scratch,
		dst,
		plaintext,
		admission.Sequence,
	)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return wire, admission.Destination, nil
}

func (p *Peer) CurrentSession() *dataplane.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current.session
}

func (p *Peer) dropExpiredLocked(now time.Time) (expiredPending, expiredPrevious *dataplane.Session) {
	if p.pending.session != nil && !now.Before(p.pending.rejectAt) {
		expiredPending = p.pending.session
		p.pending = sessionSlot{}
	}

	if p.previous.session != nil &&
		(!now.Before(p.previous.rejectAt) || !now.Before(p.previousUntil)) {
		expiredPrevious = p.previous.session
		p.previous = sessionSlot{}
		p.previousUntil = time.Time{}
	}

	return expiredPending, expiredPrevious
}
