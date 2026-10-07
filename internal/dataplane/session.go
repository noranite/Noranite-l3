package dataplane

import (
	"crypto/cipher"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// Session is the dataplane state of one concrete Opaque-L3 crypto generation.
//
// A Session deliberately does NOT know whether it is pending/current/previous.
// That is Peer lifecycle state. Packet operations pin a *Session and are then
// allowed to finish even if Peer rotates to a newer generation meanwhile.
type Session struct {
	// id and AEAD instances are immutable after construction.
	id uint64
	tx cipher.AEAD
	rx cipher.AEAD

	// txSequence is shared by independent TX producers. Reserving a sequence is
	// the only mutable operation required before work can be handed to a parallel
	// crypto worker.
	//
	// The stored value is the NEXT sequence to reserve. MaxUint64 is a terminal
	// sentinel and is never returned to a packet operation.
	txSequence atomic.Uint64

	// replay has exactly one owner: the per-peer sequential RX consumer.
	// There is intentionally no replay mutex. A runtime that calls
	// CommitAuthenticatedRX concurrently for the same Session violates the
	// Session concurrency contract.
	replay ReplayWindow

	// Endpoint is independent mutable metadata. RX sequential consumer writes it;
	// TX admission reads a snapshot before creating an outbound operation.
	endpointMu    sync.RWMutex
	endpoint      netip.AddrPort
	endpointKnown bool
}

// NewSession creates one crypto generation from already-derived directional
// traffic keys.
func NewSession(
	id uint64,
	txKey, rxKey [32]byte,
	initialTxSequence uint64,
) (*Session, error) {
	if id == 0 {
		return nil, fmt.Errorf(
			"session id is zero: %w",
			ErrInvalidConfig,
		)
	}

	tx, err := chacha20poly1305.New(txKey[:])
	if err != nil {
		return nil, fmt.Errorf("create tx AEAD: %w", err)
	}

	rx, err := chacha20poly1305.New(rxKey[:])
	if err != nil {
		return nil, fmt.Errorf("create rx AEAD: %w", err)
	}

	s := &Session{
		id: id,
		tx: tx,
		rx: rx,
	}
	s.txSequence.Store(initialTxSequence)
	return s, nil
}

// ID returns the immutable wire session identifier.
func (s *Session) ID() uint64 {
	return s.id
}

// ReserveTXSequence permanently allocates one sequence for a future outbound
// packet operation.
//
// Reservation happens before parallel encryption. Once this method succeeds,
// the sequence is consumed forever even if later packet construction or AEAD
// fails. This is intentional: a nonce must never be reused.
func (s *Session) ReserveTXSequence() (uint64, error) {
	for {
		next := s.txSequence.Load()
		if next == ^uint64(0) {
			return 0, ErrSequenceExhausted
		}
		if s.txSequence.CompareAndSwap(next, next+1) {
			return next, nil
		}
	}
}

// SealDataTo is the ordinary production DATA surface. It validates caller
// storage before consuming Session state, reserves a sequence, and then performs
// stateless packet construction for that reserved operation.
func (s *Session) SealDataTo(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
) (wire []byte, sequence uint64, err error) {
	return s.sealTo(scratch, dst, plaintext)
}

func (s *Session) sealTo(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
) (wire []byte, sequence uint64, err error) {
	// Production padding is selected only after sequence reservation. Check the
	// worst case first so a caller buffer error never consumes a sequence and
	// success never depends on the selected random-looking padding length.
	if cap(dst) < len(plaintext)+MaxDataExpansion {
		return nil, 0, ErrBufferTooSmall
	}

	sequence, err = s.ReserveTXSequence()
	if err != nil {
		return nil, 0, err
	}

	wire, err = s.SealDataToReserved(
		scratch,
		dst,
		plaintext,
		sequence,
	)
	return wire, sequence, err
}

// SealDataToReserved finishes a DATA operation whose sequence has already been
// allocated by ReserveTXSequence.
//
// This is the worker-facing API: it reads only immutable Session crypto state.
// Callers MUST pass a unique sequence previously reserved from this Session.
// The method cannot verify ownership of that reservation without reintroducing
// shared mutable bookkeeping into the hot path.
func (s *Session) SealDataToReserved(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
	sequence uint64,
) ([]byte, error) {
	paddingLength := nextDataPaddingLength(scratch.paddingRNG)
	return s.sealDataToWithPaddingReserved(
		scratch,
		dst,
		plaintext,
		paddingLength,
		sequence,
	)
}

// SealDataToWithPadding is the deterministic variant used by protocol tests and
// callers with an explicit padding policy.
func (s *Session) SealDataToWithPadding(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
	paddingLength int,
) (wire []byte, sequence uint64, err error) {
	return s.sealToWithPadding(scratch, dst, plaintext, paddingLength)
}

func (s *Session) sealToWithPadding(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
	paddingLength int,
) (wire []byte, sequence uint64, err error) {
	if paddingLength < 0 || paddingLength > MaxDataPadding {
		return nil, 0, ErrInvalidPadding
	}

	required := len(plaintext) + paddingLength + DataOverhead
	if cap(dst) < required {
		return nil, 0, ErrBufferTooSmall
	}

	sequence, err = s.ReserveTXSequence()
	if err != nil {
		return nil, 0, err
	}

	wire, err = s.sealDataToWithPaddingReserved(
		scratch,
		dst,
		plaintext,
		paddingLength,
		sequence,
	)
	return wire, sequence, err
}

// sealDataToWithPaddingReserved prepares DATA plaintext for a sequence already
// owned by the caller. No Session TX state is modified here.
func (s *Session) sealDataToWithPaddingReserved(
	scratch *DataScratch,
	dst []byte,
	plaintext []byte,
	paddingLength int,
	sequence uint64,
) ([]byte, error) {
	if paddingLength < 0 || paddingLength > MaxDataPadding {
		return nil, ErrInvalidPadding
	}

	required := len(plaintext) + paddingLength + DataOverhead
	if cap(dst) < required {
		return nil, ErrBufferTooSmall
	}

	packet := dst[:required]
	plaintextStart := RouteSize
	plaintextEnd := plaintextStart + len(plaintext)
	paddedPlaintextEnd := plaintextEnd + paddingLength

	// copy is overlap-safe, so TUN may read directly into storage that already
	// contains RouteSize bytes of headroom.
	copy(packet[plaintextStart:plaintextEnd], plaintext)
	clear(packet[plaintextEnd:paddedPlaintextEnd])

	return s.sealPreparedPlaintext(
		scratch,
		packet,
		sequence,
	)
}

// sealPreparedPlaintext performs common DATA/CONTROL AEAD + opaque-route
// construction for an already reserved sequence.
//
// Layout on entry:
//
//	[ route reservation ][ plaintext ][ tag reservation ]
//
// The function is safe to run concurrently for the same Session provided each
// caller owns a distinct sequence and its own DataScratch/buffer.
func (s *Session) sealPreparedPlaintext(
	scratch *DataScratch,
	packet []byte,
	sequence uint64,
) ([]byte, error) {
	if len(packet) < DataOverhead+1 {
		return nil, ErrPacketTooShort
	}

	plaintextEnd := len(packet) - TagSize
	nonce := scratch.nonceForSequence(sequence)

	wire := packet[:RouteSize:len(packet)]
	aad := scratch.routeAADFor(s.id, sequence)
	wire = s.tx.Seal(
		wire,
		nonce,
		packet[RouteSize:plaintextEnd],
		aad,
	)

	tag := wire[len(wire)-TagSize:]
	mask, err := scratch.routeMask(tag)
	if err != nil {
		// The caller already reserved sequence. It remains consumed on error.
		return nil, err
	}

	opaque := encodeRoute(s.id, sequence, mask)
	copy(wire[:RouteSize], opaque[:])
	return wire, nil
}

// AuthenticateInPlace performs only the expensive cryptographic RX phase:
// AEAD authentication + in-place decryption.
//
// It intentionally changes no replay, endpoint or Peer lifecycle state. That
// mutable work belongs to the per-peer sequential RX consumer after the packet
// operation has already been admitted by lifecycle.
func (s *Session) AuthenticateInPlace(
	scratch *DataScratch,
	packet []byte,
	sequence uint64,
) ([]byte, error) {
	if len(packet) < MinWirePacketSize {
		return nil, ErrPacketTooShort
	}

	sealed := packet[RouteSize:]
	nonce := scratch.nonceForSequence(sequence)
	aad := scratch.routeAADFor(s.id, sequence)

	plaintext, err := s.rx.Open(
		sealed[:0],
		nonce,
		sealed,
		aad,
	)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// CommitAuthenticatedRX commits authenticated mutable Session state.
//
// CONCURRENCY CONTRACT: one sequential RX consumer owns replay for a Session.
// This method must not be called concurrently for the same Session. Keeping
// replay single-owner is deliberate; synchronization is supplied by the packet
// engine rather than a mutex hidden in every replay operation.
//
// Endpoint has its own small lock because TX admission may read it concurrently
// while sequential RX learns a newer authenticated source.
func (s *Session) CommitAuthenticatedRX(
	sequence uint64,
	source netip.AddrPort,
) (advanced bool, err error) {
	if !source.IsValid() || source.Port() == 0 {
		return false, fmt.Errorf(
			"invalid source endpoint: %w",
			ErrInvalidConfig,
		)
	}

	accepted, advanced := s.replay.Accept(sequence)
	if !accepted {
		return false, ErrReplay
	}

	if advanced {
		s.endpointMu.Lock()
		s.endpoint = source
		s.endpointKnown = true
		s.endpointMu.Unlock()
	}

	return advanced, nil
}

// Endpoint returns an authenticated endpoint snapshot for TX admission.
func (s *Session) Endpoint() (netip.AddrPort, bool) {
	s.endpointMu.RLock()
	defer s.endpointMu.RUnlock()
	return s.endpoint, s.endpointKnown
}

// TxSequence returns the next sequence that ReserveTXSequence would allocate.
// It is intended for tests and diagnostics.
func (s *Session) TxSequence() uint64 {
	return s.txSequence.Load()
}
