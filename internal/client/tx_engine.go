package client

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const (
	DefaultTXEncryptQueueSize = 256
	DefaultTXPeerQueueSize    = 64
)

// TXEngineConfig controls execution resources only.
type TXEngineConfig struct {
	EncryptWorkers   int
	EncryptQueueSize int
	PeerQueueSize    int
	BatchSize        int
}

func (c TXEngineConfig) normalized() (TXEngineConfig, error) {
	if c.EncryptWorkers < 0 || c.EncryptQueueSize < 0 || c.PeerQueueSize < 0 || c.BatchSize < 0 {
		return TXEngineConfig{}, fmt.Errorf(
			"negative TX engine configuration: %w",
			dataplane.ErrInvalidConfig,
		)
	}
	if c.EncryptWorkers == 0 {
		c.EncryptWorkers = runtime.GOMAXPROCS(0)
		if c.EncryptWorkers < 1 {
			c.EncryptWorkers = 1
		}
	}
	if c.EncryptQueueSize == 0 {
		c.EncryptQueueSize = DefaultTXEncryptQueueSize
	}
	if c.PeerQueueSize == 0 {
		c.PeerQueueSize = DefaultTXPeerQueueSize
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultEngineBatchSize
	}
	return c, nil
}

// TXPacket is a fully encrypted UDP datagram. Wire aliases the submission
// buffer and remains engine-owned for the duration of TXSendFunc.
type TXPacket struct {
	Wire        []byte
	Destination netip.AddrPort
}

// TXSendFunc is the transport dependency of TXEngine. Calls are serialized for
// the client's single Peer and preserve enqueue order. The packet descriptor
// slice is borrowed for the duration of the call and must not be retained.
type TXSendFunc func([]TXPacket) error

// TXSubmission is the compatibility submission surface. Operation and Buffer
// remain caller-owned until the returned completion fires.
type TXSubmission struct {
	Operation *OutboundOperation
	Buffer    []byte
}

// TXOwnedSubmission is the steady-state allocation-free runtime submission
// surface. Engine copies Operation into a pooled work element and takes
// ownership of Buffer on successful enqueue. EnqueueOwnedBatch supplies the
// batch-wide buffer releaser. Backing storage of simultaneously in-flight
// owned submissions must not overlap.
type TXOwnedSubmission struct {
	Operation OutboundOperation
	Buffer    []byte
}

// TXResult belongs to the compatibility Enqueue/EnqueueBatch API.
type TXResult struct {
	Err error
}

type txElement struct {
	op      OutboundOperation
	buffer  []byte
	wire    []byte
	sealErr error
	result  chan TXResult
}

type txContainer struct {
	sync.Mutex
	peer     *Peer
	owned    bool
	releaser PacketBufferReleaser
	elems    []*txElement
}

// TXEngine parallelizes encryption while preserving one ordered transport-send
// stream. Lifecycle has already been resolved by OutboundOperation admission.
type TXEngine struct {
	core   *Core
	send   TXSendFunc
	report EngineErrorFunc

	batchSize int

	encryptQueue chan *txContainer
	peerQueue    chan *txContainer

	elementPool   sync.Pool
	containerPool sync.Pool

	// submitSeen is reusable compatibility batch-validation scratch protected by
	// submitMu. The owned path uses move-style value copies: one admitted operation
	// must never be independently submitted more than once.
	submitMu   sync.Mutex
	submitSeen map[*OutboundOperation]struct{}
	closed     bool

	workers sync.WaitGroup
	done    chan struct{}
}

func NewTXEngine(core *Core, config TXEngineConfig, send TXSendFunc) (*TXEngine, error) {
	return newTXEngine(core, config, send, nil)
}

// NewOwnedTXEngine creates a TX engine whose steady-state allocation-free owned path reports
// asynchronous seal/send failures through report.
func NewOwnedTXEngine(
	core *Core,
	config TXEngineConfig,
	send TXSendFunc,
	report EngineErrorFunc,
) (*TXEngine, error) {
	if report == nil {
		return nil, fmt.Errorf("TX error reporter is nil: %w", dataplane.ErrInvalidConfig)
	}
	return newTXEngine(core, config, send, report)
}

func newTXEngine(
	core *Core,
	config TXEngineConfig,
	send TXSendFunc,
	report EngineErrorFunc,
) (*TXEngine, error) {
	if core == nil || core.peer == nil {
		return nil, fmt.Errorf("client core is nil: %w", dataplane.ErrInvalidConfig)
	}
	if send == nil {
		return nil, fmt.Errorf("TX send function is nil: %w", dataplane.ErrInvalidConfig)
	}

	config, err := config.normalized()
	if err != nil {
		return nil, err
	}

	scratches := make([]*dataplane.DataScratch, config.EncryptWorkers)
	for i := range scratches {
		scratches[i], err = core.NewDataScratch()
		if err != nil {
			return nil, fmt.Errorf("create TX encrypt scratch %d: %w", i, err)
		}
	}

	e := &TXEngine{
		core:         core,
		send:         send,
		report:       report,
		batchSize:    config.BatchSize,
		encryptQueue: make(chan *txContainer, config.EncryptQueueSize),
		peerQueue:    make(chan *txContainer, config.PeerQueueSize),
		submitSeen:   make(map[*OutboundOperation]struct{}),
		done:         make(chan struct{}),
	}
	e.elementPool.New = func() any {
		return new(txElement)
	}
	e.containerPool.New = func() any {
		return &txContainer{elems: make([]*txElement, 0, config.BatchSize)}
	}

	e.workers.Add(1)
	go e.routineSequentialSender(core.peer)
	for i, scratch := range scratches {
		e.workers.Add(1)
		go e.routineEncryption(i, scratch)
	}
	return e, nil
}

func (e *TXEngine) Enqueue(submission TXSubmission) (<-chan TXResult, error) {
	results, err := e.EnqueueBatch([]TXSubmission{submission})
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

func (e *TXEngine) EnqueueBatch(submissions []TXSubmission) ([]<-chan TXResult, error) {
	if len(submissions) == 0 {
		return nil, nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return nil, ErrTXEngineClosed
	}
	if len(submissions) > e.batchSize {
		return nil, fmt.Errorf(
			"TX batch size %d exceeds configured maximum %d: %w",
			len(submissions),
			e.batchSize,
			dataplane.ErrInvalidConfig,
		)
	}

	clear(e.submitSeen)
	for i, submission := range submissions {
		op := submission.Operation
		if op == nil || op.peer != e.core.peer || op.session == nil {
			clear(e.submitSeen)
			return nil, fmt.Errorf(
				"invalid outbound operation %d: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if _, duplicate := e.submitSeen[op]; duplicate {
			clear(e.submitSeen)
			return nil, fmt.Errorf(
				"outbound operation %d is enqueued more than once: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if cap(submission.Buffer) < op.MaxWireSize() {
			clear(e.submitSeen)
			return nil, fmt.Errorf(
				"outbound operation %d output capacity %d, need %d: %w",
				i,
				cap(submission.Buffer),
				op.MaxWireSize(),
				dataplane.ErrBufferTooSmall,
			)
		}
		e.submitSeen[op] = struct{}{}
	}
	clear(e.submitSeen)

	container := e.getContainer(false)
	results := make([]<-chan TXResult, len(submissions))
	for i, submission := range submissions {
		result := make(chan TXResult, 1)
		elem := e.getElement()
		elem.op = *submission.Operation
		elem.buffer = submission.Buffer[:0]
		elem.result = result
		container.elems = append(container.elems, elem)
		results[i] = result
	}

	e.publish(container)
	return results, nil
}

// EnqueueOwnedBatch transfers submissions to the engine without creating
// per-packet completion objects. All validation happens before ownership is
// transferred. The sequential sender returns each buffer through releaser.
func (e *TXEngine) EnqueueOwnedBatch(
	submissions []TXOwnedSubmission,
	releaser PacketBufferReleaser,
) error {
	if len(submissions) == 0 {
		return nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return ErrTXEngineClosed
	}
	if e.report == nil {
		return fmt.Errorf("owned TX path has no error reporter: %w", dataplane.ErrInvalidConfig)
	}
	if len(submissions) > e.batchSize {
		return fmt.Errorf(
			"TX batch size %d exceeds configured maximum %d: %w",
			len(submissions),
			e.batchSize,
			dataplane.ErrInvalidConfig,
		)
	}

	for i := range submissions {
		submission := &submissions[i]
		op := &submission.Operation
		if op.peer != e.core.peer || op.session == nil {
			return fmt.Errorf(
				"invalid owned outbound operation %d: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if cap(submission.Buffer) < op.MaxWireSize() {
			return fmt.Errorf(
				"owned outbound operation %d output capacity %d, need %d: %w",
				i,
				cap(submission.Buffer),
				op.MaxWireSize(),
				dataplane.ErrBufferTooSmall,
			)
		}
	}

	container := e.getContainer(true)
	container.releaser = releaser
	for i := range submissions {
		submission := &submissions[i]
		elem := e.getElement()
		elem.op = submission.Operation
		elem.buffer = submission.Buffer[:0]
		container.elems = append(container.elems, elem)
	}

	e.publish(container)
	return nil
}

// EnqueueOwned is the single-packet form of EnqueueOwnedBatch.
func (e *TXEngine) EnqueueOwned(
	submission TXOwnedSubmission,
	releaser PacketBufferReleaser,
) error {
	var batch [1]TXOwnedSubmission
	batch[0] = submission
	return e.EnqueueOwnedBatch(batch[:], releaser)
}

func (e *TXEngine) publish(container *txContainer) {
	container.Lock()
	e.peerQueue <- container
	e.encryptQueue <- container
}

// Close stops admission and drains accepted work through encryption and send.
func (e *TXEngine) Close() {
	if e == nil {
		return
	}

	e.submitMu.Lock()
	if e.closed {
		done := e.done
		e.submitMu.Unlock()
		<-done
		return
	}
	e.closed = true
	close(e.encryptQueue)
	close(e.peerQueue)
	e.submitMu.Unlock()

	e.workers.Wait()
	close(e.done)
}

func (e *TXEngine) routineEncryption(_ int, scratch *dataplane.DataScratch) {
	defer e.workers.Done()
	for container := range e.encryptQueue {
		for _, elem := range container.elems {
			elem.wire, elem.sealErr = elem.op.SealTo(scratch, elem.buffer)
		}
		container.Unlock()
	}
}

func (e *TXEngine) routineSequentialSender(peer *Peer) {
	defer e.workers.Done()

	packets := make([]TXPacket, 0, e.batchSize)
	for container := range e.peerQueue {
		container.Lock()
		container.Unlock()

		if container.peer != peer {
			if container.owned {
				e.report(dataplane.ErrInvalidConfig)
				e.recycleOwnedContainer(container)
			} else {
				for _, elem := range container.elems {
					elem.finish(TXResult{Err: dataplane.ErrInvalidConfig})
					e.putElement(elem)
				}
				e.putContainer(container)
			}
			continue
		}

		packets = packets[:0]
		for _, elem := range container.elems {
			if elem.sealErr != nil {
				continue
			}
			packets = append(packets, TXPacket{
				Wire:        elem.wire,
				Destination: elem.op.destination,
			})
		}

		var sendErr error
		if len(packets) != 0 {
			sendErr = e.send(packets)
		}
		clear(packets)

		if container.owned {
			for _, elem := range container.elems {
				if elem.sealErr != nil {
					e.report(elem.sealErr)
				}
				e.releaseElementBuffer(container, elem)
				e.putElement(elem)
			}
			if sendErr != nil {
				e.report(sendErr)
			}
			e.putContainer(container)
			continue
		}

		for _, elem := range container.elems {
			if elem.sealErr != nil {
				elem.finish(TXResult{Err: elem.sealErr})
			} else {
				elem.finish(TXResult{Err: sendErr})
			}
			e.putElement(elem)
		}
		e.putContainer(container)
	}
}

func (e *TXEngine) getElement() *txElement {
	return e.elementPool.Get().(*txElement)
}

func (e *TXEngine) putElement(elem *txElement) {
	elem.op = OutboundOperation{}
	elem.buffer = nil
	elem.wire = nil
	elem.sealErr = nil
	elem.result = nil
	e.elementPool.Put(elem)
}

func (e *TXEngine) getContainer(owned bool) *txContainer {
	container := e.containerPool.Get().(*txContainer)
	container.Mutex = sync.Mutex{}
	container.peer = e.core.peer
	container.owned = owned
	return container
}

func (e *TXEngine) putContainer(container *txContainer) {
	for i := range container.elems {
		container.elems[i] = nil
	}
	container.elems = container.elems[:0]
	container.peer = nil
	container.owned = false
	container.releaser = nil
	e.containerPool.Put(container)
}

func (e *TXEngine) releaseElementBuffer(container *txContainer, elem *txElement) {
	if container.releaser != nil && elem.buffer != nil {
		container.releaser.Put(elem.buffer)
	}
}

func (e *TXEngine) recycleOwnedContainer(container *txContainer) {
	for _, elem := range container.elems {
		e.releaseElementBuffer(container, elem)
		e.putElement(elem)
	}
	e.putContainer(container)
}

func (e *txElement) finish(result TXResult) {
	e.result <- result
	close(e.result)
}
