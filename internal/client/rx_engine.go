package client

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const (
	DefaultRXDecryptQueueSize = 256
	DefaultRXPeerQueueSize    = 64
)

// RXEngineConfig controls execution resources only. Lifecycle policy remains in
// Peer and is evaluated before an operation enters the engine.
type RXEngineConfig struct {
	DecryptWorkers   int
	DecryptQueueSize int
	PeerQueueSize    int
	BatchSize        int
}

func (c RXEngineConfig) normalized() (RXEngineConfig, error) {
	if c.DecryptWorkers < 0 || c.DecryptQueueSize < 0 || c.PeerQueueSize < 0 || c.BatchSize < 0 {
		return RXEngineConfig{}, fmt.Errorf(
			"negative RX engine configuration: %w",
			dataplane.ErrInvalidConfig,
		)
	}
	if c.DecryptWorkers == 0 {
		c.DecryptWorkers = runtime.GOMAXPROCS(0)
		if c.DecryptWorkers < 1 {
			c.DecryptWorkers = 1
		}
	}
	if c.DecryptQueueSize == 0 {
		c.DecryptQueueSize = DefaultRXDecryptQueueSize
	}
	if c.PeerQueueSize == 0 {
		c.PeerQueueSize = DefaultRXPeerQueueSize
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultEngineBatchSize
	}
	return c, nil
}

// RXResult is the post-AEAD, post-replay, post-lifecycle client event. On the
// owned runtime path Buffer is the receive buffer backing Inbound.IPv4 and is
// borrowed only for the duration of RXConsumeFunc.
type RXResult struct {
	Inbound dataplane.InboundPacket
	Buffer  []byte
	Err     error
}

// RXConsumeFunc is the final ordered RX consumer. The result slice and all
// buffers referenced by it are borrowed for the duration of the call and must
// not be retained.
type RXConsumeFunc func([]RXResult) error

// RXOwnedSubmission is the steady-state allocation-free runtime submission
// surface. Engine copies Operation into a pooled work element and takes
// ownership of the packet backing Operation on successful enqueue. Backing
// storage of simultaneously in-flight owned submissions must not overlap.
type RXOwnedSubmission struct {
	Operation InboundOperation
}

type rxElement struct {
	op         InboundOperation
	buffer     []byte
	decryptErr error
	result     chan RXResult
}

// rxContainer is published to both the global decrypt queue and the one ordered
// client Peer queue. Its mutex is a crypto-completion barrier.
type rxContainer struct {
	sync.Mutex
	peer     *Peer
	owned    bool
	releaser PacketBufferReleaser
	elems    []*rxElement
}

// RXEngine parallelizes AEAD while preserving one sequential replay/lifecycle
// commit stream for the client's single Peer.
type RXEngine struct {
	core    *Core
	consume RXConsumeFunc
	report  EngineErrorFunc

	batchSize int

	decryptQueue chan *rxContainer
	peerQueue    chan *rxContainer

	elementPool   sync.Pool
	containerPool sync.Pool

	// submitSeen is reusable compatibility batch-validation scratch protected by
	// submitMu. The owned path uses move-style value copies: one admitted operation
	// must never be independently submitted more than once.
	submitMu   sync.Mutex
	submitSeen map[*InboundOperation]struct{}
	closed     bool

	workers sync.WaitGroup
	done    chan struct{}
}

func NewRXEngine(core *Core, config RXEngineConfig) (*RXEngine, error) {
	return newRXEngine(core, config, nil, nil)
}

// NewOwnedRXEngine creates an RX engine whose steady-state allocation-free owned path ends
// in consume and reports consumer failures through report.
func NewOwnedRXEngine(
	core *Core,
	config RXEngineConfig,
	consume RXConsumeFunc,
	report EngineErrorFunc,
) (*RXEngine, error) {
	if consume == nil {
		return nil, fmt.Errorf("RX consumer is nil: %w", dataplane.ErrInvalidConfig)
	}
	if report == nil {
		return nil, fmt.Errorf("RX error reporter is nil: %w", dataplane.ErrInvalidConfig)
	}
	return newRXEngine(core, config, consume, report)
}

func newRXEngine(
	core *Core,
	config RXEngineConfig,
	consume RXConsumeFunc,
	report EngineErrorFunc,
) (*RXEngine, error) {
	if core == nil || core.peer == nil {
		return nil, fmt.Errorf("client core is nil: %w", dataplane.ErrInvalidConfig)
	}

	config, err := config.normalized()
	if err != nil {
		return nil, err
	}

	scratches := make([]*dataplane.DataScratch, config.DecryptWorkers)
	for i := range scratches {
		scratches[i], err = core.NewDataScratch()
		if err != nil {
			return nil, fmt.Errorf("create RX decrypt scratch %d: %w", i, err)
		}
	}

	e := &RXEngine{
		core:         core,
		consume:      consume,
		report:       report,
		batchSize:    config.BatchSize,
		decryptQueue: make(chan *rxContainer, config.DecryptQueueSize),
		peerQueue:    make(chan *rxContainer, config.PeerQueueSize),
		submitSeen:   make(map[*InboundOperation]struct{}),
		done:         make(chan struct{}),
	}
	e.elementPool.New = func() any {
		return new(rxElement)
	}
	e.containerPool.New = func() any {
		return &rxContainer{elems: make([]*rxElement, 0, config.BatchSize)}
	}

	e.workers.Add(1)
	go e.routineSequentialReceiver(core.peer)
	for i, scratch := range scratches {
		e.workers.Add(1)
		go e.routineDecryption(i, scratch)
	}
	return e, nil
}

func (e *RXEngine) Enqueue(op *InboundOperation) (<-chan RXResult, error) {
	results, err := e.EnqueueBatch([]*InboundOperation{op})
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

// EnqueueBatch is the compatibility path and preserves the caller's admission
// order for the single client Peer.
func (e *RXEngine) EnqueueBatch(ops []*InboundOperation) ([]<-chan RXResult, error) {
	if len(ops) == 0 {
		return nil, nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return nil, ErrRXEngineClosed
	}
	if len(ops) > e.batchSize {
		return nil, fmt.Errorf(
			"RX batch size %d exceeds configured maximum %d: %w",
			len(ops),
			e.batchSize,
			dataplane.ErrInvalidConfig,
		)
	}

	clear(e.submitSeen)
	for i, op := range ops {
		if op == nil || op.peer != e.core.peer || op.admission.Session == nil {
			clear(e.submitSeen)
			return nil, fmt.Errorf(
				"invalid inbound operation %d: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if _, duplicate := e.submitSeen[op]; duplicate {
			clear(e.submitSeen)
			return nil, fmt.Errorf(
				"inbound operation %d is enqueued more than once: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		e.submitSeen[op] = struct{}{}
	}
	clear(e.submitSeen)

	container := e.getContainer(false)
	results := make([]<-chan RXResult, len(ops))
	for i, op := range ops {
		result := make(chan RXResult, 1)
		elem := e.getElement()
		elem.op = *op
		elem.result = result
		container.elems = append(container.elems, elem)
		results[i] = result
	}

	e.publish(container)
	return results, nil
}

// EnqueueOwnedBatch transfers submissions to the engine without creating
// per-packet completion objects. All validation happens before ownership is
// transferred. The ordered consumer sees one borrowed result vector and the
// engine returns every receive buffer after that call completes.
func (e *RXEngine) EnqueueOwnedBatch(
	submissions []RXOwnedSubmission,
	releaser PacketBufferReleaser,
) error {
	if len(submissions) == 0 {
		return nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return ErrRXEngineClosed
	}
	if e.consume == nil || e.report == nil {
		return fmt.Errorf("owned RX path is not configured: %w", dataplane.ErrInvalidConfig)
	}
	if len(submissions) > e.batchSize {
		return fmt.Errorf(
			"RX batch size %d exceeds configured maximum %d: %w",
			len(submissions),
			e.batchSize,
			dataplane.ErrInvalidConfig,
		)
	}

	for i := range submissions {
		op := &submissions[i].Operation
		if op.peer != e.core.peer || op.admission.Session == nil {
			return fmt.Errorf(
				"invalid owned inbound operation %d: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
		if len(op.packet) == 0 {
			return fmt.Errorf(
				"owned inbound operation %d has empty packet: %w",
				i,
				dataplane.ErrInvalidConfig,
			)
		}
	}

	container := e.getContainer(true)
	container.releaser = releaser
	for i := range submissions {
		submission := &submissions[i]
		elem := e.getElement()
		elem.op = submission.Operation
		elem.buffer = elem.op.packet
		container.elems = append(container.elems, elem)
	}

	e.publish(container)
	return nil
}

func (e *RXEngine) publish(container *rxContainer) {
	container.Lock()
	e.peerQueue <- container
	e.decryptQueue <- container
}

// Close stops admission and drains every operation accepted before the close
// boundary. It is idempotent.
func (e *RXEngine) Close() {
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
	close(e.decryptQueue)
	close(e.peerQueue)
	e.submitMu.Unlock()

	e.workers.Wait()
	close(e.done)
}

func (e *RXEngine) routineDecryption(_ int, scratch *dataplane.DataScratch) {
	defer e.workers.Done()
	for container := range e.decryptQueue {
		for _, elem := range container.elems {
			elem.decryptErr = elem.op.Decrypt(scratch)
		}
		container.Unlock()
	}
}

func (e *RXEngine) routineSequentialReceiver(peer *Peer) {
	defer e.workers.Done()

	results := make([]RXResult, 0, e.batchSize)
	for container := range e.peerQueue {
		container.Lock()
		container.Unlock()

		if container.owned {
			results = results[:0]
			if container.peer != peer {
				for _, elem := range container.elems {
					results = append(results, RXResult{
						Buffer: elem.buffer,
						Err:    dataplane.ErrInvalidConfig,
					})
				}
			} else {
				for _, elem := range container.elems {
					result := RXResult{Buffer: elem.buffer}
					if elem.decryptErr != nil {
						result.Err = elem.decryptErr
					} else {
						result.Inbound, result.Err = e.core.commitInboundOwned(&elem.op)
					}
					results = append(results, result)
				}
			}

			if err := e.consume(results); err != nil {
				e.report(err)
			}
			clear(results)
			e.recycleOwnedContainer(container)
			continue
		}

		if container.peer != peer {
			for _, elem := range container.elems {
				elem.finish(RXResult{Err: dataplane.ErrInvalidConfig})
				e.putElement(elem)
			}
			e.putContainer(container)
			continue
		}

		for _, elem := range container.elems {
			if elem.decryptErr != nil {
				elem.finish(RXResult{Err: elem.decryptErr})
				e.putElement(elem)
				continue
			}
			inbound, err := e.core.commitInboundOwned(&elem.op)
			elem.finish(RXResult{Inbound: inbound, Err: err})
			e.putElement(elem)
		}
		e.putContainer(container)
	}
}

func (e *RXEngine) getElement() *rxElement {
	return e.elementPool.Get().(*rxElement)
}

func (e *RXEngine) putElement(elem *rxElement) {
	elem.op = InboundOperation{}
	elem.buffer = nil
	elem.decryptErr = nil
	elem.result = nil
	e.elementPool.Put(elem)
}

func (e *RXEngine) getContainer(owned bool) *rxContainer {
	container := e.containerPool.Get().(*rxContainer)
	container.Mutex = sync.Mutex{}
	container.peer = e.core.peer
	container.owned = owned
	return container
}

func (e *RXEngine) putContainer(container *rxContainer) {
	for i := range container.elems {
		container.elems[i] = nil
	}
	container.elems = container.elems[:0]
	container.peer = nil
	container.owned = false
	container.releaser = nil
	e.containerPool.Put(container)
}

func (e *RXEngine) releaseElementBuffer(container *rxContainer, elem *rxElement) {
	if container.releaser != nil && elem.buffer != nil {
		container.releaser.Put(elem.buffer)
	}
}

func (e *RXEngine) recycleOwnedContainer(container *rxContainer) {
	for _, elem := range container.elems {
		e.releaseElementBuffer(container, elem)
		e.putElement(elem)
	}
	e.putContainer(container)
}

func (e *rxElement) finish(result RXResult) {
	e.result <- result
	close(e.result)
}
