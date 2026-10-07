package server

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

// TXEngineConfig controls only execution resources. It is not wire protocol
// policy and deliberately contains no rekey/keepalive/session-lifetime knobs.
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

// TXPacket is a fully encrypted UDP datagram passed to the transport sender.
// Wire aliases the output buffer supplied with the corresponding submission and
// remains engine-owned for the duration of TXSendFunc.
type TXPacket struct {
	Wire        []byte
	Destination netip.AddrPort
}

// TXSendFunc is the only transport dependency of TXEngine.
//
// One call contains packets for one Peer and preserves that Peer's admission
// order. Different Peer sender goroutines may call the function concurrently;
// a transport that requires serialization can provide it inside the callback.
//
// Returning an error fails every successfully encrypted packet in that call.
// Packet-local encryption failures are never passed to send. The packet
// descriptor slice is borrowed for the duration of the call and must not be
// retained.
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

// txContainer is published to both the global encryption queue and one ordered
// per-peer queue. Its mutex is a crypto-completion barrier.
type txContainer struct {
	sync.Mutex
	peer     *Peer
	owned    bool
	releaser PacketBufferReleaser
	elems    []*txElement
}

// TXEngine parallelizes packet encryption globally while preserving one
// sequential send stream per Peer.
//
// Session selection, endpoint snapshot and sequence reservation happen BEFORE
// an operation reaches this type. Therefore generation rotation cannot change
// an accepted operation and crypto workers never dereference mutable Peer state.
type TXEngine struct {
	core   *Core
	send   TXSendFunc
	report EngineErrorFunc

	batchSize int

	encryptQueue chan *txContainer
	peerQueues   map[*Peer]chan *txContainer

	elementPool   sync.Pool
	containerPool sync.Pool

	// submitMu makes dual publication and shutdown one atomic ownership domain.
	// The remaining submit* fields are reusable batch scratch protected by it.
	submitMu             sync.Mutex
	submitSeen           map[*OutboundOperation]struct{}
	submitContainers     map[*Peer]*txContainer
	submitContainerOrder []*txContainer
	closed               bool

	workers sync.WaitGroup
	done    chan struct{}
}

func NewTXEngine(
	core *Core,
	config TXEngineConfig,
	send TXSendFunc,
) (*TXEngine, error) {
	return newTXEngine(core, config, send, nil)
}

// NewOwnedTXEngine creates a TX engine whose owned path reports asynchronous
// seal/send failures through report and returns accepted buffers through their
// batch releaser after the ordered send stage.
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
	if core == nil {
		return nil, fmt.Errorf("server core is nil: %w", dataplane.ErrInvalidConfig)
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

	engine := &TXEngine{
		core:             core,
		send:             send,
		report:           report,
		batchSize:        config.BatchSize,
		encryptQueue:     make(chan *txContainer, config.EncryptQueueSize),
		peerQueues:       make(map[*Peer]chan *txContainer, len(core.peersByTunnelIPv4)),
		submitSeen:       make(map[*OutboundOperation]struct{}),
		submitContainers: make(map[*Peer]*txContainer),
		done:             make(chan struct{}),
	}

	for _, peer := range core.peersByTunnelIPv4 {
		if _, exists := engine.peerQueues[peer]; exists {
			continue
		}
		engine.peerQueues[peer] = make(chan *txContainer, config.PeerQueueSize)
	}
	engine.submitContainerOrder = make([]*txContainer, 0, min(config.BatchSize, len(engine.peerQueues)))
	engine.elementPool.New = func() any {
		return new(txElement)
	}
	engine.containerPool.New = func() any {
		return new(txContainer)
	}

	for peer, queue := range engine.peerQueues {
		engine.workers.Add(1)
		go engine.routineSequentialSender(peer, queue)
	}
	for i, scratch := range scratches {
		engine.workers.Add(1)
		go engine.routineEncryption(i, scratch)
	}

	return engine, nil
}

func (e *TXEngine) Enqueue(submission TXSubmission) (<-chan TXResult, error) {
	results, err := e.EnqueueBatch([]TXSubmission{submission})
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

// EnqueueBatch is the compatibility completion-oriented path. It preserves the
// pre-owned-engine behavior and does not inherit BatchSize as a new API limit.
func (e *TXEngine) EnqueueBatch(submissions []TXSubmission) ([]<-chan TXResult, error) {
	if len(submissions) == 0 {
		return nil, nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return nil, ErrTXEngineClosed
	}
	clear(e.submitSeen)
	for i, submission := range submissions {
		op := submission.Operation
		if op == nil || op.peer == nil || op.session == nil {
			clear(e.submitSeen)
			return nil, fmt.Errorf("invalid outbound operation %d: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, exists := e.peerQueues[op.peer]; !exists {
			clear(e.submitSeen)
			return nil, fmt.Errorf("outbound operation %d belongs to unknown engine peer: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, duplicate := e.submitSeen[op]; duplicate {
			clear(e.submitSeen)
			return nil, fmt.Errorf("outbound operation %d is enqueued more than once: %w", i, dataplane.ErrInvalidConfig)
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

	results := make([]<-chan TXResult, len(submissions))
	for i, submission := range submissions {
		op := submission.Operation
		container := e.submitContainers[op.peer]
		if container == nil {
			container = e.getContainer(op.peer, false)
			e.submitContainers[op.peer] = container
			e.submitContainerOrder = append(e.submitContainerOrder, container)
		}

		result := make(chan TXResult, 1)
		elem := e.getElement()
		elem.op = *op
		elem.buffer = submission.Buffer[:0]
		elem.result = result
		container.elems = append(container.elems, elem)
		results[i] = result
	}

	e.publishSubmittedContainers()
	return results, nil
}

// EnqueueOwnedBatch transfers submissions to the engine without creating
// per-packet completion objects. Validation completes before any buffer
// ownership is transferred. Operations are grouped by Peer while preserving
// admission order within each Peer. OutboundOperation is a single-use
// reservation; callers must not submit the same logical operation more than once.
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
	if releaser == nil {
		return fmt.Errorf("owned TX buffer releaser is nil: %w", dataplane.ErrInvalidConfig)
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
		if op.peer == nil || op.session == nil {
			return fmt.Errorf("invalid owned outbound operation %d: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, exists := e.peerQueues[op.peer]; !exists {
			return fmt.Errorf("owned outbound operation %d belongs to unknown engine peer: %w", i, dataplane.ErrInvalidConfig)
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

	for i := range submissions {
		submission := &submissions[i]
		op := &submission.Operation
		container := e.submitContainers[op.peer]
		if container == nil {
			container = e.getContainer(op.peer, true)
			container.releaser = releaser
			e.submitContainers[op.peer] = container
			e.submitContainerOrder = append(e.submitContainerOrder, container)
		}

		elem := e.getElement()
		elem.op = submission.Operation
		elem.buffer = submission.Buffer[:0]
		container.elems = append(container.elems, elem)
	}

	e.publishSubmittedContainers()
	return nil
}

// EnqueueOwned is the single-packet form of EnqueueOwnedBatch.
func (e *TXEngine) EnqueueOwned(submission TXOwnedSubmission, releaser PacketBufferReleaser) error {
	var batch [1]TXOwnedSubmission
	batch[0] = submission
	return e.EnqueueOwnedBatch(batch[:], releaser)
}

func (e *TXEngine) publishSubmittedContainers() {
	for _, container := range e.submitContainerOrder {
		container.Lock()
		e.peerQueues[container.peer] <- container
		e.encryptQueue <- container
	}
	clear(e.submitContainers)
	clear(e.submitContainerOrder)
	e.submitContainerOrder = e.submitContainerOrder[:0]
}

// Close stops admission and drains every accepted container through encryption
// and transport send. It is idempotent.
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
	for _, queue := range e.peerQueues {
		close(queue)
	}
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

func (e *TXEngine) routineSequentialSender(peer *Peer, queue <-chan *txContainer) {
	defer e.workers.Done()

	var packets []TXPacket
	for container := range queue {
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
			packets = append(packets, TXPacket{Wire: elem.wire, Destination: elem.op.destination})
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

func (e *TXEngine) getContainer(peer *Peer, owned bool) *txContainer {
	container := e.containerPool.Get().(*txContainer)
	container.Mutex = sync.Mutex{}
	container.peer = peer
	container.owned = owned
	return container
}

func (e *TXEngine) putContainer(container *txContainer) {
	if cap(container.elems) > pooledContainerCapacityLimit(e.batchSize) {
		container.elems = nil
	} else {
		clear(container.elems)
		container.elems = container.elems[:0]
	}
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
