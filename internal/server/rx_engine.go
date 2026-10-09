package server

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

// RXEngineConfig configures only execution mechanics. None of these values are
// protocol semantics.
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

// RXResult belongs to the compatibility completion-oriented API. Inbound.IPv4
// aliases the receive buffer owned by the submitted InboundOperation.
type RXResult struct {
	Inbound  dataplane.InboundPacket
	Outbound *OutboundOperation
	Err      error
}

// RXOwnedSubmission is the steady-state allocation-free runtime submission
// surface. Engine copies Operation into a pooled work element and takes
// ownership of the packet backing Operation on successful enqueue. Backing
// storage of simultaneously in-flight owned submissions must not overlap.
type RXOwnedSubmission struct {
	Operation InboundOperation
}

// RXOwnedResult is borrowed by the final RX delivery consumer. Buffer is the
// receive buffer backing Inbound.IPv4. Outbound is valid only when HasOutbound
// is true and uses move-style linear ownership when submitted to TXEngine.
type RXOwnedResult struct {
	Inbound     dataplane.InboundPacket
	Buffer      []byte
	Outbound    OutboundOperation
	HasOutbound bool
	Err         error
}

// RXConsumeFunc is the final owned RX delivery consumer. One call may contain
// already committed packets from several Peers. Per-Peer ordering has already
// been enforced before results reach this callback. The result slice and every
// referenced buffer are borrowed for the duration of the call and must not be
// retained.
type RXConsumeFunc func([]RXOwnedResult) error

type rxElement struct {
	op                  InboundOperation
	buffer              []byte
	emitControlResponse bool
	decryptErr          error

	// Owned-path outcome. Stateful commit is performed by the per-Peer ordered
	// receiver; one global delivery worker later batches these outcomes across
	// already-ready Peers before releasing their packet storage.
	inbound     dataplane.InboundPacket
	outbound    OutboundOperation
	hasOutbound bool
	commitErr   error

	result chan RXResult
}

// rxContainer is published to both the global decrypt queue and one ordered
// per-peer queue. Its mutex is a crypto-completion barrier.
type rxContainer struct {
	sync.Mutex
	peer     *Peer
	owned    bool
	releaser PacketBufferReleaser
	elems    []*rxElement
}

// RXEngine parallelizes AEAD globally while preserving one sequential
// replay/lifecycle commit stream per Peer. On the owned path, committed
// containers from all Peers converge on one final delivery queue so TUN/ACK
// vectorization can span Peers without reintroducing per-packet futures.
type RXEngine struct {
	core    *Core
	consume RXConsumeFunc
	report  EngineErrorFunc

	batchSize     int
	peerQueueSize int

	decryptQueue  chan *rxContainer
	peerQueues    map[*Peer]chan *rxContainer // present+nil means registered but not activated
	deliveryQueue chan *rxContainer

	elementPool   sync.Pool
	containerPool sync.Pool

	// submitMu makes dual publication and shutdown one atomic ownership domain.
	// The remaining submit* fields are reusable batch scratch protected by it.
	submitMu             sync.Mutex
	submitSeen           map[*InboundOperation]struct{}
	submitContainers     map[*Peer]*rxContainer
	submitContainerOrder []*rxContainer
	closed               bool

	// workers contains decrypt workers and per-Peer ordered receivers. Delivery
	// is separate because its input queue may only be closed after every ordered
	// receiver has stopped publishing committed containers.
	workers  sync.WaitGroup
	delivery sync.WaitGroup
	done     chan struct{}
}

func NewRXEngine(core *Core, config RXEngineConfig) (*RXEngine, error) {
	return newRXEngine(core, config, nil, nil)
}

// NewOwnedRXEngine creates an RX engine whose owned path converges committed
// containers from all Peers into one cross-Peer batch consumer. Consumer
// failures are asynchronous and are reported through report.
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
	if core == nil {
		return nil, fmt.Errorf("server core is nil: %w", dataplane.ErrInvalidConfig)
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

	engine := &RXEngine{
		core:             core,
		consume:          consume,
		report:           report,
		batchSize:        config.BatchSize,
		peerQueueSize:    config.PeerQueueSize,
		decryptQueue:     make(chan *rxContainer, config.DecryptQueueSize),
		peerQueues:       make(map[*Peer]chan *rxContainer, len(core.peersByTunnelIPv4)),
		submitSeen:       make(map[*InboundOperation]struct{}),
		submitContainers: make(map[*Peer]*rxContainer),
		done:             make(chan struct{}),
	}
	if consume != nil {
		// This queue contains containers that have already passed both AEAD and
		// ordered per-Peer stateful commit. A bounded backlog lets independent
		// Peers keep committing while the single batch I/O consumer is busy.
		engine.deliveryQueue = make(chan *rxContainer, config.DecryptQueueSize)
	}

	for _, peer := range core.peersByTunnelIPv4 {
		if _, exists := engine.peerQueues[peer]; exists {
			continue
		}
		// A nil queue means the Peer is registered with this engine but has not
		// carried traffic yet. The ordered lane is allocated on first submission.
		engine.peerQueues[peer] = nil
	}
	engine.submitContainerOrder = make([]*rxContainer, 0, min(config.BatchSize, len(engine.peerQueues)))
	engine.elementPool.New = func() any {
		return new(rxElement)
	}
	engine.containerPool.New = func() any {
		return new(rxContainer)
	}

	for i, scratch := range scratches {
		engine.workers.Add(1)
		go engine.routineDecryption(i, scratch)
	}
	if engine.deliveryQueue != nil {
		engine.delivery.Add(1)
		go engine.routineDelivery()
	}
	return engine, nil
}

func (e *RXEngine) Enqueue(op *InboundOperation, emitControlResponse bool) (<-chan RXResult, error) {
	results, err := e.EnqueueBatch([]*InboundOperation{op}, emitControlResponse)
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

// EnqueueBatch is the compatibility completion-oriented path. It intentionally
// preserves the pre-owned-engine behavior and does not inherit BatchSize as a
// new API limit; pooled container slices may grow when a compatibility caller
// submits a larger batch.
func (e *RXEngine) EnqueueBatch(
	ops []*InboundOperation,
	emitControlResponse bool,
) ([]<-chan RXResult, error) {
	if len(ops) == 0 {
		return nil, nil
	}

	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return nil, ErrRXEngineClosed
	}

	clear(e.submitSeen)
	for i, op := range ops {
		if op == nil || op.binding.peer == nil || op.admission.Session == nil {
			clear(e.submitSeen)
			return nil, fmt.Errorf("invalid inbound operation %d: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, exists := e.peerQueues[op.binding.peer]; !exists {
			clear(e.submitSeen)
			return nil, fmt.Errorf("inbound operation %d belongs to unknown engine peer: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, duplicate := e.submitSeen[op]; duplicate {
			clear(e.submitSeen)
			return nil, fmt.Errorf("inbound operation %d is enqueued more than once: %w", i, dataplane.ErrInvalidConfig)
		}
		e.submitSeen[op] = struct{}{}
	}
	clear(e.submitSeen)

	results := make([]<-chan RXResult, len(ops))
	for i, op := range ops {
		peer := op.binding.peer
		e.ensurePeerQueueLocked(peer)
		container := e.submitContainers[peer]
		if container == nil {
			container = e.getContainer(peer, false)
			e.submitContainers[peer] = container
			e.submitContainerOrder = append(e.submitContainerOrder, container)
		}

		result := make(chan RXResult, 1)
		elem := e.getElement()
		elem.op = *op
		elem.emitControlResponse = emitControlResponse
		elem.result = result
		container.elems = append(container.elems, elem)
		results[i] = result
	}

	e.publishSubmittedContainers()
	return results, nil
}

// EnqueueOwnedBatch transfers submissions to the engine without creating
// per-packet completion objects. All validation happens before ownership is
// transferred. A single ingress batch may become several per-peer containers;
// BatchSize bounds the owned delivery vector reconstructed after commit.
func (e *RXEngine) EnqueueOwnedBatch(
	submissions []RXOwnedSubmission,
	emitControlResponse bool,
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
	if e.consume == nil || e.report == nil || e.deliveryQueue == nil {
		return fmt.Errorf("owned RX path is not configured: %w", dataplane.ErrInvalidConfig)
	}
	if releaser == nil {
		return fmt.Errorf("owned RX buffer releaser is nil: %w", dataplane.ErrInvalidConfig)
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
		if op.binding.peer == nil || op.admission.Session == nil {
			return fmt.Errorf("invalid owned inbound operation %d: %w", i, dataplane.ErrInvalidConfig)
		}
		if _, exists := e.peerQueues[op.binding.peer]; !exists && !op.binding.peer.IsRevoked() {
			return fmt.Errorf("owned inbound operation %d belongs to unknown engine peer: %w", i, dataplane.ErrInvalidConfig)
		}
		if len(op.packet) == 0 {
			return fmt.Errorf("owned inbound operation %d has empty packet: %w", i, dataplane.ErrInvalidConfig)
		}
	}

	for i := range submissions {
		op := &submissions[i].Operation
		peer := op.binding.peer
		if _, registered := e.peerQueues[peer]; !registered {
			releaser.Put(op.packet)
			continue
		}
		e.ensurePeerQueueLocked(peer)
		container := e.submitContainers[peer]
		if container == nil {
			container = e.getContainer(peer, true)
			container.releaser = releaser
			e.submitContainers[peer] = container
			e.submitContainerOrder = append(e.submitContainerOrder, container)
		}

		elem := e.getElement()
		elem.op = *op
		elem.buffer = elem.op.packet
		elem.emitControlResponse = emitControlResponse
		container.elems = append(container.elems, elem)
	}

	e.publishSubmittedContainers()
	return nil
}

// AddPeer registers a Peer before it becomes visible in Core. Its ordered
// queue and worker are created lazily on the first accepted submission.
func (e *RXEngine) AddPeer(peer *Peer) error {
	if peer == nil {
		return dataplane.ErrInvalidConfig
	}
	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	if e.closed {
		return ErrRXEngineClosed
	}
	if _, exists := e.peerQueues[peer]; exists {
		return dataplane.ErrInvalidConfig
	}
	e.peerQueues[peer] = nil
	return nil
}

// ensurePeerQueueLocked activates the per-Peer ordered lane. submitMu must be
// held by the caller, which serializes activation with RetirePeer and Close.
func (e *RXEngine) ensurePeerQueueLocked(peer *Peer) chan *rxContainer {
	queue, registered := e.peerQueues[peer]
	if !registered {
		return nil
	}
	if queue != nil {
		return queue
	}
	queue = make(chan *rxContainer, e.peerQueueSize)
	e.peerQueues[peer] = queue
	e.workers.Add(1)
	go e.routineSequentialReceiver(peer, queue)
	return queue
}

// RetirePeer prevents new submissions and drains previously accepted work.
func (e *RXEngine) RetirePeer(peer *Peer) {
	e.submitMu.Lock()
	defer e.submitMu.Unlock()
	// Close may already have closed every queue without removing the entries.
	// Never close a channel a second time during daemon shutdown.
	if e.closed {
		return
	}
	if queue, exists := e.peerQueues[peer]; exists {
		delete(e.peerQueues, peer)
		if queue != nil {
			close(queue)
		}
	}
}

func (e *RXEngine) publishSubmittedContainers() {
	for _, container := range e.submitContainerOrder {
		container.Lock()
		e.peerQueues[container.peer] <- container
		e.decryptQueue <- container
	}
	clear(e.submitContainers)
	clear(e.submitContainerOrder)
	e.submitContainerOrder = e.submitContainerOrder[:0]
}

// Close stops admission and drains every operation accepted before the close
// boundary. Ordered receivers finish stateful commit first; only after they
// stop publishing is the global owned delivery queue closed and drained.
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
	for _, queue := range e.peerQueues {
		if queue != nil {
			close(queue)
		}
	}
	clear(e.peerQueues)
	e.submitMu.Unlock()

	e.workers.Wait()
	if e.deliveryQueue != nil {
		close(e.deliveryQueue)
		e.delivery.Wait()
	}
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

func (e *RXEngine) routineSequentialReceiver(peer *Peer, queue <-chan *rxContainer) {
	defer e.workers.Done()

	for container := range queue {
		container.Lock()
		container.Unlock()

		if container.owned {
			if container.peer != peer {
				for _, elem := range container.elems {
					elem.commitErr = dataplane.ErrInvalidConfig
				}
			} else {
				for _, elem := range container.elems {
					if elem.decryptErr != nil {
						elem.commitErr = elem.decryptErr
						continue
					}
					elem.inbound, elem.hasOutbound, elem.commitErr = e.core.commitInboundOwnedInto(
						&elem.op,
						elem.emitControlResponse,
						&elem.outbound,
					)
				}
			}

			// Delivery ownership is transferred as one whole container. This send
			// preserves order for this Peer while allowing already-ready containers
			// from other Peers to be coalesced by the global final stage.
			e.deliveryQueue <- container
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
			inbound, outbound, err := e.core.commitInboundOwned(&elem.op, elem.emitControlResponse)
			elem.finish(RXResult{Inbound: inbound, Outbound: outbound, Err: err})
			e.putElement(elem)
		}
		e.putContainer(container)
	}
}

// routineDelivery is deliberately global rather than per Peer. Expensive AEAD
// and stateful commit remain parallel/per-Peer, while the final I/O-facing stage
// opportunistically reconstructs vectors from whichever committed containers
// are already ready. Unlike the old future collector, it never waits on an
// earlier not-yet-ready packet from another Peer.
func (e *RXEngine) routineDelivery() {
	defer e.delivery.Done()

	var results []RXOwnedResult
	var containers []*rxContainer

	flush := func() {
		if len(results) == 0 {
			return
		}
		if err := e.consume(results); err != nil {
			e.report(err)
		}
		clear(results)
		results = results[:0]

		for _, container := range containers {
			e.recycleOwnedContainer(container)
		}
		clear(containers)
		containers = containers[:0]
	}

	for first := range e.deliveryQueue {
		container := first
		for {
			// Keep consumer vectors within the configured owned batch bound. Each
			// owned container is itself <= batchSize, so a container never needs to
			// be split and can be recycled immediately after one consumer call.
			if len(results) != 0 && len(results)+len(container.elems) > e.batchSize {
				flush()
			}

			containers = append(containers, container)
			for _, elem := range container.elems {
				results = append(results, RXOwnedResult{
					Inbound:     elem.inbound,
					Buffer:      elem.buffer,
					Outbound:    elem.outbound,
					HasOutbound: elem.hasOutbound,
					Err:         elem.commitErr,
				})
			}
			if len(results) >= e.batchSize {
				flush()
			}

			select {
			case next, ok := <-e.deliveryQueue:
				if !ok {
					flush()
					return
				}
				container = next
				continue
			default:
				flush()
			}
			break
		}
	}
	flush()
}

func (e *RXEngine) getElement() *rxElement {
	return e.elementPool.Get().(*rxElement)
}

func (e *RXEngine) putElement(elem *rxElement) {
	elem.op = InboundOperation{}
	elem.buffer = nil
	elem.emitControlResponse = false
	elem.decryptErr = nil
	elem.inbound = dataplane.InboundPacket{}
	elem.outbound = OutboundOperation{}
	elem.hasOutbound = false
	elem.commitErr = nil
	elem.result = nil
	e.elementPool.Put(elem)
}

func (e *RXEngine) getContainer(peer *Peer, owned bool) *rxContainer {
	container := e.containerPool.Get().(*rxContainer)
	container.Mutex = sync.Mutex{}
	container.peer = peer
	container.owned = owned
	return container
}

func (e *RXEngine) putContainer(container *rxContainer) {
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
