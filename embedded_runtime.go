package noranite

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	coreclient "github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
)

const (
	embeddedRuntimeBatchSize   = coreclient.DefaultEngineBatchSize
	embeddedRuntimeBufferCount = embeddedRuntimeBatchSize * 4
)

var _ coreclient.SessionControllerRuntime = (*embeddedRuntime)(nil)

// clientDatagramDemux is the same-socket establishment classifier used before
// encrypted transport admission. packet aliases reusable receive storage and
// must not be retained after the call returns.
type clientDatagramDemux interface {
	HandleDatagram(
		source netip.AddrPort,
		route dataplane.Route,
		routeDecoded bool,
		packet []byte,
	) (handled bool, err error)
}

type clientActivityEventSink interface {
	HandleOutboundDemand() coreclient.OutboundDemandWait
	HandleOutboundActivity()
}

type embeddedRuntime struct {
	device         PacketDevice
	serverEndpoint netip.AddrPort
	core           *coreclient.Core
	mtu            int

	admitScratch *dataplane.DataScratch
	writer       *connectedDatagramWriter
	txEngine     *coreclient.TXEngine
	rxEngine     *coreclient.RXEngine
	txPool       *packetPool
	rxPool       *packetPool

	rxDeviceWrite [][]byte
	demux         clientDatagramDemux
	eventSink     clientActivityEventSink

	errC              chan error
	transportFailures chan TransportFailure

	protocolMu        sync.Mutex
	protocolAccepting bool

	// transportProcessMu keeps shared RX scratch and protocol demux single-owner
	// while old/new socket readers briefly overlap. Replacement itself does not
	// take this lock; packets already in flight are ordinary UDP reordering.
	transportProcessMu sync.Mutex
	transportMu        sync.Mutex
	transport          *embeddedTransportGeneration
	transportID        uint64
	transportStarted   bool
	transportClosing   bool
	transportWG        sync.WaitGroup

	stateMu sync.Mutex
	started bool
	ready   chan struct{}
	done    chan struct{}
	stop    chan struct{}

	closeOnce      sync.Once
	closeErr       error
	closeRequested bool
}

type embeddedTransportGeneration struct {
	id        uint64
	conn      net.Conn
	closeOnce sync.Once
	closeErr  error
}

func (g *embeddedTransportGeneration) close() error {
	if g == nil || g.conn == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.closeErr = g.conn.Close()
	})
	return g.closeErr
}

func newEmbeddedRuntime(
	device PacketDevice,
	transport net.Conn,
	core *coreclient.Core,
	serverEndpoint netip.AddrPort,
	mtu int,
) (*embeddedRuntime, error) {
	if device == nil || core == nil || !serverEndpoint.IsValid() {
		return nil, fmt.Errorf("invalid embedded runtime input: %w", dataplane.ErrInvalidConfig)
	}
	if mtu < dataplane.MinTunnelMTU || mtu > dataplane.MaxTunnelMTU {
		return nil, fmt.Errorf(
			"invalid embedded runtime MTU %d, want [%d, %d]: %w",
			mtu,
			dataplane.MinTunnelMTU,
			dataplane.MaxTunnelMTU,
			dataplane.ErrInvalidConfig,
		)
	}

	admitScratch, err := core.NewDataScratch()
	if err != nil {
		return nil, fmt.Errorf("create client ingress scratch: %w", err)
	}

	wireBufferSize := MaxWireDatagramSize(mtu)

	r := &embeddedRuntime{
		device:            device,
		serverEndpoint:    serverEndpoint,
		core:              core,
		mtu:               mtu,
		admitScratch:      admitScratch,
		txPool:            newPacketPool(wireBufferSize, embeddedRuntimeBufferCount),
		rxPool:            newPacketPool(wireBufferSize, embeddedRuntimeBufferCount),
		rxDeviceWrite:     make([][]byte, 0, embeddedRuntimeBatchSize),
		errC:              make(chan error, 1),
		transportFailures: make(chan TransportFailure, 1),
		ready:             make(chan struct{}),
		done:              make(chan struct{}),
		stop:              make(chan struct{}),
	}
	if transport != nil {
		r.transportID = 1
		r.transport = &embeddedTransportGeneration{id: 1, conn: transport}
	}
	r.writer = &connectedDatagramWriter{runtime: r, serverEndpoint: serverEndpoint}

	report := func(err error) {
		if err == nil {
			return
		}
		select {
		case r.errC <- err:
		default:
		}
	}

	txEngine, err := coreclient.NewOwnedTXEngine(
		core,
		coreclient.TXEngineConfig{BatchSize: embeddedRuntimeBatchSize},
		r.writer.Send,
		report,
	)
	if err != nil {
		return nil, fmt.Errorf("create embedded client TX engine: %w", err)
	}
	r.txEngine = txEngine

	rxEngine, err := coreclient.NewOwnedRXEngine(
		core,
		coreclient.RXEngineConfig{BatchSize: embeddedRuntimeBatchSize},
		r.consumeRXResults,
		report,
	)
	if err != nil {
		txEngine.Close()
		return nil, fmt.Errorf("create embedded client RX engine: %w", err)
	}
	r.rxEngine = rxEngine

	return r, nil
}

func (r *embeddedRuntime) disposeConstructionFailure() {
	if r == nil {
		return
	}
	if r.rxEngine != nil {
		r.rxEngine.Close()
	}
	if r.txEngine != nil {
		r.txEngine.Close()
	}
}

func (r *embeddedRuntime) disposeUnstarted() error {
	if r == nil {
		return nil
	}
	closeErr := r.closeIngress(false)
	if r.rxEngine != nil {
		r.rxEngine.Close()
	}
	if r.txEngine != nil {
		r.txEngine.Close()
	}
	r.stateMu.Lock()
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	r.stateMu.Unlock()
	return closeErr
}

func (r *embeddedRuntime) SendProtocolDatagram(packet []byte, destination netip.AddrPort) error {
	if r == nil || len(packet) == 0 {
		return fmt.Errorf("invalid protocol datagram: %w", dataplane.ErrInvalidConfig)
	}

	r.protocolMu.Lock()
	defer r.protocolMu.Unlock()
	if !r.protocolAccepting {
		return fmt.Errorf("embedded runtime is not accepting protocol traffic")
	}

	if err := r.writer.WriteDatagram(packet, destination); err != nil {
		r.report(err)
		return err
	}
	return nil
}

func (r *embeddedRuntime) SubmitProtocolTransport(op *coreclient.OutboundOperation) error {
	if r == nil || op == nil || op.MaxWireSize() <= 0 {
		return fmt.Errorf("invalid protocol transport operation: %w", dataplane.ErrInvalidConfig)
	}

	r.protocolMu.Lock()
	defer r.protocolMu.Unlock()
	if !r.protocolAccepting {
		return fmt.Errorf("embedded runtime is not accepting protocol traffic")
	}

	buffer := make([]byte, op.MaxWireSize())
	return r.txEngine.EnqueueOwned(coreclient.TXOwnedSubmission{
		Operation: *op,
		Buffer:    buffer[:0],
	}, nil)
}

func (r *embeddedRuntime) Ready() <-chan struct{} {
	if r == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return r.ready
}

func (r *embeddedRuntime) Done() <-chan struct{} {
	if r == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return r.done
}

func (r *embeddedRuntime) requestClose() error {
	if r == nil {
		return nil
	}
	return r.closeIngress(true)
}

func (r *embeddedRuntime) closeIngress(requested bool) error {
	if requested {
		r.stateMu.Lock()
		r.closeRequested = true
		r.stateMu.Unlock()
	}

	r.closeOnce.Do(func() {
		close(r.stop)

		r.transportMu.Lock()
		r.transportClosing = true
		transport := r.transport
		r.transport = nil
		r.transportMu.Unlock()

		var transportErr error
		if transport != nil {
			transportErr = transport.close()
		}
		r.closeErr = errors.Join(r.device.Close(), transportErr)
	})
	return r.closeErr
}

func (r *embeddedRuntime) replaceTransport(transport net.Conn) (uint64, error) {
	if r == nil || transport == nil {
		return 0, fmt.Errorf("invalid replacement transport: %w", dataplane.ErrInvalidConfig)
	}

	r.transportMu.Lock()
	if r.transportClosing {
		r.transportMu.Unlock()
		return 0, ErrClientClosed
	}

	r.transportID++
	if r.transportID == 0 {
		r.transportID++
	}
	next := &embeddedTransportGeneration{id: r.transportID, conn: transport}
	previous := r.transport
	r.transport = next
	select {
	case <-r.transportFailures:
	default:
	}
	if r.transportStarted {
		r.startTransportReaderLocked(next)
	}
	r.transportMu.Unlock()

	// Publish before closing the old generation. A late old Read/Close error is
	// therefore stale and cannot tear down the newly current transport.
	if previous != nil {
		_ = previous.close()
	}
	return next.id, nil
}

func (r *embeddedRuntime) startTransportReaderLocked(generation *embeddedTransportGeneration) {
	if generation == nil || generation.conn == nil || r.transportClosing {
		return
	}
	r.transportWG.Add(1)
	go func() {
		defer r.transportWG.Done()
		if err := r.runTransportGeneration(generation); err != nil {
			r.report(err)
		}
	}()
}

func (r *embeddedRuntime) invalidateTransport(generation *embeddedTransportGeneration, cause error) {
	if r == nil || generation == nil {
		return
	}
	r.transportMu.Lock()
	current := r.transport == generation
	signal := current && !r.transportClosing
	if signal {
		r.transport = nil
	}
	r.transportMu.Unlock()
	if current {
		_ = generation.close()
	}
	if signal {
		event := TransportFailure{Generation: generation.id, Err: cause}
		select {
		case r.transportFailures <- event:
		default:
		}
	}
}

func (r *embeddedRuntime) report(err error) {
	if err == nil {
		return
	}
	select {
	case r.errC <- err:
	default:
	}
}

func (r *embeddedRuntime) Run() error {
	if r == nil {
		return fmt.Errorf("embedded runtime is nil: %w", dataplane.ErrInvalidConfig)
	}

	r.stateMu.Lock()
	if r.started {
		r.stateMu.Unlock()
		return ErrClientStarted
	}
	r.started = true
	r.stateMu.Unlock()

	r.protocolMu.Lock()
	r.protocolAccepting = true
	r.protocolMu.Unlock()

	var ingressWG sync.WaitGroup
	ingressWG.Add(1)

	go func() {
		defer ingressWG.Done()
		if err := r.runDeviceIngress(); err != nil {
			r.report(err)
		}
	}()

	r.transportMu.Lock()
	r.transportStarted = true
	if r.transport != nil {
		r.startTransportReaderLocked(r.transport)
	}
	r.transportMu.Unlock()

	close(r.ready)

	var firstErr error
	select {
	case firstErr = <-r.errC:
	case <-r.stop:
		firstErr = net.ErrClosed
	}
	r.closeIngress(false)
	ingressWG.Wait()
	r.transportWG.Wait()

	// Keep protocol TX open until accepted RX is fully drained.
	r.rxEngine.Close()

	r.protocolMu.Lock()
	r.protocolAccepting = false
	r.protocolMu.Unlock()
	r.txEngine.Close()

	close(r.done)

	r.stateMu.Lock()
	requested := r.closeRequested
	r.stateMu.Unlock()
	if requested && (errors.Is(firstErr, net.ErrClosed) || errors.Is(firstErr, io.ErrClosedPipe)) {
		return nil
	}
	return firstErr
}

func (r *embeddedRuntime) writePackets(packets [][]byte) error {
	if r == nil {
		return fmt.Errorf("embedded runtime is nil: %w", dataplane.ErrInvalidConfig)
	}
	if len(packets) == 0 {
		return nil
	}

	select {
	case <-r.ready:
	case <-r.stop:
		return ErrClientClosed
	case <-r.done:
		return ErrClientStopped
	}

	for len(packets) > 0 {
		count := len(packets)
		if count > embeddedRuntimeBatchSize {
			count = embeddedRuntimeBatchSize
		}
		if err := r.submitBorrowedPacketBatch(packets[:count]); err != nil {
			return err
		}
		packets = packets[count:]
	}
	return nil
}

func (r *embeddedRuntime) waitOutboundDemand() bool {
	if r.eventSink == nil {
		return true
	}
	demand := r.eventSink.HandleOutboundDemand()
	select {
	case <-demand.Usable:
		return true
	case <-demand.Abandoned:
		return false
	case <-r.stop:
		return false
	}
}

func (r *embeddedRuntime) admitInnerBuffer(
	buffer []byte,
	size int,
	submission *coreclient.TXOwnedSubmission,
) (bool, error) {
	if size <= 0 || size > r.mtu {
		return false, nil
	}
	inner := buffer[dataplane.RouteSize : dataplane.RouteSize+size]

	for {
		// Preserve SessionController demand semantics for every application DATA
		// packet. Even while the current Session is TX-eligible this call may
		// start a demand-driven soft rekey. If admission races a hard deadline,
		// retry the same packet after another demand check.
		if r.eventSink != nil && !r.waitOutboundDemand() {
			return false, nil
		}

		err := r.core.AdmitInnerPacketInto(&submission.Operation, inner, cap(buffer))
		if err == nil {
			submission.Buffer = buffer[:0]
			return true, nil
		}
		if r.eventSink != nil &&
			(errors.Is(err, coreclient.ErrNoCurrentSession) || errors.Is(err, coreclient.ErrSessionNotTXEligible)) {
			continue
		}
		if errors.Is(err, dataplane.ErrSequenceExhausted) ||
			errors.Is(err, dataplane.ErrBufferTooSmall) ||
			errors.Is(err, dataplane.ErrInvalidConfig) {
			return false, fmt.Errorf("admit embedded packet: %w", err)
		}
		return false, nil
	}
}

func (r *embeddedRuntime) submitBorrowedPacketBatch(packets [][]byte) error {
	submissions := make([]coreclient.TXOwnedSubmission, 0, len(packets))
	release := func() {
		for i := range submissions {
			r.txPool.Put(submissions[i].Buffer)
			submissions[i] = coreclient.TXOwnedSubmission{}
		}
	}

	for _, packet := range packets {
		if len(packet) <= 0 || len(packet) > r.mtu {
			continue
		}

		buffer := r.txPool.Get()
		copy(buffer[dataplane.RouteSize:dataplane.RouteSize+len(packet)], packet)
		var submission coreclient.TXOwnedSubmission
		admitted, err := r.admitInnerBuffer(buffer, len(packet), &submission)
		if err != nil {
			r.txPool.Put(buffer)
			release()
			return err
		}
		if !admitted {
			r.txPool.Put(buffer)
			continue
		}
		submissions = append(submissions, submission)
	}

	if len(submissions) == 0 {
		return nil
	}
	if err := r.txEngine.EnqueueOwnedBatch(submissions, r.txPool); err != nil {
		release()
		return fmt.Errorf("enqueue embedded direct TX batch: %w", err)
	}
	if r.eventSink != nil {
		for range submissions {
			r.eventSink.HandleOutboundActivity()
		}
	}
	clear(submissions)
	return nil
}

func (r *embeddedRuntime) runDeviceIngress() error {
	bufs := make([][]byte, embeddedRuntimeBatchSize)
	sizes := make([]int, embeddedRuntimeBatchSize)
	for i := range bufs {
		bufs[i] = r.txPool.Get()
	}
	defer func() {
		for _, buffer := range bufs {
			if buffer != nil {
				r.txPool.Put(buffer)
			}
		}
	}()

	indices := make([]int, embeddedRuntimeBatchSize)
	submissions := make([]coreclient.TXOwnedSubmission, embeddedRuntimeBatchSize)

	for {
		n, err := r.device.Read(bufs, sizes, dataplane.RouteSize)
		if err != nil {
			return fmt.Errorf("read embedded packet device: %w", err)
		}
		if n <= 0 {
			continue
		}
		if n > len(bufs) {
			return fmt.Errorf("embedded packet device returned batch size %d, max %d: %w", n, len(bufs), dataplane.ErrInvalidConfig)
		}

		accepted := 0
		for i := 0; i < n; i++ {
			submission := &submissions[accepted]
			admitted, err := r.admitInnerBuffer(bufs[i], sizes[i], submission)
			if err != nil {
				for j := 0; j < accepted; j++ {
					submissions[j] = coreclient.TXOwnedSubmission{}
				}
				return err
			}
			if !admitted {
				continue
			}
			indices[accepted] = i
			accepted++
		}

		if accepted == 0 {
			select {
			case <-r.stop:
				return nil
			default:
			}
			continue
		}

		if err := r.txEngine.EnqueueOwnedBatch(submissions[:accepted], r.txPool); err != nil {
			for i := 0; i < accepted; i++ {
				submissions[i] = coreclient.TXOwnedSubmission{}
			}
			return fmt.Errorf("enqueue embedded device TX batch: %w", err)
		}
		if r.eventSink != nil {
			for i := 0; i < accepted; i++ {
				r.eventSink.HandleOutboundActivity()
			}
		}

		for i := 0; i < accepted; i++ {
			submissions[i] = coreclient.TXOwnedSubmission{}
			bufs[indices[i]] = nil
		}
		for i := 0; i < accepted; i++ {
			bufs[indices[i]] = r.txPool.Get()
		}
	}
}

func (r *embeddedRuntime) runTransportGeneration(generation *embeddedTransportGeneration) error {
	buffers := make([][]byte, embeddedRuntimeBatchSize)
	sizes := make([]int, embeddedRuntimeBatchSize)
	indices := make([]int, embeddedRuntimeBatchSize)
	submissions := make([]coreclient.RXOwnedSubmission, embeddedRuntimeBatchSize)
	for i := range buffers {
		buffers[i] = r.rxPool.Get()
	}
	defer func() {
		for _, buffer := range buffers {
			if buffer != nil {
				r.rxPool.Put(buffer)
			}
		}
	}()

	for {
		count, err := readDatagramBatch(generation.conn, buffers, sizes)
		if err != nil {
			// Socket/read failure is a recoverable transport event. If this is
			// still the current generation, make transport unavailable; if a
			// replacement is already published, the error is stale.
			r.invalidateTransport(generation, fmt.Errorf("read embedded UDP transport: %w", err))
			return nil
		}
		if count <= 0 {
			continue
		}
		if count > len(buffers) || count > len(sizes) {
			return fmt.Errorf("embedded UDP transport returned batch size %d, max %d: %w", count, len(buffers), dataplane.ErrInvalidConfig)
		}
		receivedAt := time.Now()

		r.transportProcessMu.Lock()
		r.transportMu.Lock()
		current := !r.transportClosing && r.transport == generation
		r.transportMu.Unlock()
		if !current {
			r.transportProcessMu.Unlock()
			continue
		}

		accepted := 0
		for i := 0; i < count; i++ {
			size := sizes[i]
			buffer := buffers[i]
			if buffer == nil || size <= 0 || size > len(buffer) {
				continue
			}

			packet := buffer[:size]
			route, routeErr := dataplane.DecodeRoute(r.admitScratch, packet)
			routeDecoded := routeErr == nil

			if r.demux != nil {
				handled, err := r.demux.HandleDatagram(
					r.serverEndpoint,
					route,
					routeDecoded,
					packet,
				)
				if err != nil {
					r.transportProcessMu.Unlock()
					return fmt.Errorf("embedded UDP control-plane demux: %w", err)
				}
				if handled {
					continue
				}
			}
			if !routeDecoded {
				continue
			}

			submission := &submissions[accepted]
			if err := r.core.AdmitNetworkDatagramRouteAtInto(
				&submission.Operation,
				route,
				r.serverEndpoint,
				packet,
				receivedAt,
			); err != nil {
				continue
			}
			indices[accepted] = i
			accepted++
		}

		if accepted == 0 {
			r.transportProcessMu.Unlock()
			continue
		}
		if err := r.rxEngine.EnqueueOwnedBatch(submissions[:accepted], r.rxPool); err != nil {
			for i := 0; i < accepted; i++ {
				submissions[i] = coreclient.RXOwnedSubmission{}
			}
			r.transportProcessMu.Unlock()
			return fmt.Errorf("enqueue embedded UDP RX batch: %w", err)
		}
		for i := 0; i < accepted; i++ {
			submissions[i] = coreclient.RXOwnedSubmission{}
			buffers[indices[i]] = nil // ownership transferred to RX engine/pool
		}
		r.transportProcessMu.Unlock()

		for i := 0; i < accepted; i++ {
			buffers[indices[i]] = r.rxPool.Get()
		}
	}
}

func readDatagramBatch(conn net.Conn, buffers [][]byte, sizes []int) (int, error) {
	if len(buffers) == 0 || len(sizes) < len(buffers) {
		return 0, fmt.Errorf("invalid embedded UDP batch buffers: %w", dataplane.ErrInvalidConfig)
	}
	if batchConn, ok := conn.(BatchDatagramConn); ok {
		return batchConn.ReadBatch(buffers, sizes)
	}
	n, err := conn.Read(buffers[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (r *embeddedRuntime) consumeRXResults(results []coreclient.RXResult) error {
	write := r.rxDeviceWrite[:0]
	defer func() {
		clear(write)
		r.rxDeviceWrite = write[:0]
	}()

	for i := range results {
		result := &results[i]
		if result.Err != nil {
			if errors.Is(result.Err, dataplane.ErrInvalidConfig) {
				r.report(fmt.Errorf("embedded client RX invariant: %w", result.Err))
			}
			continue
		}

		switch result.Inbound.Kind {
		case dataplane.InboundIPv4:
			inner := result.Inbound.IPv4
			if len(inner) == 0 || dataplane.RouteSize+len(inner) > len(result.Buffer) {
				r.report(fmt.Errorf("invalid embedded client IPv4 result buffer bounds"))
				continue
			}
			write = append(write, result.Buffer[:dataplane.RouteSize+len(inner)])

		case dataplane.InboundACK:
			continue

		default:
			r.report(fmt.Errorf("unexpected embedded client inbound kind %v", result.Inbound.Kind))
		}
	}

	if len(write) == 0 {
		return nil
	}
	n, err := r.device.Write(write, dataplane.RouteSize)
	if err != nil {
		return fmt.Errorf("write embedded packet device: %w", err)
	}
	if n != len(write) {
		return fmt.Errorf("write embedded packet device: wrote %d packets, want %d: %w", n, len(write), io.ErrShortWrite)
	}
	return nil
}

type connectedDatagramWriter struct {
	runtime        *embeddedRuntime
	serverEndpoint netip.AddrPort
}

func (w *connectedDatagramWriter) Send(packets []coreclient.TXPacket) error {
	if len(packets) == 0 {
		return nil
	}
	wireBatch := make([][]byte, len(packets))
	for i := range packets {
		packet := &packets[i]
		if len(packet.Wire) == 0 {
			return fmt.Errorf("invalid connected datagram write: %w", dataplane.ErrInvalidConfig)
		}
		if normalizeServerEndpoint(packet.Destination) != w.serverEndpoint {
			return fmt.Errorf("unexpected embedded UDP destination %v, want %v: %w", packet.Destination, w.serverEndpoint, dataplane.ErrInvalidConfig)
		}
		wireBatch[i] = packet.Wire
	}
	return w.writeBatch(wireBatch)
}

func (w *connectedDatagramWriter) WriteDatagram(packet []byte, destination netip.AddrPort) error {
	if w == nil || w.runtime == nil || len(packet) == 0 {
		return fmt.Errorf("invalid connected datagram write: %w", dataplane.ErrInvalidConfig)
	}
	if normalizeServerEndpoint(destination) != w.serverEndpoint {
		return fmt.Errorf("unexpected embedded UDP destination %v, want %v: %w", destination, w.serverEndpoint, dataplane.ErrInvalidConfig)
	}
	return w.writeBatch([][]byte{packet})
}

func (w *connectedDatagramWriter) writeBatch(packets [][]byte) error {
	if w == nil || w.runtime == nil || len(packets) == 0 {
		return fmt.Errorf("invalid connected datagram batch write: %w", dataplane.ErrInvalidConfig)
	}

	r := w.runtime
	r.transportMu.Lock()
	generation := r.transport
	closing := r.transportClosing
	r.transportMu.Unlock()
	if closing || generation == nil {
		// No transport is a recoverable network state. Admitted ciphertext is
		// intentionally dropped and must never be retransmitted with the same
		// traffic sequence/ciphertext.
		return nil
	}

	var err error
	if batchConn, ok := generation.conn.(BatchDatagramConn); ok {
		err = batchConn.WriteBatch(packets)
	} else {
		for _, packet := range packets {
			var n int
			n, err = generation.conn.Write(packet)
			if err != nil || n != len(packet) {
				if err == nil {
					err = io.ErrShortWrite
				}
				break
			}
		}
	}
	if err == nil {
		return nil
	}

	// EMSGSIZE is a packet/path-MTU failure, not evidence that the connected
	// UDP socket is dead. The admitted ciphertext is still single-use and is
	// dropped, but the transport remains current.
	if errors.Is(err, syscall.EMSGSIZE) {
		return nil
	}
	r.invalidateTransport(generation, fmt.Errorf("write embedded UDP transport: %w", err))
	return nil
}

var _ coreclient.PacketBufferReleaser = (*packetPool)(nil)

type packetPool struct {
	bufferSize int
	buffers    chan []byte
}

func newPacketPool(bufferSize, count int) *packetPool {
	if bufferSize <= 0 || count <= 0 {
		panic("invalid embedded packet pool")
	}
	p := &packetPool{
		bufferSize: bufferSize,
		buffers:    make(chan []byte, count),
	}
	for i := 0; i < count; i++ {
		p.buffers <- make([]byte, bufferSize)
	}
	return p
}

func (p *packetPool) Get() []byte {
	return <-p.buffers
}

func (p *packetPool) Put(buffer []byte) {
	if cap(buffer) < p.bufferSize {
		panic("embedded packet pool received undersized buffer")
	}
	p.buffers <- buffer[:p.bufferSize]
}
