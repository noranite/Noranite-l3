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

const embeddedRuntimeBufferCount = 64

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

type clientAuthenticatedEventSink interface {
	HandleAuthenticatedACK(keepaliveID uint64)
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
	eventSink     clientAuthenticatedEventSink

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

	wireBufferSize := mtu + dataplane.MaxDataExpansion
	if wireBufferSize < dataplane.MaxGeneratedEstablishmentWirePacketSize {
		wireBufferSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}

	r := &embeddedRuntime{
		device:            device,
		serverEndpoint:    serverEndpoint,
		core:              core,
		mtu:               mtu,
		admitScratch:      admitScratch,
		txPool:            newPacketPool(wireBufferSize, embeddedRuntimeBufferCount),
		rxPool:            newPacketPool(wireBufferSize, embeddedRuntimeBufferCount),
		rxDeviceWrite:     make([][]byte, 0, 1),
		errC:              make(chan error, 1),
		transportFailures: make(chan TransportFailure, 1),
		ready:             make(chan struct{}),
		done:              make(chan struct{}),
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
		coreclient.TXEngineConfig{BatchSize: 1},
		r.writer.Send,
		report,
	)
	if err != nil {
		return nil, fmt.Errorf("create embedded client TX engine: %w", err)
	}
	r.txEngine = txEngine

	rxEngine, err := coreclient.NewOwnedRXEngine(
		core,
		coreclient.RXEngineConfig{BatchSize: 1},
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

	firstErr := <-r.errC
	r.closeIngress(false)
	ingressWG.Wait()
	r.transportWG.Wait()

	// RX may synchronously notify SessionController while consuming accepted
	// packets, so protocol TX remains open until accepted RX is fully drained.
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

func (r *embeddedRuntime) runDeviceIngress() error {
	buffer := r.txPool.Get()
	bufs := [][]byte{buffer}
	sizes := []int{0}
	submissions := make([]coreclient.TXOwnedSubmission, 1)

	for {
		n, err := r.device.Read(bufs, sizes, dataplane.RouteSize)
		if err != nil {
			return fmt.Errorf("read embedded packet device: %w", err)
		}
		if n <= 0 {
			continue
		}
		if n != 1 {
			return fmt.Errorf("embedded packet device returned batch size %d, want 1: %w", n, dataplane.ErrInvalidConfig)
		}

		size := sizes[0]
		if size <= 0 || size > r.mtu {
			continue
		}

		inner := buffer[dataplane.RouteSize : dataplane.RouteSize+size]
		submission := &submissions[0]
		if err := r.core.AdmitInnerPacketInto(&submission.Operation, inner, cap(buffer)); err != nil {
			if errors.Is(err, dataplane.ErrSequenceExhausted) ||
				errors.Is(err, dataplane.ErrBufferTooSmall) ||
				errors.Is(err, dataplane.ErrInvalidConfig) {
				return fmt.Errorf("admit embedded device packet: %w", err)
			}
			continue
		}
		submission.Buffer = buffer[:0]

		if err := r.txEngine.EnqueueOwnedBatch(submissions, r.txPool); err != nil {
			return fmt.Errorf("enqueue embedded device TX: %w", err)
		}
		*submission = coreclient.TXOwnedSubmission{}

		buffer = r.txPool.Get()
		bufs[0] = buffer
	}
}

func (r *embeddedRuntime) runTransportGeneration(generation *embeddedTransportGeneration) error {
	buffer := r.rxPool.Get()
	defer func() {
		if buffer != nil {
			r.rxPool.Put(buffer)
		}
	}()
	submissions := make([]coreclient.RXOwnedSubmission, 1)

	for {
		n, err := generation.conn.Read(buffer)
		if err != nil {
			// Socket/read failure is a recoverable transport event. If this is
			// still the current generation, make transport unavailable; if a
			// replacement is already published, the error is stale.
			r.invalidateTransport(generation, fmt.Errorf("read embedded UDP transport: %w", err))
			return nil
		}
		receivedAt := time.Now()
		if n <= 0 || n > len(buffer) {
			continue
		}

		r.transportProcessMu.Lock()
		r.transportMu.Lock()
		current := !r.transportClosing && r.transport == generation
		r.transportMu.Unlock()
		if !current {
			r.transportProcessMu.Unlock()
			continue
		}

		packet := buffer[:n]
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
				r.transportProcessMu.Unlock()
				continue
			}
		}
		if !routeDecoded {
			r.transportProcessMu.Unlock()
			continue
		}

		submission := &submissions[0]
		if err := r.core.AdmitNetworkDatagramRouteAtInto(
			&submission.Operation,
			route,
			r.serverEndpoint,
			packet,
			receivedAt,
		); err != nil {
			r.transportProcessMu.Unlock()
			continue
		}

		if err := r.rxEngine.EnqueueOwnedBatch(submissions, r.rxPool); err != nil {
			r.transportProcessMu.Unlock()
			return fmt.Errorf("enqueue embedded UDP RX: %w", err)
		}
		*submission = coreclient.RXOwnedSubmission{}
		buffer = nil // ownership transferred to RX engine/pool
		r.transportProcessMu.Unlock()

		buffer = r.rxPool.Get()
	}
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
			if r.eventSink != nil {
				r.eventSink.HandleAuthenticatedACK(result.Inbound.KeepaliveID)
			}

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
	if len(packets) != 1 {
		return fmt.Errorf("embedded TX batch size %d, want 1: %w", len(packets), dataplane.ErrInvalidConfig)
	}
	return w.WriteDatagram(packets[0].Wire, packets[0].Destination)
}

func (w *connectedDatagramWriter) WriteDatagram(packet []byte, destination netip.AddrPort) error {
	if w == nil || w.runtime == nil || len(packet) == 0 {
		return fmt.Errorf("invalid connected datagram write: %w", dataplane.ErrInvalidConfig)
	}
	if normalizeServerEndpoint(destination) != w.serverEndpoint {
		return fmt.Errorf("unexpected embedded UDP destination %v, want %v: %w", destination, w.serverEndpoint, dataplane.ErrInvalidConfig)
	}

	r := w.runtime
	r.transportMu.Lock()
	generation := r.transport
	closing := r.transportClosing
	r.transportMu.Unlock()
	if closing || generation == nil {
		// No transport is a recoverable network state. The admitted packet is
		// intentionally dropped and must never be retransmitted with the same
		// traffic sequence/ciphertext.
		return nil
	}
	n, err := generation.conn.Write(packet)
	if err == nil && n == len(packet) {
		return nil
	}

	// A connected UDP send failure is recoverable transport loss, not a
	// protocol failure. Invalidate only if this generation is still current; a
	// concurrent replacement makes this write result stale.
	if err != nil {
		// EMSGSIZE is a packet/path-MTU failure, not evidence that the connected
		// UDP socket is dead. The admitted ciphertext is still single-use and is
		// dropped, but the transport remains current.
		if errors.Is(err, syscall.EMSGSIZE) {
			return nil
		}
		r.invalidateTransport(generation, fmt.Errorf("write embedded UDP transport: %w", err))
	} else {
		r.invalidateTransport(generation, fmt.Errorf("write embedded UDP transport: %w", io.ErrShortWrite))
	}
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
