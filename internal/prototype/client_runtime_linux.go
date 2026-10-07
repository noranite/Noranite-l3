//go:build linux

package prototype

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/tun"

	"golang.org/x/net/ipv4"
)

var (
	ErrClientRuntimeStarted    = errors.New("client runtime already started")
	ErrClientRuntimeNotRunning = errors.New("client runtime is not accepting protocol traffic")
)

// ClientDatagramDemux is the same-socket control-plane ingress seam.
//
// The runtime remains the only UDP reader. For every valid IPv4 UDP datagram it
// invokes the demux before encrypted transport admission. Returning handled=true
// consumes the datagram. Returning handled=false falls through to the normal
// opaque-route/session transport path. A non-nil error is terminal for the
// runtime; malformed recognized protocol packets should therefore normally be
// consumed with handled=true and err=nil.
//
// packet aliases a reusable UDP receive buffer and must not be retained after
// HandleDatagram returns. Asynchronous handlers must copy retained bytes.
type ClientDatagramDemux interface {
	HandleDatagram(
		source netip.AddrPort,
		route dataplane.Route,
		routeDecoded bool,
		packet []byte,
	) (handled bool, err error)
}

// ClientAuthenticatedEventSink receives already-authenticated protocol events
// after ordered RX commit. It is deliberately separate from raw datagram demux:
// callers can use ACK for keepalive/reconnect policy without making it part of
// Session lifecycle correctness.
type ClientAuthenticatedEventSink interface {
	HandleAuthenticatedACK(keepaliveID uint64)
}

// ClientDatagramDemuxFunc adapts a function to ClientDatagramDemux.
type ClientDatagramDemuxFunc func(
	source netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (handled bool, err error)

func (f ClientDatagramDemuxFunc) HandleDatagram(
	source netip.AddrPort,
	route dataplane.Route,
	routeDecoded bool,
	packet []byte,
) (bool, error) {
	return f(source, route, routeDecoded, packet)
}

// ClientRuntimeConfig configures execution resources only. Session lifecycle,
// rekey policy and handshake state remain outside the runtime.
type ClientRuntimeConfig struct {
	RXEngine client.RXEngineConfig
	TXEngine client.TXEngineConfig
}

// ClientRuntime owns the live client UDP/TUN execution boundary.
//
// Exactly one goroutine hierarchy owns UDP receive. Handshake/control-plane
// traffic is demultiplexed there, while every encrypted transport packet --
// TUN DATA and protocol-generated activation/keepalive alike -- uses the same
// TXEngine and ordered UDP sender.
type ClientRuntime struct {
	dev  tun.Device
	conn *net.UDPConn
	core *client.Core
	mtu  int

	batchSize    int
	admitScratch *dataplane.DataScratch
	udpConn      *ipv4.PacketConn
	sender       *clientUDPSender
	txEngine     *client.TXEngine
	rxEngine     *client.RXEngine
	tunPool      *runtimePacketPool
	rxPool       *runtimePacketPool

	errC     chan error
	reporter runtimeErrorReporter

	// rxTunWrite is owned exclusively by RXEngine's one sequential consumer.
	rxTunWrite [][]byte
	eventSink  ClientAuthenticatedEventSink

	stateMu sync.Mutex
	started bool
	demux   ClientDatagramDemux
	ready   chan struct{}
	done    chan struct{}

	// protocolMu serializes the explicit protocol producer close boundary with
	// SubmitProtocolTransport/SendProtocolDatagram.
	protocolMu        sync.Mutex
	protocolAccepting bool

	closeOnce sync.Once
}

func NewClientRuntime(
	dev tun.Device,
	conn *net.UDPConn,
	core *client.Core,
	mtu int,
	config ClientRuntimeConfig,
) (*ClientRuntime, error) {
	if dev == nil || conn == nil || core == nil {
		return nil, fmt.Errorf("client tunnel input is nil")
	}
	if mtu < dataplane.MinTunnelMTU || mtu > dataplane.MaxTunnelMTU {
		return nil, fmt.Errorf("invalid tunnel MTU %d: %w", mtu, dataplane.ErrInvalidConfig)
	}

	batchSize := dev.BatchSize()
	if batchSize < 1 {
		return nil, fmt.Errorf("invalid TUN batch size %d", batchSize)
	}
	if config.TXEngine.BatchSize > 0 && config.TXEngine.BatchSize < batchSize {
		return nil, fmt.Errorf(
			"client TX engine batch size %d smaller than TUN batch size %d: %w",
			config.TXEngine.BatchSize,
			batchSize,
			dataplane.ErrInvalidConfig,
		)
	}
	if config.RXEngine.BatchSize > 0 && config.RXEngine.BatchSize < batchSize {
		return nil, fmt.Errorf(
			"client RX engine batch size %d smaller than TUN batch size %d: %w",
			config.RXEngine.BatchSize,
			batchSize,
			dataplane.ErrInvalidConfig,
		)
	}
	if config.TXEngine.BatchSize == 0 {
		config.TXEngine.BatchSize = batchSize
	}
	if config.RXEngine.BatchSize == 0 {
		config.RXEngine.BatchSize = batchSize
	}

	admitScratch, err := core.NewDataScratch()
	if err != nil {
		return nil, fmt.Errorf("create client ingress scratch: %w", err)
	}

	udpConn := ipv4.NewPacketConn(conn)
	sender := newClientUDPSender(udpConn, batchSize)

	wireBufferSize := mtu + dataplane.MaxDataExpansion
	if wireBufferSize < dataplane.MaxGeneratedEstablishmentWirePacketSize {
		wireBufferSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}

	poolCount := batchSize * clientRuntimeBufferBatches
	if poolCount < batchSize+1 {
		poolCount = batchSize + 1
	}

	errC := make(chan error, 1)
	r := &ClientRuntime{
		dev:          dev,
		conn:         conn,
		core:         core,
		mtu:          mtu,
		batchSize:    batchSize,
		admitScratch: admitScratch,
		udpConn:      udpConn,
		sender:       sender,
		tunPool:      newRuntimePacketPool(wireBufferSize, poolCount),
		rxPool:       newRuntimeGROPacketPool(wireBufferSize, poolCount),
		errC:         errC,
		reporter:     runtimeErrorReporter{c: errC},
		rxTunWrite:   make([][]byte, 0, batchSize),
		ready:        make(chan struct{}),
		done:         make(chan struct{}),
	}

	txEngine, err := client.NewOwnedTXEngine(
		core,
		config.TXEngine,
		sender.Send,
		r.reporter.Report,
	)
	if err != nil {
		return nil, fmt.Errorf("create client TX engine: %w", err)
	}
	r.txEngine = txEngine

	rxEngine, err := client.NewOwnedRXEngine(
		core,
		config.RXEngine,
		r.consumeRXResults,
		r.reporter.Report,
	)
	if err != nil {
		txEngine.Close()
		return nil, fmt.Errorf("create client RX engine: %w", err)
	}
	r.rxEngine = rxEngine

	return r, nil
}

// consumeRXResults is the final ordered owner of authenticated client RX
// packets. It performs the TUN/event side effects synchronously; RXEngine
// returns packet buffers to their pools immediately after this method returns.
func (r *ClientRuntime) consumeRXResults(results []client.RXResult) error {
	tunWrite := r.rxTunWrite[:0]
	defer func() {
		clear(tunWrite)
		r.rxTunWrite = tunWrite[:0]
	}()

	for i := range results {
		result := &results[i]
		if result.Err != nil {
			// Authentication/replay/authorization/grammar failures are packet-local.
			// ErrInvalidConfig signals an ownership invariant bug.
			if errors.Is(result.Err, dataplane.ErrInvalidConfig) {
				r.reporter.Report(fmt.Errorf("client RX invariant: %w", result.Err))
			}
			continue
		}

		switch result.Inbound.Kind {
		case dataplane.InboundIPv4:
			inner := result.Inbound.IPv4
			if len(inner) == 0 || dataplane.RouteSize+len(inner) > len(result.Buffer) {
				r.reporter.Report(fmt.Errorf("invalid client IPv4 result buffer bounds"))
				continue
			}
			tunWrite = append(
				tunWrite,
				result.Buffer[:dataplane.RouteSize+len(inner)],
			)

		case dataplane.InboundACK:
			if r.eventSink != nil {
				r.eventSink.HandleAuthenticatedACK(result.Inbound.KeepaliveID)
			}

		default:
			r.reporter.Report(fmt.Errorf(
				"unexpected client inbound kind %v",
				result.Inbound.Kind,
			))
		}
	}

	if len(tunWrite) == 0 {
		return nil
	}
	n, err := r.dev.Write(tunWrite, dataplane.RouteSize)
	if err != nil {
		return fmt.Errorf("write client TUN batch: %w", err)
	}
	if n != len(tunWrite) {
		return fmt.Errorf("write client TUN batch: wrote %d packets, want %d: %w", n, len(tunWrite), io.ErrShortWrite)
	}
	return nil
}

// SetDatagramDemux installs the same-socket control-plane demultiplexer. It is
// intentionally immutable after Run starts, so UDP ingress has one stable owner
// and one stable classification rule for its lifetime.
func (r *ClientRuntime) SetDatagramDemux(demux ClientDatagramDemux) error {
	if r == nil {
		return fmt.Errorf("client runtime is nil: %w", dataplane.ErrInvalidConfig)
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.started {
		return ErrClientRuntimeStarted
	}
	r.demux = demux
	return nil
}

// SubmitProtocolTransport submits an already-admitted encrypted transport
// operation produced by lifecycle orchestration (activation/keepalive/etc.).
// It deliberately shares TXEngine with TUN DATA. TXEngine takes ownership of
// the temporary output buffer on successful enqueue; asynchronous send failures
// become terminal runtime errors exactly like TUN-originated TX failures.
func (r *ClientRuntime) SubmitProtocolTransport(op *client.OutboundOperation) error {
	if r == nil || op == nil || op.MaxWireSize() <= 0 {
		return fmt.Errorf("invalid protocol transport operation: %w", dataplane.ErrInvalidConfig)
	}

	r.protocolMu.Lock()
	defer r.protocolMu.Unlock()
	if !r.protocolAccepting {
		return ErrClientRuntimeNotRunning
	}

	buffer := make([]byte, op.MaxWireSize())
	return r.txEngine.EnqueueOwned(client.TXOwnedSubmission{
		Operation: *op,
		Buffer:    buffer[:0],
	}, nil)
}

// SendProtocolDatagram sends one unencrypted control-plane datagram through the
// runtime-owned UDP sender. This path is
// intentionally separate from SubmitProtocolTransport: handshake datagrams are
// not traffic-generation packets and therefore must not consume Session nonce
// space or pass through TXEngine.
func (r *ClientRuntime) SendProtocolDatagram(
	packet []byte,
	destination netip.AddrPort,
) error {
	if r == nil || len(packet) == 0 {
		return fmt.Errorf("invalid protocol datagram: %w", dataplane.ErrInvalidConfig)
	}

	r.protocolMu.Lock()
	defer r.protocolMu.Unlock()
	if !r.protocolAccepting {
		return ErrClientRuntimeNotRunning
	}

	err := r.sender.Send([]client.TXPacket{{
		Wire:        packet,
		Destination: destination,
	}})
	if err != nil {
		r.reporter.Report(err)
	}
	return err
}

// Ready closes after Run has opened the protocol producer boundary. Callers that
// start orchestration concurrently with Run can wait on it before sending the
// first handshake/control-plane datagram.
func (r *ClientRuntime) Ready() <-chan struct{} {
	if r == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return r.ready
}

// Done closes after all accepted RX/TX work has drained and Run is returning.
func (r *ClientRuntime) Done() <-chan struct{} {
	if r == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return r.done
}

// Close requests runtime shutdown by closing both ingress descriptors. Run is
// responsible for the ordered drain and remains the owner of engine closure.
func (r *ClientRuntime) Close() {
	if r == nil {
		return
	}
	r.closeIngress()
}

func (r *ClientRuntime) closeIngress() {
	r.closeOnce.Do(func() {
		_ = r.dev.Close()
		_ = r.conn.Close()
	})
}

// Run starts the single live client execution model and blocks until a terminal
// runtime error/close, then drains already accepted operations.
func (r *ClientRuntime) Run() error {
	if r == nil {
		return fmt.Errorf("client runtime is nil: %w", dataplane.ErrInvalidConfig)
	}

	r.stateMu.Lock()
	if r.started {
		r.stateMu.Unlock()
		return ErrClientRuntimeStarted
	}
	r.started = true
	demux := r.demux
	if sink, ok := demux.(ClientAuthenticatedEventSink); ok {
		r.eventSink = sink
	}
	r.stateMu.Unlock()

	r.protocolMu.Lock()
	r.protocolAccepting = true
	r.protocolMu.Unlock()

	go drainTunEvents(r.dev)

	var ingressWG sync.WaitGroup
	ingressWG.Add(2)

	go func() {
		defer ingressWG.Done()
		if err := runClientTunIngress(
			r.dev,
			r.core,
			r.txEngine,
			r.tunPool,
			r.mtu,
			r.batchSize,
		); err != nil {
			r.reporter.Report(err)
		}
	}()

	go func() {
		defer ingressWG.Done()
		if err := runClientUDPIngress(
			r.udpConn,
			r.core,
			r.admitScratch,
			r.rxEngine,
			r.rxPool,
			r.batchSize,
			demux,
		); err != nil {
			r.reporter.Report(err)
		}
	}()

	// Both ingress owners and both engine pipelines are live before orchestration
	// is released.
	close(r.ready)

	// A terminal TUN/UDP/TX/control-plane error is the runtime stop signal.
	firstErr := <-r.errC
	r.closeIngress()

	// No new TUN or UDP packet operations can be admitted after ingress exits.
	ingressWG.Wait()

	// Drain accepted RX first. Ordered RX consume may still trigger protocol
	// orchestration while protocol TX remains open.
	r.rxEngine.Close()

	// Close the explicit protocol producer boundary only after accepted RX has
	// drained, then drain all accepted TUN/protocol TX work.
	r.protocolMu.Lock()
	r.protocolAccepting = false
	r.protocolMu.Unlock()

	r.txEngine.Close()

	close(r.done)
	return firstErr
}
