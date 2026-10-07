//go:build linux

package prototype

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/tun"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	// Buffer pools are the runtime backpressure boundary. Four batches let the
	// UDP/TUN readers stay ahead of crypto/send workers without allowing an
	// unbounded number of packet buffers to accumulate under load.
	serverRuntimeBufferBatches = 4
)

// RunServerTunnel connects server.Core to the WG-style RX/TX execution engines
// and Linux batch I/O.
//
// Hot path:
//
//	UDP ReadBatch -> route/admission -> global decrypt workers
//	                               +-> per-peer ordered RX commit
//	                               +-> global cross-peer delivery batch
//	                               +-> TUN write / optional ACK batch
//
//	TUN Read      -> TX admission  -> global encrypt workers
//	                               +-> per-peer ordered UDP sender
//
// Receive/TUN buffers are transferred to asynchronous operations without a
// packet copy. A bounded pool supplies replacement read buffers immediately;
// each engine returns owned buffers after its final stage. Pool exhaustion
// therefore applies blocking backpressure instead of allocating indefinitely or
// dropping an operation after half-publishing it.
func RunServerTunnel(
	dev tun.Device,
	conn *net.UDPConn,
	core *server.Core,
	establishmentIngress ServerEstablishmentIngress,
	mtu int,
) error {
	if dev == nil || conn == nil || core == nil {
		return fmt.Errorf("server tunnel input is nil")
	}
	if mtu < dataplane.MinTunnelMTU || mtu > dataplane.MaxTunnelMTU {
		return fmt.Errorf("invalid tunnel MTU %d: %w", mtu, dataplane.ErrInvalidConfig)
	}

	batchSize := dev.BatchSize()
	if batchSize < 1 {
		return fmt.Errorf("invalid TUN batch size %d", batchSize)
	}

	admitScratch, err := core.NewDataScratch()
	if err != nil {
		return fmt.Errorf("create server ingress scratch: %w", err)
	}

	udpConn := ipv4.NewPacketConn(conn)
	sender := newServerUDPSender(udpConn, batchSize)

	wireBufferSize := mtu + dataplane.MaxDataExpansion
	if wireBufferSize < dataplane.MaxGeneratedEstablishmentWirePacketSize {
		wireBufferSize = dataplane.MaxGeneratedEstablishmentWirePacketSize
	}

	poolCount := batchSize * serverRuntimeBufferBatches
	if poolCount < batchSize+1 {
		poolCount = batchSize + 1
	}
	tunPool := newRuntimePacketPool(wireBufferSize, poolCount)
	rxPool := newRuntimeGROPacketPool(wireBufferSize, poolCount)

	// ACK storage is independent from RX storage so receive buffers can be
	// recycled immediately after the global delivery consumer returns. The
	// consumer flushes a partial ACK vector before any blocking acquisition, so
	// control-pool exhaustion cannot create a pool/queue dependency cycle.
	controlPoolCount := batchSize * 2
	if controlPoolCount < 32 {
		controlPoolCount = 32
	}
	controlPool := newRuntimePacketPool(wireBufferSize, controlPoolCount)

	errC := make(chan error, 1)
	reporter := runtimeErrorReporter{c: errC}

	txEngine, err := server.NewOwnedTXEngine(
		core,
		server.TXEngineConfig{BatchSize: batchSize},
		sender.Send,
		reporter.Report,
	)
	if err != nil {
		return fmt.Errorf("create TX engine: %w", err)
	}

	rxEngine, err := server.NewOwnedRXEngine(
		core,
		server.RXEngineConfig{BatchSize: batchSize},
		newServerRXConsumer(
			dev,
			txEngine,
			controlPool,
			batchSize,
		),
		reporter.Report,
	)
	if err != nil {
		txEngine.Close()
		return fmt.Errorf("create RX engine: %w", err)
	}

	var establishmentExecutor *serverEstablishmentExecutor
	if establishmentIngress != nil {
		establishmentExecutor, err = newServerEstablishmentExecutor(
			establishmentIngress,
			wireBufferSize,
			serverEstablishmentQueueCapacity,
			serverEstablishmentWorkerCount,
			func(response []byte, destination netip.AddrPort) error {
				return sender.Send([]server.TXPacket{{
					Wire:        response,
					Destination: destination,
				}})
			},
			reporter.Report,
		)
		if err != nil {
			rxEngine.Close()
			txEngine.Close()
			return fmt.Errorf("create establishment executor: %w", err)
		}
	}

	go drainTunEvents(dev)

	var ingressWG sync.WaitGroup
	ingressWG.Add(2)
	go func() {
		defer ingressWG.Done()
		if err := runServerTunIngress(
			dev,
			core,
			txEngine,
			tunPool,
			mtu,
			batchSize,
		); err != nil {
			reporter.Report(err)
		}
	}()
	go func() {
		defer ingressWG.Done()
		if err := runServerUDPIngress(
			udpConn,
			core,
			establishmentExecutor,
			admitScratch,
			rxEngine,
			rxPool,
			batchSize,
		); err != nil {
			reporter.Report(err)
		}
	}()

	// The runtime is intentionally long-lived. Any terminal TUN/UDP/TX/RX
	// consumer error becomes the stop signal; closing descriptors unblocks ingress.
	firstErr := <-errC
	_ = dev.Close()
	_ = conn.Close()

	// No new packet operations can be admitted after both readers exit.
	ingressWG.Wait()

	// The UDP reader is the sole establishment submitter, so the bounded queue is
	// now safe to close and drain.
	if establishmentExecutor != nil {
		establishmentExecutor.CloseAndWait()
	}

	// RX drains first while TX remains open because an accepted KEEPALIVE may
	// still produce an ACK after ordered per-peer commit in the delivery worker.
	rxEngine.Close()

	// TUN ingress has stopped and RX delivery has returned, so no producer can
	// submit a new TX operation. Drain encryption/send and release all buffers.
	txEngine.Close()

	return firstErr
}

// serverUDPSender adapts the TX engine's per-message destination model to
// ipv4.PacketConn.WriteBatch. A mutex deliberately serializes the syscall
// scratch arrays; crypto remains parallel and the sender can later be sharded if
// benchmarks show one sendmmsg stream is the bottleneck.
type serverUDPSender struct {
	mu   sync.Mutex
	conn *ipv4.PacketConn

	messages []ipv4.Message
	addrs    []net.UDPAddr
	ips      [][4]byte
}

func newServerUDPSender(conn *ipv4.PacketConn, capacity int) *serverUDPSender {
	s := &serverUDPSender{conn: conn}
	s.ensureCapacity(capacity)
	return s
}

func (s *serverUDPSender) ensureCapacity(count int) {
	if cap(s.messages) >= count {
		return
	}

	s.messages = make([]ipv4.Message, count)
	s.addrs = make([]net.UDPAddr, count)
	s.ips = make([][4]byte, count)
	for i := range s.messages {
		s.messages[i].Buffers = make([][]byte, 1)
		s.addrs[i].IP = s.ips[i][:]
	}
}

func (s *serverUDPSender) Send(packets []server.TXPacket) error {
	if len(packets) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureCapacity(len(packets))
	messages := s.messages[:len(packets)]

	for i, packet := range packets {
		destination := packet.Destination
		if !destination.IsValid() || destination.Port() == 0 {
			return fmt.Errorf("invalid TX destination %v", destination)
		}
		addr := destination.Addr().Unmap()
		if !addr.Is4() {
			return fmt.Errorf("TX destination is not IPv4: %v", destination)
		}

		ipv4Addr := addr.As4()
		copy(s.ips[i][:], ipv4Addr[:])
		s.addrs[i].Port = int(destination.Port())
		s.addrs[i].Zone = ""

		messages[i].Buffers[0] = packet.Wire
		messages[i].Addr = &s.addrs[i]
	}

	if err := writeUDPBatch(s.conn, messages); err != nil {
		return fmt.Errorf("write server UDP batch: %w", err)
	}
	return nil
}

func newServerRXConsumer(
	dev tun.Device,
	txEngine *server.TXEngine,
	controlPool *runtimePacketPool,
	batchSize int,
) server.RXConsumeFunc {
	// These vectors belong to the one global RX delivery worker. They start nil
	// and grow only to the high-water mark actually observed at runtime instead
	// of reserving BatchSize storage for every configured Peer.
	var tunWrite [][]byte
	var ackSubmissions []server.TXOwnedSubmission

	flushACKs := func() error {
		if len(ackSubmissions) == 0 {
			return nil
		}
		if err := txEngine.EnqueueOwnedBatch(ackSubmissions, controlPool); err != nil {
			// Validation/enqueue failure occurs before ownership transfer.
			for i := range ackSubmissions {
				controlPool.Put(ackSubmissions[i].Buffer)
			}
			clear(ackSubmissions)
			ackSubmissions = ackSubmissions[:0]
			return fmt.Errorf("enqueue server ACK batch: %w", err)
		}
		clear(ackSubmissions)
		ackSubmissions = ackSubmissions[:0]
		return nil
	}

	return func(results []server.RXOwnedResult) error {
		tunWrite = tunWrite[:0]
		var terminalErr error

		defer func() {
			clear(tunWrite)
			tunWrite = tunWrite[:0]
			// Normally empty after flushACKs. This defensive branch prevents a
			// future early-return path from leaking control-pool ownership.
			for i := range ackSubmissions {
				controlPool.Put(ackSubmissions[i].Buffer)
			}
			clear(ackSubmissions)
			ackSubmissions = ackSubmissions[:0]
		}()

		for i := range results {
			result := &results[i]
			if result.Err != nil {
				// Authentication/replay/authorization/grammar failures are
				// packet-local. Invalid engine ownership and exhausted server TX
				// sequence space are terminal runtime conditions.
				if errors.Is(result.Err, dataplane.ErrInvalidConfig) {
					terminalErr = errors.Join(
						terminalErr,
						fmt.Errorf("server RX invariant: %w", result.Err),
					)
				} else if errors.Is(result.Err, dataplane.ErrSequenceExhausted) {
					terminalErr = errors.Join(
						terminalErr,
						fmt.Errorf("server ACK sequence exhausted: %w", result.Err),
					)
				}
				continue
			}

			if result.HasOutbound {
				// Never block on the control pool while retaining an unsubmitted ACK
				// vector. This remains safe even if pool sizing changes independently
				// of BatchSize later.
				buffer, ok := controlPool.TryGet()
				if !ok {
					if err := flushACKs(); err != nil {
						return errors.Join(terminalErr, err)
					}
					buffer = controlPool.Get()
				}
				ackSubmissions = append(ackSubmissions, server.TXOwnedSubmission{
					Operation: result.Outbound,
					Buffer:    buffer[:0],
				})
				if len(ackSubmissions) == batchSize {
					if err := flushACKs(); err != nil {
						return errors.Join(terminalErr, err)
					}
				}
			}

			switch result.Inbound.Kind {
			case dataplane.InboundIPv4:
				inner := result.Inbound.IPv4
				if len(inner) == 0 || dataplane.RouteSize+len(inner) > len(result.Buffer) {
					terminalErr = errors.Join(
						terminalErr,
						fmt.Errorf("invalid server IPv4 result buffer bounds"),
					)
					continue
				}
				tunWrite = append(tunWrite, result.Buffer[:dataplane.RouteSize+len(inner)])

			case dataplane.InboundKeepalive:
				// CONTROL never enters TUN. Any ACK owns independent TX storage.

			default:
				terminalErr = errors.Join(
					terminalErr,
					fmt.Errorf("unexpected server inbound kind %v", result.Inbound.Kind),
				)
			}
		}

		if err := flushACKs(); err != nil {
			return errors.Join(terminalErr, err)
		}

		if len(tunWrite) != 0 {
			n, err := dev.Write(tunWrite, dataplane.RouteSize)
			if err != nil {
				return errors.Join(terminalErr, fmt.Errorf("write server TUN batch: %w", err))
			}
			if n != len(tunWrite) {
				return errors.Join(terminalErr, fmt.Errorf("write server TUN batch: wrote %d packets, want %d: %w", n, len(tunWrite), io.ErrShortWrite))
			}
		}
		return terminalErr
	}
}

func runServerTunIngress(
	dev tun.Device,
	core *server.Core,
	txEngine *server.TXEngine,
	pool *runtimePacketPool,
	mtu int,
	batchSize int,
) error {
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = pool.Get()
	}

	indices := make([]int, batchSize)
	submissions := make([]server.TXOwnedSubmission, batchSize)

	for {
		n, err := dev.Read(bufs, sizes, dataplane.RouteSize)
		if err != nil {
			return fmt.Errorf("read server TUN: %w", err)
		}

		accepted := 0
		for i := 0; i < n; i++ {
			size := sizes[i]
			if size <= 0 || size > mtu {
				continue
			}

			inner := bufs[i][dataplane.RouteSize : dataplane.RouteSize+size]
			submission := &submissions[accepted]
			if err := core.AdmitInnerPacketInto(
				&submission.Operation,
				inner,
				cap(bufs[i]),
			); err != nil {
				if errors.Is(err, dataplane.ErrSequenceExhausted) ||
					errors.Is(err, dataplane.ErrBufferTooSmall) ||
					errors.Is(err, dataplane.ErrInvalidConfig) {
					return fmt.Errorf("admit server TUN packet: %w", err)
				}
				continue
			}

			indices[accepted] = i
			submission.Buffer = bufs[i][:0]
			accepted++
		}

		if accepted == 0 {
			continue
		}

		if err := txEngine.EnqueueOwnedBatch(submissions[:accepted], pool); err != nil {
			return fmt.Errorf("enqueue server TUN TX batch: %w", err)
		}

		for i := 0; i < accepted; i++ {
			submissions[i] = server.TXOwnedSubmission{}
		}
		for i := 0; i < accepted; i++ {
			index := indices[i]
			bufs[index] = pool.Get()
		}
	}
}

func runServerUDPIngress(
	conn *ipv4.PacketConn,
	core *server.Core,
	establishmentExecutor *serverEstablishmentExecutor,
	admitScratch *dataplane.DataScratch,
	rxEngine *server.RXEngine,
	pool *runtimePacketPool,
	batchSize int,
) error {
	bufs := make([][]byte, batchSize)
	messages := make([]ipv4.Message, batchSize)
	for i := range bufs {
		bufs[i] = pool.Get()
		messages[i].Buffers = [][]byte{bufs[i]}
	}

	indices := make([]int, batchSize)
	submissions := make([]server.RXOwnedSubmission, batchSize)

	for {
		n, err := conn.ReadBatch(messages, 0)
		if err != nil {
			return fmt.Errorf("read server UDP batch: %w", err)
		}
		batchReceivedAt := time.Now()

		accepted := 0
		for i := 0; i < n; i++ {
			message := &messages[i]
			if message.Flags&unix.MSG_TRUNC != 0 || message.N <= 0 || message.N > len(bufs[i]) {
				continue
			}

			udpAddr, ok := message.Addr.(*net.UDPAddr)
			if !ok || udpAddr == nil {
				return fmt.Errorf("unexpected UDP source address type %T", message.Addr)
			}
			source := udpAddr.AddrPort()
			if !source.IsValid() || source.Port() == 0 {
				continue
			}
			source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
			if !source.Addr().Is4() {
				continue
			}

			packet := bufs[i][:message.N]
			route, routeErr := dataplane.DecodeRoute(admitScratch, packet)
			routeDecoded := routeErr == nil

			if establishmentExecutor != nil {
				owned, _ := establishmentExecutor.TrySubmit(source, route, routeDecoded, packet)
				if owned {
					continue
				}
			}
			if !routeDecoded {
				continue
			}

			submission := &submissions[accepted]
			if err := core.AdmitNetworkDatagramRouteAtInto(
				&submission.Operation,
				route,
				source,
				packet,
				batchReceivedAt,
			); err != nil {
				continue
			}

			indices[accepted] = i
			accepted++
		}

		if accepted == 0 {
			continue
		}

		if err := rxEngine.EnqueueOwnedBatch(submissions[:accepted], true, pool); err != nil {
			return fmt.Errorf("enqueue server UDP RX batch: %w", err)
		}

		for i := 0; i < accepted; i++ {
			submissions[i] = server.RXOwnedSubmission{}
		}
		for i := 0; i < accepted; i++ {
			index := indices[i]
			bufs[index] = pool.Get()
			messages[index].Buffers[0] = bufs[index]
		}
	}
}
