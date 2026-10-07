//go:build linux

package prototype

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/tun"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const clientRuntimeBufferBatches = 4

// RunClientTunnel connects client.Core to the parallel RX/TX engines and Linux
// batch I/O. Lifecycle is resolved at ingress admission; asynchronous workers
// only operate on exact pinned packet operations.
//
// Hot path:
//
//	TUN ReadBatch -> TX admission -> parallel encryption -> ordered UDP send
//	UDP ReadBatch -> RX admission -> parallel decryption -> ordered replay/lifecycle commit -> TUN WriteBatch
//
// Packet buffers are transferred to accepted asynchronous operations without a
// copy. Bounded pools provide replacement read buffers and therefore turn pool
// exhaustion into backpressure rather than unbounded allocation.
func RunClientTunnel(
	dev tun.Device,
	conn *net.UDPConn,
	core *client.Core,
	mtu int,
) error {
	runtime, err := NewClientRuntime(dev, conn, core, mtu, ClientRuntimeConfig{})
	if err != nil {
		return err
	}
	return runtime.Run()
}

// clientUDPSender owns reusable sendmmsg descriptors for the TX engine. The
// engine already serializes calls for the single client Peer; the mutex keeps
// the adapter safe if another ordered protocol producer is added later.
type clientUDPSender struct {
	mu   sync.Mutex
	conn *ipv4.PacketConn

	messages []ipv4.Message
	addrs    []net.UDPAddr
	ips      [][4]byte
}

func newClientUDPSender(conn *ipv4.PacketConn, capacity int) *clientUDPSender {
	s := &clientUDPSender{conn: conn}
	s.ensureCapacity(capacity)
	return s
}

func (s *clientUDPSender) ensureCapacity(count int) {
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

func (s *clientUDPSender) Send(packets []client.TXPacket) error {
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
			return fmt.Errorf("invalid client TX destination %v", destination)
		}
		addr := destination.Addr().Unmap()
		if !addr.Is4() {
			return fmt.Errorf("client TX destination is not IPv4: %v", destination)
		}

		ipv4Addr := addr.As4()
		copy(s.ips[i][:], ipv4Addr[:])
		s.addrs[i].Port = int(destination.Port())
		s.addrs[i].Zone = ""

		messages[i].Buffers[0] = packet.Wire
		messages[i].Addr = &s.addrs[i]
	}

	if err := writeUDPBatch(s.conn, messages); err != nil {
		return fmt.Errorf("write client UDP batch: %w", err)
	}
	return nil
}

func runClientTunIngress(
	dev tun.Device,
	core *client.Core,
	txEngine *client.TXEngine,
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
	submissions := make([]client.TXOwnedSubmission, batchSize)

	for {
		n, err := dev.Read(bufs, sizes, dataplane.RouteSize)
		if err != nil {
			return fmt.Errorf("read client TUN: %w", err)
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
				// Malformed/unauthorized input and lifecycle unavailability are
				// packet-local. These errors indicate a broken runtime invariant or
				// exhausted nonce space and cannot be safely ignored.
				if errors.Is(err, dataplane.ErrSequenceExhausted) ||
					errors.Is(err, dataplane.ErrBufferTooSmall) ||
					errors.Is(err, dataplane.ErrInvalidConfig) {
					return fmt.Errorf("admit client TUN packet: %w", err)
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
			return fmt.Errorf("enqueue client TUN TX batch: %w", err)
		}

		// Engine now owns accepted buffers and operation state. Clear the ingress
		// descriptors before waiting for replacement buffers so this reusable
		// slice does not retain sessions or packet slices.
		for i := 0; i < accepted; i++ {
			submissions[i] = client.TXOwnedSubmission{}
		}
		for i := 0; i < accepted; i++ {
			index := indices[i]
			bufs[index] = pool.Get()
		}
	}
}

func runClientUDPIngress(
	conn *ipv4.PacketConn,
	core *client.Core,
	admitScratch *dataplane.DataScratch,
	rxEngine *client.RXEngine,
	pool *runtimePacketPool,
	batchSize int,
	demux ClientDatagramDemux,
) error {
	bufs := make([][]byte, batchSize)
	messages := make([]ipv4.Message, batchSize)
	for i := range bufs {
		bufs[i] = pool.Get()
		messages[i].Buffers = [][]byte{bufs[i]}
	}

	indices := make([]int, batchSize)
	submissions := make([]client.RXOwnedSubmission, batchSize)

	for {
		n, err := conn.ReadBatch(messages, 0)
		if err != nil {
			return fmt.Errorf("read client UDP batch: %w", err)
		}
		// One timestamp is captured immediately after dequeue, before any packet
		// in this kernel batch enters the control-plane classifier. A slow demux
		// decision for packet #0 therefore cannot extend the lifecycle admission
		// time observed by later transport packets from the same batch.
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

			if demux != nil {
				handled, err := demux.HandleDatagram(source, route, routeDecoded, packet)
				if err != nil {
					return fmt.Errorf("client UDP control-plane demux: %w", err)
				}
				if handled {
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
				// Garbage, unknown/expired Session and bad route decoding are silent
				// packet-local drops at the unauthenticated network boundary.
				continue
			}

			indices[accepted] = i
			accepted++
		}

		if accepted == 0 {
			continue
		}

		if err := rxEngine.EnqueueOwnedBatch(submissions[:accepted], pool); err != nil {
			return fmt.Errorf("enqueue client UDP RX batch: %w", err)
		}

		for i := 0; i < accepted; i++ {
			submissions[i] = client.RXOwnedSubmission{}
		}
		for i := 0; i < accepted; i++ {
			index := indices[i]
			bufs[index] = pool.Get()
			messages[index].Buffers[0] = bufs[index]
		}
	}
}
