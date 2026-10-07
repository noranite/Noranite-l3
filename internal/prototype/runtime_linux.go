//go:build linux

package prototype

import (
	"fmt"

	"github.com/noranite/Noranite-l3/internal/tun"

	"golang.org/x/net/ipv4"
)

const runtimeTUNGROBackingCapacity = (1 << 16) - 1

// runtimePacketPool is the bounded ownership/backpressure boundary shared by
// the Linux client/server runtimes. Buffers are transferred to asynchronous
// packet operations and returned only after the last consumer is finished.
type runtimePacketPool struct {
	bufferSize     int
	bufferCapacity int
	buffers        chan []byte
}

func newRuntimePacketPool(bufferSize, count int) *runtimePacketPool {
	return newRuntimePacketPoolWithCapacity(bufferSize, bufferSize, count)
}

// newRuntimeGROPacketPool keeps the UDP receive length bounded by bufferSize,
// while reserving enough spare backing capacity for wireguard-go's Linux
// NativeTun software GRO to coalesce decrypted packets in place. The 65535-byte
// capacity matches wireguard-go's default Linux message-buffer backing size.
//
// Memory note: with the current client policy (BatchSize=128 and four batches),
// this is 512 * 65535 bytes, approximately 32 MiB of bounded RX backing storage.
// That is an intentional Linux GRO memory cost, not GC churn. Do not carry this
// buffer geometry unchanged to memory-constrained platform runtimes such as iOS.
func newRuntimeGROPacketPool(bufferSize, count int) *runtimePacketPool {
	return newRuntimePacketPoolWithCapacity(
		bufferSize,
		max(bufferSize, runtimeTUNGROBackingCapacity),
		count,
	)
}

func newRuntimePacketPoolWithCapacity(
	bufferSize int,
	bufferCapacity int,
	count int,
) *runtimePacketPool {
	if bufferCapacity < bufferSize {
		panic("runtime packet pool capacity smaller than logical buffer size")
	}

	pool := &runtimePacketPool{
		bufferSize:     bufferSize,
		bufferCapacity: bufferCapacity,
		buffers:        make(chan []byte, count),
	}
	for i := 0; i < count; i++ {
		pool.buffers <- make([]byte, bufferSize, bufferCapacity)
	}
	return pool
}

func (p *runtimePacketPool) Get() []byte {
	return <-p.buffers
}

// TryGet acquires a buffer without blocking. It is used when a producer holds
// other pooled buffers that must be submitted before waiting for more storage.
func (p *runtimePacketPool) TryGet() ([]byte, bool) {
	select {
	case buffer := <-p.buffers:
		return buffer, true
	default:
		return nil, false
	}
}

func (p *runtimePacketPool) Put(buffer []byte) {
	if cap(buffer) < p.bufferCapacity {
		panic("runtime packet pool received undersized buffer")
	}
	p.buffers <- buffer[:p.bufferSize]
}

type runtimeErrorReporter struct {
	c chan<- error
}

func (r runtimeErrorReporter) Report(err error) {
	if err == nil {
		return
	}
	select {
	case r.c <- err:
	default:
	}
}

// writeUDPBatch sends every message, handling legal partial-progress returns
// from sendmmsg-style implementations.
func writeUDPBatch(conn *ipv4.PacketConn, messages []ipv4.Message) error {
	for len(messages) > 0 {
		n, err := conn.WriteBatch(messages, 0)
		if err != nil {
			return err
		}
		if n <= 0 {
			return fmt.Errorf("UDP batch write made no progress")
		}
		messages = messages[n:]
	}
	return nil
}

func drainTunEvents(dev tun.Device) {
	for range dev.Events() {
	}
}
