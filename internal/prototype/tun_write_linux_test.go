//go:build linux

package prototype

import (
	"errors"
	"io"
	"testing"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/tun"
)

type writeResultTun struct {
	tun.Device
	n       int
	err     error
	calls   int
	packets int
	offset  int
}

func (d *writeResultTun) Write(bufs [][]byte, offset int) (int, error) {
	d.calls++
	d.packets = len(bufs)
	d.offset = offset
	return d.n, d.err
}

func TestRuntimeTUNWriteResults(t *testing.T) {
	deviceErr := errors.New("TUN write failed")
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			for _, tt := range []struct {
				name    string
				packets int
				n       int
				err     error
				want    error
			}{
				{name: "empty"},
				{name: "complete", packets: 2, n: 2},
				{name: "zero write", packets: 2, want: io.ErrShortWrite},
				{name: "partial write", packets: 2, n: 1, want: io.ErrShortWrite},
				{name: "device error", packets: 2, n: 1, err: deviceErr, want: deviceErr},
			} {
				t.Run(tt.name, func(t *testing.T) {
					dev := &writeResultTun{n: tt.n, err: tt.err}
					clientResults := make([]client.RXResult, tt.packets)
					serverResults := make([]server.RXOwnedResult, tt.packets)
					for i := 0; i < tt.packets; i++ {
						buffer := make([]byte, dataplane.RouteSize+20)
						inner := buffer[dataplane.RouteSize:]
						inner[0] = 0x45
						inner[3] = 20
						inbound := dataplane.InboundPacket{Kind: dataplane.InboundIPv4, IPv4: inner}
						clientResults[i] = client.RXResult{Inbound: inbound, Buffer: buffer}
						serverResults[i] = server.RXOwnedResult{Inbound: inbound, Buffer: buffer}
					}
					var err error
					if side == "client" {
						runtime := &ClientRuntime{dev: dev}
						err = runtime.consumeRXResults(clientResults)
					} else {
						consumer := newServerRXConsumer(dev, nil, nil, 2)
						err = consumer(serverResults)
					}
					if !errors.Is(err, tt.want) {
						t.Fatalf("consume error=%v, want %v", err, tt.want)
					}
					wantCalls := 1
					if tt.packets == 0 {
						wantCalls = 0
					}
					if dev.calls != wantCalls || dev.packets != tt.packets {
						t.Fatalf("Write calls=%d packets=%d, want %d calls with %d packets", dev.calls, dev.packets, wantCalls, tt.packets)
					}
					if dev.calls > 0 && dev.offset != dataplane.RouteSize {
						t.Fatalf("Write offset=%d, want %d", dev.offset, dataplane.RouteSize)
					}
				})
			}
		})
	}
}

func TestServerRXConsumerPreservesInvariantErrorOnShortWrite(t *testing.T) {
	dev := &writeResultTun{}
	consumer := newServerRXConsumer(dev, nil, nil, 2)
	buffer := make([]byte, dataplane.RouteSize+20)
	err := consumer([]server.RXOwnedResult{
		{Err: dataplane.ErrInvalidConfig},
		{Inbound: dataplane.InboundPacket{Kind: dataplane.InboundIPv4, IPv4: buffer[dataplane.RouteSize:]}, Buffer: buffer},
	})
	if !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, dataplane.ErrInvalidConfig) {
		t.Fatalf("consumer error=%v, want ErrShortWrite and ErrInvalidConfig", err)
	}
}
