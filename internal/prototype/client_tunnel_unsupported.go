//go:build !linux

package prototype

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/noranite/Noranite-l3/internal/client"
	"github.com/noranite/Noranite-l3/internal/dataplane"
	"github.com/noranite/Noranite-l3/internal/tun"
)

var (
	ErrClientRuntimeStarted    = errors.New("client runtime already started")
	ErrClientRuntimeNotRunning = errors.New("client runtime is not accepting protocol traffic")
)

type ClientDatagramDemux interface {
	HandleDatagram(
		source netip.AddrPort,
		route dataplane.Route,
		routeDecoded bool,
		packet []byte,
	) (handled bool, err error)
}

type ClientAuthenticatedEventSink interface {
	HandleAuthenticatedACK(keepaliveID uint64)
}

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

type ClientRuntimeConfig struct {
	RXEngine client.RXEngineConfig
	TXEngine client.TXEngineConfig
}

type ClientRuntime struct{}

func NewClientRuntime(
	dev tun.Device,
	conn *net.UDPConn,
	core *client.Core,
	mtu int,
	config ClientRuntimeConfig,
) (*ClientRuntime, error) {
	return nil, fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}

func (r *ClientRuntime) SetDatagramDemux(ClientDatagramDemux) error {
	return fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}
func (r *ClientRuntime) SubmitProtocolTransport(*client.OutboundOperation) error {
	return fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}
func (r *ClientRuntime) SendProtocolDatagram([]byte, netip.AddrPort) error {
	return fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}
func (r *ClientRuntime) Ready() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (r *ClientRuntime) Done() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
func (r *ClientRuntime) Close() {}
func (r *ClientRuntime) Run() error {
	return fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}

// RunClientTunnel has a Linux implementation because the current runtime uses
// recvmmsg/sendmmsg-style batch I/O and the Linux TUN path.
func RunClientTunnel(
	dev tun.Device,
	conn *net.UDPConn,
	core *client.Core,
	mtu int,
) error {
	return fmt.Errorf("parallel client tunnel runtime is supported only on linux")
}
