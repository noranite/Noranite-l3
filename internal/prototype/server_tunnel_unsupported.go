//go:build !linux

package prototype

import (
	"fmt"
	"net"

	"github.com/noranite/Noranite-l3/internal/server"
	"github.com/noranite/Noranite-l3/internal/tun"
)

// RunServerTunnel has a Linux implementation because the current runtime uses
// recvmmsg/sendmmsg-style batch I/O and the Linux TUN path.
func RunServerTunnel(
	dev tun.Device,
	conn *net.UDPConn,
	core *server.Core,
	establishmentIngress ServerEstablishmentIngress,
	mtu int,
) error {
	return fmt.Errorf("parallel server tunnel runtime is supported only on linux")
}

func RunServerTunnelWithHook(
	dev tun.Device, conn *net.UDPConn, core *server.Core,
	establishmentIngress ServerEstablishmentIngress, mtu int,
	onReady func(*server.RXEngine, *server.TXEngine) error,
	onShutdown func(),
) error {
	return fmt.Errorf("parallel server tunnel runtime is supported only on linux")
}
