package outerudp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// socketBufferSize is the requested kernel socket buffer size for the outer
// UDP transport. It deliberately matches wireguard-go@ecfc5a8d5446's 7 MiB
// request: large enough to absorb packet-processing bursts without making the
// application depend on net.core.rmem_default/wmem_default.
const socketBufferSize = 7 << 20

// ListenIPv4 creates a fully configured IPv4 outer UDP socket.
//
// Socket policy belongs at resource construction, before establishment or the
// dataplane can use the descriptor. On Linux socketControl also attempts the
// privileged SO_RCVBUFFORCE/SO_SNDBUFFORCE variants; failure of those attempts
// is intentionally non-fatal so unprivileged deployments still work with the
// largest buffers allowed by net.core.rmem_max/wmem_max.
func ListenIPv4(addr netip.AddrPort) (*net.UDPConn, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("outer UDP bind address is invalid: %v", addr)
	}
	ipv4 := addr.Addr().Unmap()
	if !ipv4.Is4() {
		return nil, fmt.Errorf("outer UDP bind address must be IPv4: %v", addr)
	}
	addr = netip.AddrPortFrom(ipv4, addr.Port())

	listenConfig := net.ListenConfig{Control: socketControl}
	packetConn, err := listenConfig.ListenPacket(
		context.Background(),
		"udp4",
		addr.String(),
	)
	if err != nil {
		return nil, err
	}

	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("unexpected outer UDP connection type %T", packetConn)
	}
	return conn, nil
}
