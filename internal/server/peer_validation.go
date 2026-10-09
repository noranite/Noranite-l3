package server

import (
	"fmt"
	"net/netip"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

// ValidateTunnelIPv4 applies the server-wide policy for inner peer addresses.
func ValidateTunnelIPv4(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return fmt.Errorf("invalid tunnel IPv4 %s: %w", ip, dataplane.ErrInvalidConfig)
	}
	return nil
}
