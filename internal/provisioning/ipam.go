package provisioning

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrAddressPoolExhausted = errors.New("tunnel IPv4 pool is exhausted")

const (
	ipv4PoolSize       = 1 << 16
	ipv4PoolBitmapSize = ipv4PoolSize / 8
)

// ValidateTunnelAddress validates the installation-level address plan used by
// the provisioning utility. Runtime protocol code intentionally does not know
// about this /16 policy.
func ValidateTunnelAddress(address netip.Prefix) error {
	if !address.IsValid() || !address.Addr().Unmap().Is4() {
		return fmt.Errorf("tunnel address must be IPv4 /16")
	}
	if address.Bits() != 16 {
		return fmt.Errorf("tunnel address prefix length %d, want /16", address.Bits())
	}
	server := ipv4Uint32(address.Addr().Unmap())
	network := ipv4Uint32(address.Masked().Addr().Unmap())
	broadcast := network | 0xffff
	if server == network || server == broadcast {
		return fmt.Errorf("server tunnel address must be a host address inside %s", address.Masked())
	}
	return nil
}

// AllocateTunnelIPv4 returns the first free host address in the /16, excluding
// the server address, network address and broadcast address. The occupied set
// is represented as an 8 KiB bitmap, so allocation is bounded by one pass over
// the 65,536 addresses regardless of how many peers are currently configured.
// Addresses outside this /16 do not occupy space in this pool.
func AllocateTunnelIPv4(address netip.Prefix, used []netip.Addr) (netip.Addr, error) {
	if err := ValidateTunnelAddress(address); err != nil {
		return netip.Addr{}, err
	}

	network := ipv4Uint32(address.Masked().Addr().Unmap())
	serverOffset := uint16(ipv4Uint32(address.Addr().Unmap()) - network)

	var occupied [ipv4PoolBitmapSize]byte
	setOccupied(&occupied, 0)
	setOccupied(&occupied, serverOffset)
	setOccupied(&occupied, 0xffff)

	for _, addr := range used {
		addr = addr.Unmap()
		if !addr.Is4() || !address.Masked().Contains(addr) {
			continue
		}
		offset := uint16(ipv4Uint32(addr) - network)
		setOccupied(&occupied, offset)
	}

	for offset := uint32(1); offset < 0xffff; offset++ {
		if isOccupied(&occupied, uint16(offset)) {
			continue
		}
		return uint32IPv4(network + offset), nil
	}
	return netip.Addr{}, ErrAddressPoolExhausted
}

func setOccupied(bitmap *[ipv4PoolBitmapSize]byte, offset uint16) {
	bitmap[offset>>3] |= byte(1 << (offset & 7))
}

func isOccupied(bitmap *[ipv4PoolBitmapSize]byte, offset uint16) bool {
	return bitmap[offset>>3]&byte(1<<(offset&7)) != 0
}

func ipv4Uint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func uint32IPv4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}
