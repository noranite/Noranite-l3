package provisioning

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateTunnelIPv4From16(t *testing.T) {
	address := netip.MustParsePrefix("10.66.0.1/16")
	used := []netip.Addr{
		netip.MustParseAddr("10.66.0.2"),
		netip.MustParseAddr("10.66.0.3"),
	}
	got, err := AllocateTunnelIPv4(address, used)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.66.0.4"); got != want {
		t.Fatalf("allocated %s, want %s", got, want)
	}
}

func TestAllocateTunnelIPv4IgnoresAddressesOutsidePool(t *testing.T) {
	address := netip.MustParsePrefix("10.66.0.1/16")
	used := []netip.Addr{
		netip.MustParseAddr("10.67.0.2"),
		netip.MustParseAddr("192.0.2.10"),
	}
	got, err := AllocateTunnelIPv4(address, used)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.66.0.2"); got != want {
		t.Fatalf("allocated %s, want %s", got, want)
	}
}

func TestAllocateTunnelIPv4DoesNotTreat24BoundariesAsReserved(t *testing.T) {
	address := netip.MustParsePrefix("10.66.0.1/16")
	used := make([]netip.Addr, 0, 254)
	for raw := 2; raw < 256; raw++ {
		used = append(used, netip.AddrFrom4([4]byte{10, 66, 0, byte(raw)}))
	}
	got, err := AllocateTunnelIPv4(address, used)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.66.1.0"); got != want {
		t.Fatalf("allocated %s, want %s", got, want)
	}
}

func TestValidateTunnelAddressRequires16AndHostAddress(t *testing.T) {
	for _, text := range []string{"10.66.0.1/24", "10.66.0.0/16", "10.66.255.255/16", "2001:db8::1/16"} {
		if err := ValidateTunnelAddress(netip.MustParsePrefix(text)); err == nil {
			t.Fatalf("ValidateTunnelAddress(%s) unexpectedly succeeded", text)
		}
	}
}

func TestAllocateTunnelIPv4Exhausted(t *testing.T) {
	address := netip.MustParsePrefix("10.66.0.1/16")
	used := make([]netip.Addr, 0, 65533)
	for a := uint32(0x0a420002); a <= 0x0a42fffe; a++ {
		used = append(used, uint32IPv4(a))
	}
	_, err := AllocateTunnelIPv4(address, used)
	if !errors.Is(err, ErrAddressPoolExhausted) {
		t.Fatalf("AllocateTunnelIPv4: %v", err)
	}
}
