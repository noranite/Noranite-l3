package main

import (
	"net"
	"net/netip"
	"testing"
)

type testNetworkAddress string

func (a testNetworkAddress) Network() string { return "test" }
func (a testNetworkAddress) String() string  { return string(a) }

func TestTunnelAddressMatchesExactHostAndPrefix(t *testing.T) {
	addresses := []net.Addr{
		testNetworkAddress("10.66.0.1/16"),
		testNetworkAddress("fe80::1/64"),
	}

	if !tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/16"), addresses) {
		t.Fatal("exact tunnel address did not match")
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.2/16"), addresses) {
		t.Fatal("different host address in the same /16 unexpectedly matched")
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/24"), addresses) {
		t.Fatal("different prefix length unexpectedly matched")
	}
}

func TestTunnelAddressMatchesIgnoresMalformedAndIPv6Addresses(t *testing.T) {
	addresses := []net.Addr{
		testNetworkAddress("not-an-address"),
		testNetworkAddress("fe80::1/64"),
	}
	if tunnelAddressMatches(netip.MustParsePrefix("10.66.0.1/16"), addresses) {
		t.Fatal("unexpected tunnel address match")
	}
}
