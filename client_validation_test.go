package noranite

import (
	"errors"
	"fmt"
	"testing"

	"github.com/noranite/Noranite-l3/internal/dataplane"
)

func TestNewClientRouteKeyValidation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		key   [32]byte
		valid bool
	}{
		{name: "zero"},
		{name: "first byte", key: [32]byte{1}, valid: true},
		{name: "last byte", key: [32]byte{31: 1}, valid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			device := newTestPacketDevice()
			defer device.Close()
			config := testPublicClientConfig(t, DefaultMTU)
			config.RouteKey = tt.key
			client, err := NewClient(config, device, nil)
			if client != nil {
				defer client.Close()
			}
			if tt.valid {
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				return
			}
			if client != nil || !errors.Is(err, dataplane.ErrInvalidConfig) {
				t.Fatalf("NewClient = (%v, %v), want nil, ErrInvalidConfig", client, err)
			}
			select {
			case <-device.done:
				t.Fatal("rejected config transferred device ownership")
			default:
			}
		})
	}
}

func TestNewClientMTUBounds(t *testing.T) {
	mtus := []int{-1, 0, 20, DefaultMTU, MaxTunnelMTU, MaxTunnelMTU + 1}
	for mtu := 1; mtu < 20; mtu++ {
		mtus = append(mtus, mtu)
	}
	for _, mtu := range mtus {
		t.Run(fmt.Sprint(mtu), func(t *testing.T) {
			device := newTestPacketDevice()
			defer device.Close()
			client, err := NewClient(testPublicClientConfig(t, mtu), device, nil)
			if client != nil {
				defer client.Close()
			}
			if mtu >= 20 && mtu <= MaxTunnelMTU {
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
			} else if client != nil || !errors.Is(err, dataplane.ErrInvalidConfig) {
				t.Fatalf("NewClient = (%v, %v), want nil, ErrInvalidConfig", client, err)
			}
		})
	}
}
