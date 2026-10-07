package tun

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device is the subset of the batch-oriented wireguard-go TUN API used by
// Opaque-L3.
type Device interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)

	MTU() (int, error)
	Name() (string, error)
	BatchSize() int

	Events() <-chan Event

	Close() error
}

type Event = wgtun.Event

const (
	EventUp        = wgtun.EventUp
	EventDown      = wgtun.EventDown
	EventMTUUpdate = wgtun.EventMTUUpdate
)

// Open creates a TUN device and sets its MTU. Addresses, routes, and link state
// are configured by the caller.
func Open(name string, mtu int) (Device, error) {
	if name == "" {
		return nil, fmt.Errorf("TUN name is empty")
	}
	if mtu <= 0 {
		return nil, fmt.Errorf("invalid TUN MTU %d", mtu)
	}

	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}

	return dev, nil
}
