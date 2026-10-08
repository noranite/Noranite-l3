package tun

import (
	"fmt"
	"io"
	"runtime"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device is the subset of the batch-oriented wireguard-go TUN API used by
// Opaque-L3.
type Device interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	// Write returns the number of packets written, not bytes.
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

// linuxNativeTUN normalizes the return value of the pinned wireguard-go
// Linux NativeTun.Write. That implementation sums os.File.Write byte counts
// (including virtio headers), although Device.Write promises a packet count.
// Once it returns a nil error, every underlying write completed; os.File.Write
// reports a short write as an error. GRO also means the number of kernel writes
// may differ from the number of input packets.
type linuxNativeTUN struct {
	wgtun.Device
}

func (d *linuxNativeTUN) Write(bufs [][]byte, offset int) (int, error) {
	written, err := d.Device.Write(bufs, offset)
	if err != nil {
		return 0, err
	}
	if len(bufs) > 0 && written == 0 {
		return 0, io.ErrShortWrite
	}
	return len(bufs), nil
}

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

	if runtime.GOOS == "linux" {
		return &linuxNativeTUN{Device: dev}, nil
	}
	return dev, nil
}
