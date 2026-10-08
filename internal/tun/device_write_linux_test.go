//go:build linux

package tun

import (
	"errors"
	"io"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type byteCountingTUN struct {
	wgtun.Device
	written   int
	err       error
	gotCount  int
	gotOffset int
}

func (d *byteCountingTUN) Write(bufs [][]byte, offset int) (int, error) {
	d.gotCount = len(bufs)
	d.gotOffset = offset
	return d.written, d.err
}

func TestLinuxNativeTUNNormalizesByteCount(t *testing.T) {
	writeErr := errors.New("native TUN write failed")
	tests := []struct {
		name        string
		packets     int
		written     int
		err         error
		wantPackets int
		wantErr     error
	}{
		{name: "single native TUN packet", packets: 1, written: 70, wantPackets: 1},
		{name: "multiple native TUN packets", packets: 3, written: 210, wantPackets: 3},
		{name: "GRO coalesced writes", packets: 3, written: 130, wantPackets: 3},
		{name: "empty batch"},
		{name: "zero byte write", packets: 1, wantErr: io.ErrShortWrite},
		{name: "native error", packets: 1, written: 70, err: writeErr, wantErr: writeErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := &byteCountingTUN{written: tt.written, err: tt.err}
			device := &linuxNativeTUN{Device: underlying}
			bufs := make([][]byte, tt.packets)
			for i := range bufs {
				bufs[i] = make([]byte, 96)
			}
			const offset = 16
			count, err := device.Write(bufs, offset)
			if count != tt.wantPackets || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Write count=%d err=%v, want count=%d err=%v", count, err, tt.wantPackets, tt.wantErr)
			}
			if underlying.gotCount != tt.packets || underlying.gotOffset != offset {
				t.Fatalf("underlying called with count=%d offset=%d, want %d and %d", underlying.gotCount, underlying.gotOffset, tt.packets, offset)
			}
		})
	}
}
