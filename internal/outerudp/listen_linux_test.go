//go:build linux

package outerudp

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenIPv4ConfiguresSocketBuffers(t *testing.T) {
	conn, err := ListenIPv4(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("ListenIPv4: %v", err)
	}
	defer conn.Close()

	readBuffer, writeBuffer := socketBuffers(t, conn)

	// Linux doubles SO_RCVBUF/SO_SNDBUF values for kernel accounting and caps
	// ordinary setsockopt requests at rmem_max/wmem_max. A successful FORCE call
	// may raise the effective value further, so these are lower bounds.
	if max, ok := readSysctlInt(t, "/proc/sys/net/core/rmem_max"); ok {
		wantMin := 2 * min(socketBufferSize, max)
		if readBuffer < wantMin {
			t.Fatalf("SO_RCVBUF=%d, want at least %d", readBuffer, wantMin)
		}
	}
	if max, ok := readSysctlInt(t, "/proc/sys/net/core/wmem_max"); ok {
		wantMin := 2 * min(socketBufferSize, max)
		if writeBuffer < wantMin {
			t.Fatalf("SO_SNDBUF=%d, want at least %d", writeBuffer, wantMin)
		}
	}
}

func socketBuffers(t *testing.T, conn *net.UDPConn) (int, int) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var readBuffer int
	var writeBuffer int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		readBuffer, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if controlErr != nil {
			return
		}
		writeBuffer, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
	if controlErr != nil {
		t.Fatalf("getsockopt: %v", controlErr)
	}
	return readBuffer, writeBuffer
}

func readSysctlInt(t *testing.T, path string) (int, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("cannot read %s; skipping exact socket-buffer lower bound: %v", path, err)
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return value, true
}
