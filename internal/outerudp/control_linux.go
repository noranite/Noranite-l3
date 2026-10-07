//go:build linux

package outerudp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// socketControl applies Linux outer-UDP socket policy before bind.
//
// The ordinary SO_RCVBUF/SO_SNDBUF calls remove dependence on the system
// default sizes. The FORCE variants additionally let a process with
// CAP_NET_ADMIN exceed net.core.rmem_max/wmem_max. All four calls are best
// effort by design: inability to raise a performance-related limit must not
// make an otherwise valid tunnel fail to start.
func socketControl(_ string, _ string, raw syscall.RawConn) error {
	return raw.Control(func(fd uintptr) {
		fdInt := int(fd)
		_ = unix.SetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
		_ = unix.SetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
		_ = unix.SetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketBufferSize)
		_ = unix.SetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, socketBufferSize)
	})
}
