//go:build !linux

package outerudp

import "syscall"

// Non-Linux builds do not require the Linux-specific socket policy.
func socketControl(_ string, _ string, _ syscall.RawConn) error {
	return nil
}
