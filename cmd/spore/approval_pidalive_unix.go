//go:build unix

package main

import "syscall"

// pidAlive reports whether a process with the given PID exists locally. It
// underlies signing-lock liveness breaking: a lock whose holder is provably
// gone can be broken ahead of the TTL.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Signal 0 probes existence: nil means alive, EPERM means alive but owned
	// by another user. Anything else (ESRCH) means the process is gone.
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
