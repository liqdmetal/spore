//go:build windows

package main

import "syscall"

// processQueryLimitedInformation grants status queries without handle rights;
// value from the Win32 API (also used by os.FindProcess via internal/syscall).
const processQueryLimitedInformation = 0x1000

// pidAlive reports whether a process with the given PID exists locally. It
// underlies signing-lock liveness breaking: a lock whose holder is provably
// gone can be broken ahead of the TTL.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Query rights only: we never touch the process, and limited information
	// is granted even for other users' processes.
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if h != 0 {
		syscall.CloseHandle(h)
		return true
	}
	// Existing but inaccessible (another user's session) counts as alive.
	return err == syscall.ERROR_ACCESS_DENIED
}
