//go:build !windows && !unix

package main

// pidAlive cannot probe processes on this platform, so report the
// conservative answer: treat every holder as alive and let only the TTL
// break locks, never liveness.
func pidAlive(pid int) bool { return true }
