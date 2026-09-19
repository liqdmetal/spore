// Package safehttp centralizes the listener-safety policy for every network
// surface spore exposes (audit C1/C2/C3, ROADMAP-PRODUCTION T3 "least
// exposure"):
//
//   - all listeners default to a LOOPBACK bind;
//   - a NON-loopback bind is refused unless the operator explicitly supplies a
//     shared-secret Bearer token — erroring out, not warning, so a home node
//     can never come up as an open plaintext archive on a public interface;
//   - callers additionally log a warning when the surface carries plaintext
//     and no TLS is configured.
//
// Every CLI command that calls ListenAndServe must route its -listen value
// through CheckBind before serving.
package safehttp

import (
	"fmt"
	"net"
	"strings"
)

// HostIsLoopback reports whether the host part of addr (host[:port], or a
// :port-only value meaning "all interfaces") binds to loopback only. A bare
// ":port" or "0.0.0.0:port" binds ALL interfaces and is NOT loopback.
func HostIsLoopback(addr string) bool {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		if h == "" {
			return false // ":port" = all interfaces
		}
		return isLoopbackHost(h)
	}
	// No port suffix: the whole string is a host (e.g. "::1" — which
	// SplitHostPort rejects for too many colons).
	return isLoopbackHost(addr)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CheckBind validates a listen address against the exposure policy:
// a non-loopback bind requires a non-empty auth token. surface names the
// component (for the error message). Returns nil when the bind may proceed.
func CheckBind(addr, token, surface string) error {
	if HostIsLoopback(addr) {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf(
			"%s: refusing to listen on %s — a non-loopback bind exposes this surface to the network and requires an auth token (-token SECRET). Default is loopback-only; see docs/HOME_NODE.md",
			surface, addr,
		)
	}
	return nil
}
