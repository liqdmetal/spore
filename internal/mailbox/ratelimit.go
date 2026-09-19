package mailbox

import (
	"sync"
	"time"
)

// Prekey-pop rate limiting (audit M1): on a tokenless (self-host) mailbox,
// GET /prekey pops single-use bundles, so an anonymous drainer can exhaust
// the owner's prekey batch and force every later sender into degraded
// no-OPK mode. A per-client-IP token bucket (refill 1 per
// prekeyRefillInterval, burst prekeyBurst) lets any handful of genuine new
// contacts through immediately while making sustained draining slow enough
// that a 1000-bundle batch survives ~days, not minutes.
//
// Limitations, honestly: all senders behind one NAT or one TLS-terminating
// proxy share one bucket, and a distributed drainer spreads across IPs —
// this raises the bar, it does not close the hole. The complete fix for a
// public deployment is HandlerToken (see HOME_NODE.md), which gates the
// route entirely; this limiter only protects the open self-host posture.
// Set prekeyBurst/prekeyRefillInterval before serving to tune; the vars
// exist (instead of consts) so tests can shrink the limits.

var (
	prekeyBurst          = 30
	prekeyRefillInterval = 6 * time.Second
	// prekeyBucketCap bounds the per-IP map so a spoofed-source flood cannot
	// grow it without bound. When exceeded, all buckets are dropped (crude
	// but safe: worst case a client re-accumulates tokens).
	prekeyBucketCap = 65536
)

type prekeyBucket struct {
	tokens float64
	last   time.Time
}

// prekeyLimiter is a mutex-guarded map of per-IP token buckets.
type prekeyLimiter struct {
	mu      sync.Mutex
	buckets map[string]*prekeyBucket
}

func newPrekeyLimiter() *prekeyLimiter {
	return &prekeyLimiter{buckets: make(map[string]*prekeyBucket)}
}

// allow reports whether one prekey pop is permitted for this instant.
func (l *prekeyLimiter) allow(now time.Time, clientIP string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > prekeyBucketCap {
		l.buckets = make(map[string]*prekeyBucket)
	}
	b, ok := l.buckets[clientIP]
	if !ok {
		// First request: grant the burst MINUS this request, so a full burst
		// is never burst+1 free pops.
		l.buckets[clientIP] = &prekeyBucket{tokens: float64(prekeyBurst) - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens += elapsed.Seconds() / prekeyRefillInterval.Seconds()
		if b.tokens > float64(prekeyBurst) {
			b.tokens = float64(prekeyBurst)
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
