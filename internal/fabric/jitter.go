package fabric

// Drain-cadence jitter (F3; AUDIT-RELAYFABRIC.md R-N2).
//
// A drain loop on a fixed interval is a timing signature: a relay operator
// can read drain regularity per handle and correlate handle activity across
// relays (the threat model's timing-correlator row). Jittering the cadence
// by +/-20% per pass -- the same shape internal/relay's backoff uses --
// decorrelates drain starts across processes and relays without any
// protocol change.

import (
	"math/rand"
	"time"
)

// JitteredInterval widens base by ±percent (20 → [0.8·base, 1.2·base]),
// drawing uniformly from rnd (nil = the global math/rand source).
// percent <= 0 or base <= 0 returns base unchanged; a percent over 100 is
// clamped so the result can never go negative.
//
// Deterministic given a seeded rnd: the drain loop's tests pass a local
// *rand.Rand, production passes nil.
func JitteredInterval(base time.Duration, percent int, rnd *rand.Rand) time.Duration {
	if percent <= 0 || base <= 0 {
		return base
	}
	span := int64(base) * int64(percent) / 100
	if span <= 0 {
		return base
	}
	if percent > 100 {
		// Clamp the span at the base itself: the widest honest jitter is
		// [0, 2·base], never a negative wait.
		span = int64(base)
	}
	var d int64
	if rnd != nil {
		d = rnd.Int63n(2*span + 1)
	} else {
		d = rand.Int63n(2*span + 1)
	}
	out := int64(base) - span + d
	if out < 0 {
		out = 0
	}
	return time.Duration(out)
}
