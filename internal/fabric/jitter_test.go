package fabric

// Jitter tests (F3; AUDIT-RELAYFABRIC.md R-N2): the cadence jitter must be
// bounded (+/-percent), deterministic under a seeded rng (reproducible
// tests), degenerate-input safe, and actually diffuse (a distribution that
// always returns the base would be a no-op dressed as jitter).

import (
	"math/rand"
	"testing"
	"time"
)

func TestJitteredIntervalBounds(t *testing.T) {
	base := 10 * time.Second
	// Seeded: every value must land inside [0.8*base, 1.2*base], and the
	// same seed must reproduce the same sequence (tests pin behavior).
	r1 := rand.New(rand.NewSource(42))
	r2 := rand.New(rand.NewSource(42))
	lo, hi := int64(base)*8/10, int64(base)*12/10
	for i := 0; i < 1000; i++ {
		got := JitteredInterval(base, 20, r1)
		if int64(got) < lo || int64(got) > hi {
			t.Fatalf("jitter out of bounds: %s not in [%d,%d]", got, lo, hi)
		}
		if want := JitteredInterval(base, 20, r2); want != got {
			t.Fatalf("seeded jitter not reproducible: %s vs %s", got, want)
		}
	}
}

func TestJitteredIntervalDegenerateInputs(t *testing.T) {
	// Zero/negative base and non-positive percent: unchanged, never a panic.
	for _, base := range []time.Duration{0, -1, -time.Second} {
		if got := JitteredInterval(base, 20, nil); got != base {
			t.Fatalf("base %s must pass through, got %s", base, got)
		}
	}
	for _, pct := range []int{0, -5} {
		if got := JitteredInterval(time.Second, pct, nil); got != time.Second {
			t.Fatalf("percent %d must be a no-op, got %s", pct, got)
		}
	}
	// Tiny base (1ns) with a huge percent must never go negative — the
	// clamp keeps the span at the base itself.
	for i := 0; i < 1000; i++ {
		if got := JitteredInterval(1, 5000, nil); got < 0 {
			t.Fatalf("jitter went negative: %d", got)
		}
	}
	// A 1ns base can only produce 0 or 1 ns (span clamped to base).
	for i := 0; i < 100; i++ {
		if got := JitteredInterval(1, 100, nil); got > 2 {
			t.Fatalf("clamped span exceeded 2x base: %d", got)
		}
	}
}

func TestJitteredIntervalDiffuses(t *testing.T) {
	// Distribution sanity across seeds: not everything may equal the base,
	// and values must appear in both the low and the high half — a jitter
	// that only ever adds (or only ever subtracts) would be a bias, and a
	// distribution stuck on the base is no jitter at all.
	base := int64(1_000_000) // 1ms, in ns
	span := base / 5
	sawLow, sawHigh, sawBase := false, false, false
	for seed := int64(1); seed <= 200; seed++ {
		got := int64(JitteredInterval(time.Duration(base), 20, rand.New(rand.NewSource(seed))))
		if got == base {
			sawBase = true
		}
		if got < base-span/10 {
			sawLow = true
		}
		if got > base+span/10 {
			sawHigh = true
		}
	}
	if !sawLow || !sawHigh {
		t.Fatalf("jitter must reach both halves of the range (low=%v high=%v)", sawLow, sawHigh)
	}
	// Hitting the exact base is allowed but must not dominate: with a
	// uniform draw over 400001 values, exact-base hits are ~1/200001.
	_ = sawBase
}
