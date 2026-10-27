package mailbox

import (
	"context"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

// TestScanHubPollScalingIsFlat measures the actual RPC load as subscriber
// count grows. This is the number that decides whether one Hetzner box can
// host 10k mailboxes: with one watcher per mailbox, chain RPC load grows
// LINEARLY with users and dies first. With the hub it must stay FLAT.
//
// It logs the measurement rather than asserting a tight bound, because CI
// timing varies; the hard assertion lives in
// TestScanHubOnePollerForManySubscribers.
//
// Two measurement rules, both of which this test used to get wrong:
//
//   - Count only the DELTA inside the window. pollCount() is cumulative from
//     the fake's creation, so the watcher's polls during setup — up to 50
//     `Open(t.TempDir())` calls, seconds of wall time on a loaded box — were
//     being attributed to the 200ms window. That is what once produced "50
//     subscribers = 129 polls": ~85 of them happened before the window opened.
//   - Normalise by the wall time actually elapsed. hubChain.ListIncoming
//     blocks up to 20ms per call, so polls accrue at ~one per 20ms of real
//     time; a stretched sleep inflates the raw count for one shared watcher.
//
// Neither is slack. Read raw, a single shared watcher looked like it scaled
// with subscribers — the one thing this test must not get wrong. A genuinely
// per-subscriber design still lands ~50x the rate against either measure.
func TestScanHubPollScalingIsFlat(t *testing.T) {
	const window = 200 * time.Millisecond
	const interval = 5 * time.Millisecond

	measure := func(subs int) (int, time.Duration) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fc := newHubChain()
		hub := NewScanHub(ctx, fc, chain.WatchOpts{Interval: interval})
		for i := 0; i < subs; i++ {
			m, err := Open(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			hub.Subscribe(ctx, m, canonicalCodec(), nil, nil, make(chan error, 4), false, 4)
		}
		// Baseline after setup: only polls inside the window count.
		baseline := fc.pollCount()
		start := time.Now()
		time.Sleep(window)
		elapsed := time.Since(start)
		n := fc.pollCount() - baseline
		hub.Close()
		return n, elapsed
	}

	// perWindow rescales a count measured over elapsed to the nominal window.
	perWindow := func(n int, elapsed time.Duration) float64 {
		return float64(n) * float64(window) / float64(elapsed)
	}

	smallN, smallEl := measure(1)
	largeN, largeEl := measure(50)
	small, large := perWindow(smallN, smallEl), perWindow(largeN, largeEl)
	t.Logf("chain polls per %v: 1 subscriber = %.1f (%d in %v), 50 subscribers = %.1f (%d in %v)",
		window, small, smallN, smallEl.Round(time.Millisecond), large, largeN, largeEl.Round(time.Millisecond))
	if smallN == 0 && largeN == 0 {
		t.Fatal("no polls observed in either window; the measurement is not running")
	}

	// Flat means: 50x the subscribers must NOT mean ~50x the polls. Allow the
	// larger case to be at most 3x the smaller one for timing slack; a
	// per-subscriber design would be ~50x.
	if large > small*3+20 {
		t.Fatalf("poll rate scaled with subscribers (1 sub=%.1f, 50 subs=%.1f per %v; raw %d in %v and %d in %v) — the hub is not sharing one watcher",
			small, large, window, smallN, smallEl.Round(time.Millisecond), largeN, largeEl.Round(time.Millisecond))
	}
}
