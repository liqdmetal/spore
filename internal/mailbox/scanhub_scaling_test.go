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
func TestScanHubPollScalingIsFlat(t *testing.T) {
	const window = 200 * time.Millisecond
	const interval = 5 * time.Millisecond

	measure := func(subs int) int {
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
		time.Sleep(window)
		n := fc.pollCount()
		hub.Close()
		return n
	}

	small := measure(1)
	large := measure(50)
	t.Logf("chain polls in %v: 1 subscriber = %d, 50 subscribers = %d", window, small, large)

	// Flat means: 50x the subscribers must NOT mean ~50x the polls. Allow the
	// larger case to be at most 3x the smaller one for timing slack; a
	// per-subscriber design would be ~50x.
	if large > small*3+20 {
		t.Fatalf("poll count scaled with subscribers (1 sub=%d, 50 subs=%d) — the hub is not sharing one watcher", small, large)
	}
}
