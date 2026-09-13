package chain

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// countingChain is a Chain whose ListIncoming returns one message on the
// first call and nothing afterwards, counting every poll. It exists to prove
// the ADAPTIVE cadence: after the idle threshold, polls must slow to
// IdleInterval instead of hammering at Interval.
type countingChain struct {
	calls atomic.Int64
}

func (c *countingChain) Name() string                                { return "count" }
func (c *countingChain) Address(ctx context.Context) (string, error) { return "x", nil }
func (c *countingChain) Height(ctx context.Context) (uint64, error)  { return 0, nil }
func (c *countingChain) PostPayload(ctx context.Context, recipientAddr string, p Payload, amountHint uint64) (PostResult, error) {
	return PostResult{}, nil
}
func (c *countingChain) ListIncoming(ctx context.Context, cursor uint64) ([]Incoming, error) {
	n := c.calls.Add(1)
	if n == 1 {
		return []Incoming{{TxID: "first", TopoHeight: 10, ScanHeight: 10}}, nil
	}
	return nil, nil
}

// TestWatchAdaptiveBackoff: fixed 20ms cadence would fire ~40 polls in
// 400ms of runtime; adaptive (idle-after 40ms → idle 300ms) must fire far
// fewer once the single message is delivered and silence sets in.
func TestWatchAdaptiveBackoff(t *testing.T) {
	c := &countingChain{}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	in, errc := Watch(ctx, c, WatchOpts{
		MinHeight:    0,
		Interval:     20 * time.Millisecond,
		IdleInterval: 300 * time.Millisecond,
		IdleAfter:    40 * time.Millisecond,
	})
	got := 0
	for {
		select {
		case _, ok := <-in:
			if !ok {
				goto done
			}
			got++
		case err := <-errc:
			if err != nil {
				t.Fatalf("watch error: %v", err)
			}
		case <-ctx.Done():
			goto done
		}
	}
done:
	if got != 1 {
		t.Fatalf("delivered %d messages, want 1", got)
	}
	total := c.calls.Load()
	if total >= 15 {
		t.Fatalf("adaptive backoff failed: %d polls in 400ms (fixed cadence would be ~20; wanted ~4-6)", total)
	}
	t.Logf("polls in 400ms with adaptation: %d (fixed would be ~20)", total)
}

// TestWatchFixedCadenceUnchanged: zero Idle* fields must keep the old
// behavior — roughly Interval-paced polls, no backoff.
func TestWatchFixedCadenceUnchanged(t *testing.T) {
	c := &countingChain{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	in, _ := Watch(ctx, c, WatchOpts{Interval: 20 * time.Millisecond})
	for {
		select {
		case _, ok := <-in:
			if !ok {
				goto done
			}
		case <-ctx.Done():
			goto done
		}
	}
done:
	total := c.calls.Load()
	if total < 5 {
		t.Fatalf("fixed cadence regressed: only %d polls in 200ms", total)
	}
	t.Logf("polls in 200ms with fixed cadence: %d", total)
}
