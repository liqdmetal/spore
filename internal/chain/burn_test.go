package chain

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeBurnChain is a minimal Chain+Burner for testing Watch's compost
// behavior without a real network. It lists one Incoming exactly once (like
// a real mailbox contract before it's burned) and records Burn calls.
type fakeBurnChain struct {
	mu      sync.Mutex
	served  bool
	burned  []string
	burnErr error
}

func (f *fakeBurnChain) Name() string                                { return "fake" }
func (f *fakeBurnChain) Address(ctx context.Context) (string, error) { return "self", nil }
func (f *fakeBurnChain) Height(ctx context.Context) (uint64, error)  { return 1, nil }
func (f *fakeBurnChain) PostPayload(ctx context.Context, to string, p Payload, amount uint64) (PostResult, error) {
	return PostResult{}, nil
}
func (f *fakeBurnChain) ListIncoming(ctx context.Context, minHeight uint64) ([]Incoming, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.served {
		return nil, nil
	}
	f.served = true
	return []Incoming{{TxID: "tx1", Payload: Payload("hello"), BurnKey: "42"}}, nil
}
func (f *fakeBurnChain) Burn(ctx context.Context, burnKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.burned = append(f.burned, burnKey)
	return f.burnErr
}

// TestWatchAutoBurnsAfterDelivery: with AutoBurn set, once a message is
// emitted to the caller, Watch must call Burn with that message's BurnKey —
// the "compostable" half of receive. Nothing should require a second pass.
func TestWatchAutoBurnsAfterDelivery(t *testing.T) {
	f := &fakeBurnChain{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, errc := Watch(ctx, f, WatchOpts{Interval: 5 * time.Millisecond, AutoBurn: true})

	select {
	case inc, ok := <-out:
		if !ok {
			t.Fatal("channel closed before delivering the message")
		}
		if inc.TxID != "tx1" {
			t.Fatalf("got txid %q, want tx1", inc.TxID)
		}
	case err := <-errc:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}

	// Burn happens synchronously in the same select branch as the emit, but
	// give the goroutine a moment for the assignment to be visible.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.burned)
		f.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.burned) != 1 || f.burned[0] != "42" {
		t.Fatalf("burned = %v, want [\"42\"]", f.burned)
	}
}

// TestWatchNoAutoBurnLeavesMessage: with AutoBurn false (the default off
// switch for anyone who wants persistent chain history), Burn must never be
// called.
func TestWatchNoAutoBurnLeavesMessage(t *testing.T) {
	f := &fakeBurnChain{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, errc := Watch(ctx, f, WatchOpts{Interval: 5 * time.Millisecond, AutoBurn: false})

	select {
	case _, ok := <-out:
		if !ok {
			t.Fatal("channel closed before delivering the message")
		}
	case err := <-errc:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}

	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.burned) != 0 {
		t.Fatalf("burned = %v, want none (AutoBurn=false)", f.burned)
	}
}

// TestWatchBurnFailureDoesNotBlockDelivery: a broken/unreachable burn must
// never be treated as a delivery failure — the message was already handed
// to the caller; a failed compost just means the scrap lingers.
func TestWatchBurnFailureDoesNotBlockDelivery(t *testing.T) {
	f := &fakeBurnChain{burnErr: context.DeadlineExceeded}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, errc := Watch(ctx, f, WatchOpts{Interval: 5 * time.Millisecond, AutoBurn: true})

	select {
	case _, ok := <-out:
		if !ok {
			t.Fatal("channel closed before delivering the message")
		}
	case err := <-errc:
		t.Fatalf("unexpected error surfaced from a failed burn: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}
}
