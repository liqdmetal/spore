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
	// burnedCh signals each Burn call so tests await the effect directly.
	// A previous shape busy-polled len(burned) after receiving the delivery —
	// a scheduler-dependent wait that could flake under parallel load.
	burnedCh chan struct{}
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
	f.burned = append(f.burned, burnKey)
	err := f.burnErr
	f.mu.Unlock()
	select {
	case f.burnedCh <- struct{}{}:
	default:
	}
	return err
}

// TestWatchAutoBurnsAfterDelivery: with AutoBurn set, once a message is
// emitted to the caller, Watch must call Burn with that message's BurnKey —
// the "compostable" half of receive. Nothing should require a second pass.
func TestWatchAutoBurnsAfterDelivery(t *testing.T) {
	f := &fakeBurnChain{burnedCh: make(chan struct{}, 1)}
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

	// Burn runs on the watcher goroutine immediately after the emit; the
	// fake signals each call, so await the signal directly instead of
	// busy-polling the slice (which could flake under load).
	select {
	case <-f.burnedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery happened but Watch never called Burn")
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
	f := &fakeBurnChain{burnedCh: make(chan struct{}, 1)}
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
	f := &fakeBurnChain{burnErr: context.DeadlineExceeded, burnedCh: make(chan struct{}, 1)}
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
