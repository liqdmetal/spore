package continuity

import (
	"errors"
	"testing"
)

func TestWatchStateBindsObserverAndExactVaultEpoch(t *testing.T) {
	v, _, _ := testChainAnchor(t)
	observerPriv, observerPub, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewWatchState(v, observerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if state.ObserverPub != fmtHex(observerPub) {
		t.Fatalf("observer key mismatch: got %s want %s", state.ObserverPub, fmtHex(observerPub))
	}
	if err := state.VerifyForVault(v); err != nil {
		t.Fatal(err)
	}
	now := v.Checkins[len(v.Checkins)-1].Deadline + 1
	notice, err := Observe(v, observerPriv, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkNotificationQueued(observerPriv, notice, now); err != nil {
		t.Fatal(err)
	}
	if !state.NotificationQueued {
		t.Fatal("notification was not marked queued")
	}
	if err := state.VerifyForVault(v); err != nil {
		t.Fatal(err)
	}
	stale := *state
	stale.Deadline++
	if err := stale.VerifyForVault(v); !errors.Is(err, ErrInvalidWatchState) {
		t.Fatalf("stale checkpoint accepted: %v", err)
	}
}

func TestWatchStateRejectsWrongObserverAndTamper(t *testing.T) {
	v, _, _ := testChainAnchor(t)
	observerPriv, _, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongPriv, _, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewWatchState(v, observerPriv)
	if err != nil {
		t.Fatal(err)
	}
	now := v.Checkins[len(v.Checkins)-1].Deadline + 1
	notice, err := Observe(v, observerPriv, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.MarkNotificationQueued(wrongPriv, notice, now); !errors.Is(err, ErrInvalidWatchState) {
		t.Fatalf("wrong observer accepted: %v", err)
	}
	state.NotificationQueued = true
	if err := state.VerifyForVault(v); !errors.Is(err, ErrInvalidWatchState) {
		t.Fatalf("tampered checkpoint accepted: %v", err)
	}
}
