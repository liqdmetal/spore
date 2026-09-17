package peerstore

// Regression tests for the periodic reap ticker (AUDIT-SPOREPEER
// recommendation 3): the serve path only composts an expired body when
// someone asks for that exact CID, so bodies nobody ever fetches would
// linger on disk forever on a long-lived node. ReapEvery fixes that with a
// background ticker; these tests pin the composting, the shutdown
// liveness, and the disabled/clamped cadences.

import (
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

func holdBodyFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.body"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// TestReapTickerCompostsExpiredBodiesWithoutAccess: with ReapEvery set, an
// expired body must leave the disk on the ticker's cadence even though NO
// one ever fetched it — the exact gap the on-access-only behavior left.
// Post-reap, Get must report ErrNotFound (bytes gone), not ErrExpired
// (still on disk, refused at read). The deadline is already past at Put so
// the very first tick can act (DiskStore.Reap compares unix SECONDS; a
// future deadline inside the current second would be un-reapable until the
// second rolls over — a property of the store, not the ticker). An
// unexpired companion body must survive every tick.
func TestReapTickerCompostsExpiredBodiesWithoutAccess(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSporePeerStore(SporePeerConfig{Dir: dir, ReapEvery: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	expired := []byte("nobody will ever ask for me by CID")
	expCID := sha256.Sum256(expired)
	if err := s.Put(expCID, expired, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	alive := []byte("not my time yet")
	aliveCID := sha256.Sum256(alive)
	if err := s.Put(aliveCID, alive, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond) // many ticks at 25ms

	if left := holdBodyFiles(t, dir); len(left) != 1 {
		t.Fatalf("after reap: %d .body files on disk, want 1 (the unexpired one): %v", len(left), left)
	}
	if _, err := s.hold.Get(expCID); err != store.ErrNotFound {
		t.Fatalf("post-reap get err = %v, want store.ErrNotFound (bytes gone)", err)
	}
	if _, err := s.hold.Get(aliveCID); err != nil {
		t.Fatalf("unexpired body must survive the ticker: %v", err)
	}
}

// TestReapTickerShutdownIsPrompt: Close must end the ticker promptly (no
// leak that keeps the process or test binary alive), even at an aggressive
// cadence.
func TestReapTickerShutdownIsPrompt(t *testing.T) {
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), ReapEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()
	select {
	case <-done:
		// prompt shutdown — a leaked ticker would hang the wait
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s: reap ticker is not being stopped")
	}

	// Double Close stays safe (stopOnce guards the channel close).
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestReapTickerDisabledAndClamped: the default (0) and a negative value
// both mean on-access-only — nothing may be reaped in the background, and
// the expired body must still be on disk (Get refuses it as ErrExpired).
// Expiry enforcement was always read-time; the ticker only changes WHEN
// bytes leave the disk, never WHETHER they are served.
func TestReapTickerDisabledAndClamped(t *testing.T) {
	for _, every := range []time.Duration{0, -5 * time.Minute} {
		dir := t.TempDir()
		s, err := NewSporePeerStore(SporePeerConfig{Dir: dir, ReapEvery: every})
		if err != nil {
			t.Fatal(err)
		}
		body := []byte("on-access only")
		cid := sha256.Sum256(body)
		if err := s.Put(cid, body, time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // long enough for a misbehaving ticker to fire
		if left := holdBodyFiles(t, dir); len(left) != 1 {
			t.Fatalf("ReapEvery=%v: body reapplied in background, want on-access-only (files left: %d)", every, len(left))
		}
		if _, err := s.hold.Get(cid); err != store.ErrExpired {
			t.Fatalf("ReapEvery=%v: expired get err = %v, want store.ErrExpired", every, err)
		}
		s.Close()
	}
}
