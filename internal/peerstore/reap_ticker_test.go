package peerstore

// Regression tests for the periodic reap ticker (AUDIT-SPOREPEER
// recommendation 3): the serve path only composts an expired body when
// someone asks for that exact CID, so bodies nobody ever fetches would
// linger on disk forever on a long-lived node. ReapEvery fixes that with a
// background ticker; these tests pin the composting, the shutdown
// liveness, and the disabled/clamped cadences.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
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

// TestReapTickerCompostsOnTheMillisecondDeadline combines the two compost
// mechanisms end to end: the ReapEvery ticker driven by a body whose
// deadline carries a SUB-SECOND component (.expms record, written by the
// real Put path). The deadline is anchored at next-second-boundary + 300ms,
// so its sub-second part is always nonzero and the old seconds-floor logic
// alone could never authorize a reap inside the test window — every
// assertion below genuinely distinguishes millisecond precision from the
// floor. If this test ever flakes, the "same wall-clock second" guard will
// say so explicitly instead of failing mysteriously.
func TestReapTickerCompostsOnTheMillisecondDeadline(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSporePeerStore(SporePeerConfig{Dir: dir, Listen: "127.0.0.1:0", ReapEvery: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.LocalAddr()

	deadline := time.Now().Truncate(time.Second).Add(time.Second + 300*time.Millisecond)
	// The seconds-floor read path refuses anything after the deadline's
	// second boundary, so the whole pre-deadline phase (two Puts, the .expms
	// stat, two wire fetches) must finish inside the anchor second. On a
	// loaded -race runner that setup can outlive a late-anchored window and
	// the first fetch would misreport "expired" (seen once on CI). When less
	// than 700ms of the window remains, use the NEXT second's boundary:
	// ≥1.3s of margin, same millisecond-precision assertions.
	if time.Until(deadline) < 700*time.Millisecond {
		deadline = deadline.Add(time.Second)
	}

	alive := []byte("ticker must never touch me (unexpired)")
	aliveCID := sha256.Sum256(alive)
	mortal := []byte("composted mid-second by the ticker")
	mortalCID := sha256.Sum256(mortal)
	if err := s.Put(aliveCID, alive, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(mortalCID, mortal, deadline); err != nil {
		t.Fatal(err)
	}

	// The real Put path wrote the ms refinement the ticker acts on, at the
	// documented §7 hold path.
	msPath := filepath.Join(dir, hex.EncodeToString(mortalCID[:])+".expms")
	if _, err := os.Stat(msPath); err != nil {
		t.Fatalf("Put did not write the .expms refinement: %v", err)
	}

	// Before the deadline the body is served over the wire byte-for-byte,
	// and the unexpired companion must never be disturbed.
	got, err := Fetch(context.Background(), addr, mortalCID)
	if err != nil {
		t.Fatalf("pre-deadline fetch: %v", err)
	}
	if !bytes.Equal(got, mortal) {
		t.Fatal("pre-deadline body mismatch")
	}
	if _, err := Fetch(context.Background(), addr, aliveCID); err != nil {
		t.Fatalf("unexpired body disturbed before its time: %v", err)
	}

	// Cross the millisecond deadline (5ms spin — the whole test window stays
	// inside one wall-clock second).
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// The ticker must compost within a few ticks. While the bytes are still
	// on disk the read path classifies them expired (410 semantics); the
	// moment the ticker has acted, the SAME cid reads as not-found (404).
	// Under seconds-floor logic alone neither the read-refusal-then-gone
	// flip NOR the reap itself could happen before the next boundary.
	composted := false
	budget := time.Now().Add(300 * time.Millisecond)
	for !composted {
		_, err := s.hold.Get(mortalCID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			composted = true
		case errors.Is(err, store.ErrExpired):
			// still on disk, read-refused: correct interim state
		case err == nil:
			t.Fatal("body read back after its millisecond deadline")
		default:
			t.Fatalf("hold get: %v", err)
		}
		if composted {
			break
		}
		if time.Now().After(budget) {
			t.Fatal("ticker did not compost within 300ms of the ms deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Everything above happened in the SAME wall-clock second as the
	// deadline: the seconds floor alone could not have authorized any reap
	// yet, so the ms record demonstrably drove the composting.
	if time.Now().Unix() != deadline.Unix() {
		t.Fatalf("test window crossed a second boundary (%d vs %d): timing assumptions broken",
			time.Now().Unix(), deadline.Unix())
	}

	// Over the wire the composted body is now definitively 404 — never
	// served again, never reshaped — and the unexpired companion still
	// serves byte-for-byte after all of it.
	if _, err := Fetch(context.Background(), addr, mortalCID); err != store.ErrNotFound {
		t.Fatalf("post-compost fetch err = %v, want ErrNotFound (404)", err)
	}
	gotAlive, err := Fetch(context.Background(), addr, aliveCID)
	if err != nil || !bytes.Equal(gotAlive, alive) {
		t.Fatalf("unexpired body after the whole sequence: %q, %v", gotAlive, err)
	}
}
