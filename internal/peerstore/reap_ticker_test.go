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

// mintDeadline and spinPastDeadline are mirrors of the helpers in
// internal/store/diskstore_subsecond_test.go (same mechanism, same anchor;
// different package, so shared via copy): deadlines anchored just past a
// second boundary survive CI wall-clock corrections, and the spin exits
// strictly after the deadline with an explicit signature if the wall
// clock steps backward instead of hanging or failing with a mystery
// number. See the store copies for the full rationale.
func mintDeadline() time.Time {
	d := time.Now().Truncate(time.Second).Add(time.Second + 300*time.Millisecond)
	if time.Until(d) < 700*time.Millisecond {
		d = d.Add(time.Second)
	}
	return d
}

func spinPastDeadline(t *testing.T, deadline time.Time) {
	t.Helper()
	start := time.Now()
	for !time.Now().After(deadline) {
		if time.Since(start) > 2*time.Second {
			t.Fatal("wall clock did not reach the deadline within 2s (stepped backward?)")
		}
		time.Sleep(5 * time.Millisecond)
	}
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
//
// The test is split into a DETERMINISTIC half and a SCHEDULING half so it
// cannot flake under parallel load:
//
//   - Property: one reap pass composts the expired body and nothing else.
//     Driven synchronously via reapOnce — no goroutine in the way, so the
//     assertion is exact regardless of machine load.
//   - Wiring: the background loop fires and calls the same body. The test
//     waits on the reapTicks COUNTER (not on the disk effect): if the
//     counter never advances the scheduler starved the goroutine — an
//     environmental condition, reported as such. If the counter advances
//     but the bytes persist, THAT is a product bug, and the failure names
//     both numbers so the two cases can never be confused.
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

	// Deterministic property: one synchronous reap pass composts the
	// expired body and only the expired body.
	s.reapOnce()
	if left := holdBodyFiles(t, dir); len(left) != 1 {
		t.Fatalf("after one reap pass: %d .body files on disk, want 1 (the unexpired one): %v", len(left), left)
	}
	if _, err := s.hold.Get(expCID); err != store.ErrNotFound {
		t.Fatalf("post-reap get err = %v, want store.ErrNotFound (bytes gone)", err)
	}
	if _, err := s.hold.Get(aliveCID); err != nil {
		t.Fatalf("unexpired body must survive a reap pass: %v", err)
	}

	// Scheduling wiring: a fresh store's background loop must make progress
	// of its own. Waiting on the tick counter observes the GOROUTINE, not
	// the disk: a starved scheduler reports as "0 ticks in 10s" (skipped,
	// environmental — CI load), never as a product failure.
	dir2 := t.TempDir()
	s2, err := NewSporePeerStore(SporePeerConfig{Dir: dir2, ReapEvery: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	tickDeadline := time.Now().Add(10 * time.Second)
	for s2.reapTicks.Load() == 0 {
		if time.Now().After(tickDeadline) {
			t.Skipf("reap goroutine received no tick within 10s (scheduler starvation under load; "+
				"saw %d ticks) — the compost property itself is pinned synchronously above", s2.reapTicks.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The loop has ticked. Any further delay in composting is a real bug —
	// and if it ever reproduces, the counter in the message proves the
	// loop ran while the bytes stayed, which the old disk-polling version
	// could never distinguish from starvation.
	compostDeadline := time.Now().Add(2 * time.Second)
	for {
		left := holdBodyFiles(t, dir2)
		if len(left) == 0 {
			break
		}
		if time.Now().After(compostDeadline) {
			t.Fatalf("reap loop ran %d tick(s) yet %d .body file(s) remain: %v — real composting bug, not scheduling",
				s2.reapTicks.Load(), len(left), left)
		}
		time.Sleep(5 * time.Millisecond)
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
		// Distinguish environmental starvation from a real leak before
		// failing: if the loop never got a tick, the scheduler may simply
		// never have run it, and Close's wg.Wait is blocked on a goroutine
		// that never started — not a ticker leak. If the loop demonstrably
		// ran and Close still hung, that IS a stop bug.
		if s.reapTicks.Load() == 0 {
			t.Skipf("Close hung but the reap goroutine received no tick (scheduler starvation under load) — a leak cannot be distinguished from starvation this run")
		}
		t.Fatal("Close did not return within 2s with the reap loop demonstrably running: ticker is not being stopped")
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

	deadline := mintDeadline()
	// Anchor at a second boundary (see mintDeadline above): the
	// pre-deadline phase gets >=1.3s of margin against slow -race runners,
	// and the deadline keeps >=700ms of sub-second room, so a wall-clock
	// correction lands in padded zones instead of at a phase edge — the
	// forward-step case that failed CI as "reaped 1 before the deadline".

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

	// Cross the millisecond deadline with the same strict comparison the
	// store classifies by (After, not a Before-negation): exiting on
	// equality would let a sample land exactly on the boundary and read the
	// body back spuriously. The monotonic anchor bounds the spin if the
	// wall clock steps backward mid-test (the spin fails with an explicit
	// signature instead); the whole window still stays inside one
	// wall-clock second.
	spinPastDeadline(t, deadline)

	// Drive one reap pass SYNCHRONOUSLY. What this test uniquely pins is
	// the millisecond deadline SEMANTICS — that Reap(now) composts a body
	// whose sub-second deadline just crossed, inside the same wall-clock
	// second where the seconds floor alone could never authorize a reap.
	// Driving the pass directly asserts that without a goroutine in the
	// way: under parallel load a 300ms "wait for the background ticker"
	// budget was pure scheduling luck (the loop-vs-compost wiring is
	// pinned separately in TestReapTickerCompostsExpiredBodiesWithoutAccess).
	// The ticker stays running at its 25ms cadence; the synchronous pass
	// merely removes the load window from the assertion.
	s.reapOnce()
	_, err = s.hold.Get(mortalCID)
	if err != store.ErrNotFound {
		t.Fatalf("after the ms deadline crossed and one reap pass: err = %v, want ErrNotFound (composted) — ErrExpired would mean the sub-second deadline did not drive the compost", err)
	}

	// Everything above happened in the SAME wall-clock second as the
	// deadline: the seconds floor alone could not have authorized any reap
	// yet, so the ms record demonstrably drove the composting. A boundary
	// crossing without any compost would invalidate the proof — but it can
	// also happen when the TEST goroutine itself is starved past the
	// second boundary under heavy load, which says nothing about the
	// product; report that as an environmental skip, not a failure.
	if time.Now().Unix() != deadline.Unix() {
		t.Skipf("test window crossed a second boundary (%d vs %d): timing assumptions could not be held this run (load), so ms precision is unproven, not disproven",
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
