package peerstore

// The operator contract for ReapStats: `spore serve` prints this snapshot on
// a heartbeat and at shutdown, so the counters' semantics ARE the operator's
// view of the background reaper. Pinned here:
//
//   - Passes advances on every completed pass — even when nothing was
//     removed. A FROZEN pass count is the dead-reaper signal; an
//     alive-but-idle reaper must never look dead.
//   - Removed/LastRemoved describe only what the REAPER composted (on-access
//     reaping in Get/Put is deliberately invisible here — that accounting
//     would make the background reaper look alive when it is not).
//   - Every reports the configured cadence, or 0 when background reaping is
//     disabled (also a live state operators must be able to recognize as
//     "no loop", not "dead loop").

import (
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

func TestReapStatsOperatorContract(t *testing.T) {
	// NO background loop: this test drives passes synchronously via reapOnce
	// and asserts EXACT counter values. With a live ticker running, a
	// background pass could land between two statements and inflate the
	// count — the exact flake class the outbox retry tests eliminated.
	// The cadence field is pinned separately below.
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	st := s.ReapStats()
	if st.Passes != 0 || st.Removed != 0 || !st.LastPass.IsZero() || st.LastRemoved != 0 {
		t.Fatalf("fresh store stats = %+v, want all-zero with no last pass", st)
	}

	// An expired body and a live one: one synchronous pass must show the
	// removal in exactly one counter shape — Passes +1, Removed +1,
	// LastRemoved 1, LastPass set.
	expired := []byte("operator-visible composting")
	expCID := sha256.Sum256(expired)
	if err := s.Put(expCID, expired, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	alive := []byte("stays put")
	aliveCID := sha256.Sum256(alive)
	if err := s.Put(aliveCID, alive, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	s.reapOnce()
	st = s.ReapStats()
	if st.Passes != 1 {
		t.Fatalf("Passes = %d after one pass, want 1", st.Passes)
	}
	if st.Removed != 1 || st.LastRemoved != 1 {
		t.Fatalf("Removed/LastRemoved = %d/%d after composting one body, want 1/1", st.Removed, st.LastRemoved)
	}
	if st.LastPass.IsZero() {
		t.Fatal("LastPass not set after a completed pass")
	}

	// An idle pass advances Passes and touches LastPass but must NOT
	// inflate the removal accounting — alive-but-idle looks alive, and
	// alive-and-working reports honest totals.
	before := s.ReapStats()
	s.reapOnce()
	st = s.ReapStats()
	if st.Passes != before.Passes+1 {
		t.Fatalf("Passes = %d after an idle pass, want %d (a frozen pass count is the dead-reaper signal, so idle passes MUST count)", st.Passes, before.Passes+1)
	}
	if st.Removed != before.Removed {
		t.Fatalf("Removed = %d after an idle pass, want unchanged %d", st.Removed, before.Removed)
	}
	if st.LastRemoved != 0 {
		t.Fatalf("LastRemoved = %d after an idle pass, want 0", st.LastRemoved)
	}
	// LastPass must reflect the latest pass, but consecutive passes can land
	// inside one wall-clock tick (Windows granularity ~0.5ms): the honest
	// contract is non-decreasing, with Passes as the completion signal.
	if st.LastPass.Before(before.LastPass) {
		t.Fatalf("LastPass went backward across a pass (%v -> %v)", before.LastPass, st.LastPass)
	}

	// The unexpired body is untouched by all of this accounting.
	if _, err := s.hold.Get(aliveCID); err != nil {
		t.Fatalf("unexpired body must survive reap passes: %v", err)
	}
}

// TestReapStatsCadenceReported pins that the snapshot surfaces the
// configured cadence — an immutable config field, so no timing dependency.
func TestReapStatsCadenceReported(t *testing.T) {
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), ReapEvery: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if st := s.ReapStats(); st.Every != 25*time.Millisecond {
		t.Fatalf("Every = %s, want the configured cadence", st.Every)
	}
}

func TestReapStatsDisabledReaperReportsNoLoop(t *testing.T) {
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	st := s.ReapStats()
	if st.Every != 0 {
		t.Fatalf("Every = %s with no ReapEvery configured, want 0 (operators must see 'no loop', not 'dead loop')", st.Every)
	}
	// A synchronous Reap via the Store seam is on-access behavior: it must
	// not touch the reaper's accounting.
	cid := sha256.Sum256([]byte("on-access reap stays out of reaper stats"))
	if err := s.Put(cid, []byte("body"), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if s.Reap(time.Now()) != 1 {
		t.Fatal("expected the on-access reap to remove the expired body")
	}
	if st := s.ReapStats(); st.Passes != 0 || st.Removed != 0 {
		t.Fatalf("on-access reap leaked into reaper stats: %+v", st)
	}
}

// TestReapStatsConcurrentSafe pins the snapshot's race-freedom: the reaper
// goroutine writes the counters while readers snapshot them.
func TestReapStatsConcurrentSafe(t *testing.T) {
	s, err := NewSporePeerStore(SporePeerConfig{Dir: t.TempDir(), ReapEvery: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_ = s.ReapStats()
			}
		}
	}()
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		s.reapOnce()
	}
	close(done)
	wg.Wait()
}
