package store

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestPutConcurrentWithReapNeverOrphansABody pins the invariant that makes
// the composter safe: a body may never end up on disk without its deadline
// records.
//
// WHY THIS IS NOT JUST A THEORY. Put writes the deadline records BEFORE the
// body (deliberate crash ordering: a crash between the two can only leave a
// dangling .exp, which Get reports as ErrNotFound and Reap cleans). Reap
// does the opposite — it removes the body and then the records — and the two
// sequences can interleave. When a reap pass deletes the records in the
// window after Put has written them but before the body is renamed into
// place, the body lands with NO .exp at all. deadlineFor then reads that as
// "no deadline = never expires", so Reap can never see it again: the cipher
// is retained forever and the store's whole compost guarantee is silently
// lost. Observed in the wild as a peerstore test flake — one reap pass left
// 2 bodies instead of 1, and the survivor had no .exp or .expms beside it.
//
// The ticker makes this rare (a 25 ms cadence against a window of a few
// renames); this test makes it routine by racing a tight reap loop against
// the Puts, so a regression is caught here instead of as an unexplained
// intermittent failure. Every deadline below is in the past, so after the
// race a final pass must be able to remove EVERYTHING: any surviving body is
// unreachable by construction, and any surviving record is a leak.
func TestPutConcurrentWithReapNeverOrphansABody(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	const bodies = 300
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.Reap(time.Now())
		}
	}()

	for i := 0; i < bodies; i++ {
		body := []byte(fmt.Sprintf("concurrent put/reap body %d", i))
		cid := sha256.Sum256(body)
		if err := s.Put(cid, body, time.Now().Add(-time.Second)); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("put %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	// Every deadline was already past, so one final pass must clear the
	// store completely.
	s.Reap(time.Now())
	orphans, err := filepath.Glob(filepath.Join(dir, "*.body"))
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) > 0 {
		for _, b := range orphans {
			stem := b[:len(b)-len(".body")]
			if _, err := os.Stat(stem + ".exp"); err != nil {
				t.Errorf("orphaned body (no .exp record, so it can never be reaped): %s", filepath.Base(b))
			} else {
				t.Errorf("body survived a reap pass although its deadline had passed: %s", filepath.Base(b))
			}
		}
		t.Fatalf("%d of %d bodies survived a final reap pass: Put and Reap interleaved and broke the deadline record", len(orphans), bodies)
	}
	recs, err := filepath.Glob(filepath.Join(dir, "*.exp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("%d .exp records left behind after every body was reaped", len(recs))
	}
}
