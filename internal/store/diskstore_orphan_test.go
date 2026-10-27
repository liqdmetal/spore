package store

// Orphan detection and reclaim. A body with no deadline record is the one
// state Reap cannot reach (it globs *.exp), so these tests pin both halves:
// what counts as an orphan, and that reclaiming one can never take a body
// that is alive, recordless-but-young, or mid-Put.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// writeRecordless plants a body the way an artifact would exist on disk: a
// content-addressed <cid>.body and no companion record at all. Put cannot
// produce this (it writes .exp first, "0" included), which is why the test
// has to write the file itself.
func writeRecordless(t *testing.T, dir string, body []byte, mod time.Time) string {
	t.Helper()
	sum := sha256.Sum256(body)
	p := filepath.Join(dir, hex.EncodeToString(sum[:])+".body")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("plant recordless body: %v", err)
	}
	if err := os.Chtimes(p, mod, mod); err != nil {
		t.Fatalf("stamp mtime: %v", err)
	}
	return p
}

func mustPut(t *testing.T, s *DiskStore, body []byte, deadline time.Time) [32]byte {
	t.Helper()
	cid := sha256.Sum256(body)
	if err := s.Put(cid, body, deadline); err != nil {
		t.Fatalf("put %q: %v", body, err)
	}
	return cid
}

// TestOrphansFindsOnlyRecordlessBodies pins the boundary of the class. Every
// other shape in the directory — a body with a seconds floor, one with the ms
// refinement, one that deliberately never expires, a body with a record
// removed but its refinement left behind, and files that are not store files
// at all — must stay out of the result, because acting on it deletes
// ciphertext.
func TestOrphansFindsOnlyRecordlessBodies(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	mustPut(t, s, []byte("has a floor"), now.Add(time.Hour))
	mustPut(t, s, []byte("has both records"), now.Add(time.Hour))
	mustPut(t, s, []byte("never expires"), time.Time{})

	// A body whose .exp was removed but whose .expms survived: still covered.
	msOnly := []byte("only the refinement survives")
	cid := mustPut(t, s, msOnly, now.Add(time.Hour))
	if err := os.Remove(filepath.Join(dir, hex.EncodeToString(cid[:])+".exp")); err != nil {
		t.Fatal(err)
	}

	orphanPath := writeRecordless(t, dir, []byte("nobody recorded my deadline"), now.Add(-72*time.Hour))

	// Things that merely live in the directory must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README-body-notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "abc.body"), []byte("short name"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := s.Orphans()
	if err != nil {
		t.Fatalf("orphans: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("orphans: got %d (%v), want exactly the recordless body", len(got), got)
	}
	if got[0].Path != orphanPath {
		t.Fatalf("orphan path = %q, want %q", got[0].Path, orphanPath)
	}
	if got[0].Size != int64(len("nobody recorded my deadline")) {
		t.Fatalf("orphan size = %d, want %d", got[0].Size, len("nobody recorded my deadline"))
	}
	if age := got[0].Age(now); age < 71*time.Hour {
		t.Fatalf("orphan age = %v, want >= 71h (mtime is the put-time stand-in)", age)
	}
	if want := sha256.Sum256([]byte("nobody recorded my deadline")); got[0].CID != want {
		t.Fatalf("orphan cid = %x, want %x", got[0].CID, want)
	}
}

// TestSweepOrphansRespectsTheAgeGuard pins the safety property: a recordless
// body younger than the guard keeps its bytes, because its deadline is
// unknowable and it may still be inside its sender's TTL. Only the one past
// the guard is reclaimed, and nothing else in the directory is touched.
func TestSweepOrphansRespectsTheAgeGuard(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	old := writeRecordless(t, dir, []byte("planted nine days ago"), now.Add(-9*24*time.Hour))
	young := writeRecordless(t, dir, []byte("planted a minute ago"), now.Add(-time.Minute))
	live := mustPut(t, s, []byte("alive, with a deadline"), now.Add(time.Hour))

	res, err := s.SweepOrphans(now, 24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].Path != old {
		t.Fatalf("removed = %v, want only %q", res.Removed, old)
	}
	if len(res.Retained) != 1 || res.Retained[0].Path != young {
		t.Fatalf("retained = %v, want only %q", res.Retained, young)
	}
	if want := int64(len("planted nine days ago")); res.Bytes != want {
		t.Fatalf("reclaimed bytes = %d, want %d", res.Bytes, want)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old orphan still on disk (err=%v)", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatalf("young orphan must survive the guard: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, hex.EncodeToString(live[:])+".body")); err != nil {
		t.Fatalf("a body with a deadline must never be swept: %v", err)
	}

	// A second pass with the guard satisfied reclaims the survivor.
	res2, err := s.SweepOrphans(now.Add(25*time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if len(res2.Removed) != 1 || res2.Removed[0].Path != young {
		t.Fatalf("second sweep removed = %v, want %q", res2.Removed, young)
	}
	if _, err := os.Stat(young); !os.IsNotExist(err) {
		t.Fatalf("young orphan survived a sweep that cleared the guard (err=%v)", err)
	}
}

// TestSweepOrphansReclaimsEverythingAtZeroAge is the operator's explicit
// no-guard form: -min-age 0 means "these are artifacts, take them".
func TestSweepOrphansReclaimsEverythingAtZeroAge(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := writeRecordless(t, dir, []byte("one"), now)
	b := writeRecordless(t, dir, []byte("two"), now.Add(-time.Second))

	res, err := s.SweepOrphans(now, 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(res.Removed) != 2 || len(res.Retained) != 0 {
		t.Fatalf("removed=%d retained=%d, want 2/0", len(res.Removed), len(res.Retained))
	}
	for _, p := range []string{a, b} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%q still present (err=%v)", p, err)
		}
	}
	// Nothing left to report, and a clean store stays quiet.
	again, err := s.SweepOrphans(now, 0)
	if err != nil {
		t.Fatalf("idempotent sweep: %v", err)
	}
	if len(again.Removed) != 0 || len(again.Retained) != 0 {
		t.Fatalf("re-sweep of a clean store reported %v / %v", again.Removed, again.Retained)
	}
}

// TestOrphanPlanMatchesTheSweepAndRemovesNothing pins that the dry run is
// truthful: it agrees with the sweep it predicts, and it leaves every byte
// where it found it. An operator deciding to run a destructive pass relies on
// that agreement.
func TestOrphanPlanMatchesTheSweepAndRemovesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	writeRecordless(t, dir, []byte("old one"), now.Add(-9*24*time.Hour))
	writeRecordless(t, dir, []byte("old two"), now.Add(-2*24*time.Hour))
	writeRecordless(t, dir, []byte("young one"), now.Add(-time.Minute))
	mustPut(t, s, []byte("healthy"), now.Add(time.Hour))

	plan, err := s.OrphanPlan(now, 24*time.Hour)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Removed) != 2 || len(plan.Retained) != 1 {
		t.Fatalf("plan = %d due / %d kept, want 2/1", len(plan.Removed), len(plan.Retained))
	}
	// A plan removes nothing.
	left, err := s.Orphans()
	if err != nil {
		t.Fatalf("orphans after plan: %v", err)
	}
	if len(left) != 3 {
		t.Fatalf("plan left %d orphans, want all 3 still present", len(left))
	}

	swept, err := s.SweepOrphans(now, 24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(swept.Removed) != len(plan.Removed) || len(swept.Retained) != len(plan.Retained) || swept.Bytes != plan.Bytes {
		t.Fatalf("sweep %d/%d %d bytes disagrees with plan %d/%d %d bytes",
			len(swept.Removed), len(swept.Retained), swept.Bytes, len(plan.Removed), len(plan.Retained), plan.Bytes)
	}
	for i := range plan.Removed {
		if plan.Removed[i].Path != swept.Removed[i].Path {
			t.Fatalf("plan and sweep disagree at %d: %q vs %q", i, plan.Removed[i].Path, swept.Removed[i].Path)
		}
	}
}

// TestSweepStormNeverTakesAStoredBody guards the property that makes the
// sweep safe to run against a live hold: under a storm of sweeps, a body Put
// reports as stored is still readable, and no healthy write is reclassified
// as an orphan.
//
// It does NOT prove the lock is what saves the write, and it passes without
// it: Put renames records in before the body, so its own body never reads as
// recordless. The interleave the lock exists for is narrower — a RE-send of a
// cid whose records are gone, landing between the sweep's check and its
// removal — and that one cannot be forced cross-platform from a test, because
// re-writing the path collides with a concurrent removal (on Windows: "Access
// is denied"). What this test does hold is the direction of the failure: if a
// sweep ever starts removing bodies it did not classify as recordless, this
// goes red.
func TestSweepStormNeverTakesAStoredBody(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := func(i int) []byte { return []byte{byte(i), byte(i >> 8), 'p', 'u', 't'} }

	const puts = 250
	var mu sync.Mutex
	var stored [][32]byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < puts; i++ {
			cid := sha256.Sum256(body(i))
			// No error path here on purpose: a failure is a different bug and
			// surfaces in the other tests. The assertion below covers what
			// Put reported as stored.
			if err := s.Put(cid, body(i), time.Now().Add(time.Hour)); err != nil {
				continue
			}
			mu.Lock()
			stored = append(stored, cid)
			mu.Unlock()
		}
	}()

	// Sweep throughout the writer's run, with no age guard so every orphan the
	// sweep believes it sees is fair game. Paced: `go test ./...` runs
	// packages in parallel, and a loop pegging a core for seconds is the kind
	// of load that makes unrelated timing assertions flake.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-done:
			goto finished
		default:
			if _, err := s.SweepOrphans(time.Now(), 0); err != nil {
				t.Fatalf("sweep: %v", err)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}
finished:
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(stored) == 0 {
		t.Fatal("no puts succeeded; test proves nothing")
	}
	for _, cid := range stored {
		got, err := s.Get(cid)
		if err != nil {
			t.Fatalf("a body Put reported as stored is gone (%x): %v — the sweep took a live write", cid, err)
		}
		if len(got) == 0 {
			t.Fatalf("body %x came back empty", cid)
		}
	}
	// And the sweep must not have invented orphans out of healthy writes.
	if res, err := s.Orphans(); err != nil {
		t.Fatalf("orphans after the race: %v", err)
	} else if len(res) != 0 {
		t.Fatalf("healthy puts produced %d orphans", len(res))
	}
}
