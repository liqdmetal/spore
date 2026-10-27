package main

// `spore store sweep` — the outside view of bodies the store itself cannot
// see. The properties pinned here are the ones an operator relies on before
// running a destructive pass on a live hold: a dry run predicts the real one
// exactly, the age guard is honoured, a healthy body is never touched, and a
// mistyped -dir fails instead of quietly creating an empty hold that reports
// all-clear.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/store"
)

// plantRecordless writes a content-addressed body with no companion record —
// the state `Put` cannot produce and `Reap` can never revisit.
func plantRecordless(t *testing.T, dir string, body []byte, age time.Duration) string {
	t.Helper()
	sum := sha256.Sum256(body)
	p := filepath.Join(dir, hex.EncodeToString(sum[:])+".body")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	return p
}

func TestStoreSweepDryRunPredictsAndRemovesNothing(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := plantRecordless(t, dir, []byte("orphaned nine days ago"), 9*24*time.Hour)
	young := plantRecordless(t, dir, []byte("orphaned a minute ago"), time.Minute)
	healthy := []byte("a body with its record")
	cid := sha256.Sum256(healthy)
	if err := ds.Put(cid, healthy, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	plan, err := sweepHold(dir, now, 24*time.Hour, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(plan.Removed) != 1 || len(plan.Retained) != 1 {
		t.Fatalf("dry run = %d due / %d kept, want 1/1", len(plan.Removed), len(plan.Retained))
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("-dry-run removed the old orphan: %v", err)
	}

	res, err := sweepHold(dir, now, 24*time.Hour, false)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].Path != old {
		t.Fatalf("sweep removed %v, want exactly %q", res.Removed, old)
	}
	if len(res.Retained) != 1 || res.Retained[0].Path != young {
		t.Fatalf("sweep kept %v, want exactly %q", res.Retained, young)
	}
	if len(res.Removed) != len(plan.Removed) || res.Bytes != plan.Bytes {
		t.Fatalf("real pass (%d/%d bytes) disagrees with its dry run (%d/%d bytes)",
			len(res.Removed), res.Bytes, len(plan.Removed), plan.Bytes)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old orphan survived the real pass (err=%v)", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatalf("age guard let the young orphan be taken: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, hex.EncodeToString(cid[:])+".body")); err != nil {
		t.Fatalf("a body with a record was touched: %v", err)
	}
}

func TestStoreSweepRefusesAMissingDirectoryInsteadOfCreatingIt(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "typoed-hold")

	if _, err := sweepHold(missing, time.Now(), time.Hour, true); err == nil {
		t.Fatal("a missing hold directory was accepted; a typo must not read as all-clear")
	}
	// NewDiskStore would have created it — the command must not.
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("the sweep created %s (err=%v)", missing, err)
	}
}

func TestStoreSweepReportsACleanHoldAsClean(t *testing.T) {
	dir := t.TempDir()
	ds, err := store.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("normal")
	cid := sha256.Sum256(body)
	if err := ds.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	res, err := sweepHold(dir, time.Now(), 24*time.Hour, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var out bytes.Buffer
	printSweep(&out, dir, time.Now(), 24*time.Hour, true, res)
	if !strings.Contains(out.String(), "no bodies lack a deadline record") {
		t.Fatalf("clean hold output = %q, want the explicit all-clear line", out.String())
	}
	if strings.Contains(out.String(), "would reclaim") {
		t.Fatalf("clean hold printed a reclaim line: %q", out.String())
	}
}

// TestStoreSweepSaysNothingOnAFailureInsteadOfAllClear pins the reporting rule
// that a mistyped -dir exposed: the all-clear line must never be printed for a
// run that never looked at a directory, or a typo reads as a clean hold. Once
// something HAS been seen, the partial report is printed even when the run
// errored, because the operator needs to know what already moved.
func TestStoreSweepSaysNothingOnAFailureInsteadOfAllClear(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	boom := os.ErrNotExist

	var silent bytes.Buffer
	if err := reportSweep(&silent, dir, now, time.Hour, true, store.OrphanSweep{}, boom); err == nil {
		t.Fatal("a failed run reported success")
	}
	if silent.Len() != 0 {
		t.Fatalf("a failed run printed %q; it must not claim anything", silent.String())
	}

	// Partial results still print, then the error is returned for the caller.
	path := plantRecordless(t, dir, []byte("reclaimed before the failure"), 48*time.Hour)
	plan, err := sweepHold(dir, now, time.Hour, true)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var partial bytes.Buffer
	if err := reportSweep(&partial, dir, now, time.Hour, true, plan, boom); err == nil {
		t.Fatal("the error was swallowed")
	}
	if !strings.Contains(partial.String(), "would reclaim") {
		t.Fatalf("partial report was suppressed: %q", partial.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("reporting must not touch the hold: %v", err)
	}
}

// TestStoreSweepOutputNamesEveryBodyAndTheGuard keeps the run legible: an
// operator reclaiming ciphertext should see which body, how big, how old, and
// why the rest were kept — never a bare count.
func TestStoreSweepOutputNamesEveryBodyAndTheGuard(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	plantRecordless(t, dir, []byte("doomed"), 9*24*time.Hour)
	plantRecordless(t, dir, []byte("kept"), time.Minute)

	plan, err := sweepHold(dir, now, 24*time.Hour, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var out bytes.Buffer
	printSweep(&out, dir, now, 24*time.Hour, true, plan)
	got := out.String()

	for _, want := range []string{
		"would reclaim",
		"kept (younger than -min-age 24h0m0s)",
		"2 recordless body(ies)",
		"nothing was removed (-dry-run)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	// Both cids appear in full, so the operator can identify each body.
	for _, body := range [][]byte{[]byte("doomed"), []byte("kept")} {
		sum := sha256.Sum256(body)
		if !strings.Contains(got, hex.EncodeToString(sum[:])) {
			t.Fatalf("output does not name body %q:\n%s", body, got)
		}
	}
}
