package ratchetwire

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// setCountFlushInterval overrides the count throttle for one test.
func setCountFlushInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := countFlushInterval
	countFlushInterval = d
	t.Cleanup(func() { countFlushInterval = old })
}

// A burst of rejections inside the throttle window costs one file write. The
// rest stay in memory until Flush, and then they are all on disk.
func TestRejectionCountBurstIsThrottled(t *testing.T) {
	setCountFlushInterval(t, time.Hour)
	path := filepath.Join(t.TempDir(), "opk-pool.json")
	pool, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("bad first message")

	// The first rejection is written at once.
	pool.fail(StageAuthenticate, 9, cause)
	if got := onDisk(t, path, StageAuthenticate); got != 1 {
		t.Fatalf("first rejection on disk=%d, want 1", got)
	}
	// Later rejections in the window are not written.
	pool.fail(StageAuthenticate, 9, cause)
	pool.fail(StageAuthenticate, 9, cause)
	if got := onDisk(t, path, StageAuthenticate); got != 1 {
		t.Fatalf("burst wrote through the throttle: on disk=%d, want 1", got)
	}
	if got := pool.RejectedCounts()[StageAuthenticate]; got != 3 {
		t.Fatalf("in-memory count=%d, want 3", got)
	}

	if err := pool.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := onDisk(t, path, StageAuthenticate); got != 3 {
		t.Fatalf("after Flush on disk=%d, want 3", got)
	}
}

// A count held back by the throttle is written by the trailing timer without
// any caller having to flush.
func TestRejectionCountTrailingWriteLands(t *testing.T) {
	setCountFlushInterval(t, 20*time.Millisecond)
	path := filepath.Join(t.TempDir(), "opk-pool.json")
	pool, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("bad first message")
	pool.fail(StageLookup, 9, cause)
	pool.fail(StageLookup, 9, cause)
	pool.fail(StageLookup, 9, cause)

	deadline := time.Now().Add(5 * time.Second)
	for onDisk(t, path, StageLookup) != 3 {
		if time.Now().After(deadline) {
			t.Fatalf("trailing write never reached 3 on disk (have %d)", onDisk(t, path, StageLookup))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A key write persists the pending count with it, so a removal never leaves
// the file behind the in-memory counts.
func TestKeyWriteCarriesPendingCount(t *testing.T) {
	setCountFlushInterval(t, time.Hour)
	path := filepath.Join(t.TempDir(), "opk-pool.json")
	pool, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], filled(5))
	if err := pool.Add(4, key); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("bad first message")
	// Add just wrote the file, so both rejections fall inside the window.
	pool.fail(StageValidate, 4, cause)
	pool.fail(StageValidate, 4, cause)
	if got := onDisk(t, path, StageValidate); got != 0 {
		t.Fatalf("throttled count on disk=%d, want 0", got)
	}
	if _, err := pool.Take(4); err != nil {
		t.Fatal(err)
	}
	if got := onDisk(t, path, StageValidate); got != 2 {
		t.Fatalf("Take did not persist the pending count: on disk=%d, want 2", got)
	}
	if err := pool.Flush(); err != nil {
		t.Fatalf("Flush after Take: %v", err)
	}
}

// A nil pool has no pending counts, so Flush on it is a safe no-op. Commands
// without an OPK pool can call Flush on exit unconditionally.
func TestFlushOnNilPoolIsNoOp(t *testing.T) {
	var pool *OPKPool
	if err := pool.Flush(); err != nil {
		t.Fatalf("Flush on nil pool: %v", err)
	}
}

func onDisk(t *testing.T, path, stage string) uint64 {
	t.Helper()
	counts, err := ReadOnlyPrekeyRejections(path)
	if err != nil {
		t.Fatal(err)
	}
	return counts[stage]
}
