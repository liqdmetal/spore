package ratchetwire

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// If the rejection count cannot be written, the rejection still stands and is
// still counted in memory, and the returned error says the count was lost.
func TestRejectionCountWriteFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	// A regular file where the pool directory should be makes every write fail.
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := NewOPKPool()
	pool.path = filepath.Join(blocker, "opk-pool.json")

	err := pool.fail(StageAuthenticate, 9, errors.New("bad first message"))
	var pre *PrekeyRejectedError
	if !errors.As(err, &pre) {
		t.Fatalf("not a PrekeyRejectedError: %v", err)
	}
	if pre.CountErr == nil {
		t.Fatal("count write failure not recorded on the error")
	}
	if !strings.Contains(err.Error(), "rejection count not persisted") {
		t.Fatalf("error text does not report the lost count: %q", err.Error())
	}
	if !errors.Is(err, pre.Err) {
		t.Fatal("cause is not preserved")
	}
	if got := pool.RejectedCounts()[StageAuthenticate]; got != 1 {
		t.Fatalf("in-memory count=%d, want 1", got)
	}
}
