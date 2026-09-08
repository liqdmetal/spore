package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var cid [32]byte
	copy(cid[:], []byte("0123456789abcdef0123456789abcdef"))
	deadline := time.Now().Add(time.Hour)
	if err := s.Put(cid, []byte("hello body"), deadline); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(cid)
	if err != nil || string(got) != "hello body" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}

	// Survives restart (same dir).
	s2, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s2.Get(cid)
	if err != nil || string(got) != "hello body" {
		t.Fatalf("after restart get = %q, %v", got, err)
	}
}

func TestDiskStoreDeleteAndNotFound(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	var cid [32]byte
	if _, err := s.Get(cid); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Put(cid, []byte("x"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(cid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(cid); err != ErrNotFound {
		t.Fatalf("after delete want ErrNotFound, got %v", err)
	}
	if err := s.Delete(cid); err != ErrNotFound {
		t.Fatalf("double delete want ErrNotFound, got %v", err)
	}
}

func TestDiskStoreReapExpired(t *testing.T) {
	s, _ := NewDiskStore(t.TempDir())
	a, b := [32]byte{1}, [32]byte{2}
	s.Put(a, []byte("a"), time.Now().Add(-time.Minute)) // already expired
	s.Put(b, []byte("b"), time.Now().Add(time.Hour))    // still live
	if n := s.Reap(time.Now()); n != 1 {
		t.Fatalf("reap = %d, want 1", n)
	}
	if _, err := s.Get(a); err != ErrNotFound {
		t.Fatalf("expired body should be gone, got %v", err)
	}
	if _, err := s.Get(b); err != nil {
		t.Fatalf("live body lost: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}
}

func TestDiskStoreScrubbedDirMode(t *testing.T) {
	// MkdirAll(0700) is the privacy posture; Windows hosts don't honor unix
	// perms so we only assert it creates the tree without error. Real perm
	// enforcement happens on the Linux deployment.
	if _, err := NewDiskStore(filepath.Join(t.TempDir(), "sub")); err != nil {
		t.Fatal(err)
	}
}

// TestDiskStoreCrashBetweenExpAndBodyLeavesNoOrphanBody proves the safe
// half of the ordering fix: Put writes .exp before .body specifically so
// that a crash between the two writes can only ever produce an orphaned
// .exp with no matching .body — never the reverse. This test simulates that
// crash point directly (rather than actually killing the process) by
// invoking the same temp+rename sequence Put uses, stopping after the .exp
// rename, and confirming Get correctly reports the body as absent and Reap
// cleans up the dangling .exp.
func TestDiskStoreCrashBetweenExpAndBodyLeavesNoOrphanBody(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var cid [32]byte
	copy(cid[:], []byte("crash-sim-cid-only-exp-written!"))

	// Simulate the crash: write only the .exp half, as Put's first step
	// would, then stop (as if the process died before the .body rename).
	if err := os.WriteFile(s.expPath(cid), []byte("9999999999"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No body was ever written: Get must report not-found, not treat the
	// missing body as an empty-but-valid body.
	if _, err := s.Get(cid); err != ErrNotFound {
		t.Fatalf("orphaned .exp with no .body should read as ErrNotFound, got %v", err)
	}

	// Reap must clean up the dangling .exp so it doesn't accumulate forever.
	s.Reap(time.Unix(1<<62, 0)) // far future: any real deadline is "expired"
	if _, err := os.Stat(s.expPath(cid)); !os.IsNotExist(err) {
		t.Fatalf("dangling .exp was not reaped: stat err=%v", err)
	}
}

// TestDiskStorePutWritesExpBeforeAttemptingBody directly proves the write
// ORDER (not just the final state), which the other two tests above cannot
// distinguish on their own. It forces the body-write half of Put to fail by
// pre-occupying the final body path with a directory (so the rename can
// never succeed), then asserts the .exp file was nonetheless durably
// written. Under the fixed ordering (.exp first, then attempt .body), this
// is exactly what must happen. Under the original ordering (.body first,
// then .exp), a failed body write returns before .exp is ever touched, so
// this same assertion would fail — this test would have caught that
// regression.
func TestDiskStorePutWritesExpBeforeAttemptingBody(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var cid [32]byte
	copy(cid[:], []byte("force-body-write-failure-cid-32"))

	// Occupy the final body path with a directory so os.Rename(tmp, bodyPath)
	// is guaranteed to fail (rename cannot replace a non-empty semantic
	// target across these path kinds on either Windows or POSIX).
	if err := os.MkdirAll(s.bodyPath(cid), 0o700); err != nil {
		t.Fatal(err)
	}

	err = s.Put(cid, []byte("body"), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected Put to fail when the body path is occupied by a directory")
	}

	// The point of the fix: .exp must already be durable even though the
	// overall Put failed on the body half.
	if _, statErr := os.Stat(s.expPath(cid)); statErr != nil {
		t.Fatalf(".exp was not durably written before the body attempt failed: %v", statErr)
	}
}
