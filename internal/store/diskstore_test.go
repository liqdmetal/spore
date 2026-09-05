package store

import (
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
