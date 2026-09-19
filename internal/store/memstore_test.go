package store

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestPutGet(t *testing.T) {
	s := NewMemStore()
	cid := [32]byte{1}
	body := []byte("hello")
	deadline := time.Now().Add(time.Hour)
	if err := s.Put(cid, body, deadline); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d", s.Len())
	}
}

func TestExpired(t *testing.T) {
	s := NewMemStore()
	cid := [32]byte{2}
	deadline := time.Now().Add(-time.Second) // already past
	if err := s.Put(cid, []byte("x"), deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(cid); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Get([32]byte{9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestReap(t *testing.T) {
	s := NewMemStore()
	live := [32]byte{1}
	dead := [32]byte{2}
	_ = s.Put(live, []byte("a"), time.Now().Add(time.Hour))
	_ = s.Put(dead, []byte("b"), time.Now().Add(-time.Hour))
	if n := s.Reap(time.Now()); n != 1 {
		t.Fatalf("reaped %d, want 1", n)
	}
	if _, err := s.Get(live); err != nil {
		t.Fatalf("live body wrongly evicted: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}
}

func TestDelete(t *testing.T) {
	s := NewMemStore()
	cid := [32]byte{3}
	_ = s.Put(cid, []byte("x"), time.Now().Add(time.Hour))
	if err := s.Delete(cid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(cid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}
