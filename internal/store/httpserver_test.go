package store

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPServerClientRoundTrip drives the real Server handler and a real
// HTTPStore client through the wire protocol.
func TestHTTPServerClientRoundTrip(t *testing.T) {
	srv := NewServer(NewMemStore(), 50*time.Millisecond)
	defer srv.Stop()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client, err := NewHTTPStore(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	cid := [32]byte{1, 2, 3}
	body := []byte("ciphertext bytes")
	deadline := time.Now().Add(time.Hour)
	if err := client.Put(cid, body, deadline); err != nil {
		t.Fatal(err)
	}

	got, err := client.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}

	// Delete then Get → ErrNotFound.
	if err := client.Delete(cid); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(cid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestHTTPServerExpired verifies the server returns 410 → ErrExpired.
func TestHTTPServerExpired(t *testing.T) {
	srv := NewServer(NewMemStore(), time.Hour)
	defer srv.Stop()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client, _ := NewHTTPStore(ts.URL)
	cid := [32]byte{9}
	_ = client.Put(cid, []byte("x"), time.Now().Add(-time.Second))

	if _, err := client.Get(cid); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

// TestHTTPServerReapAfterDeadline verifies the reaper evicts bodies server-side.
func TestHTTPServerReapAfterDeadline(t *testing.T) {
	backend := NewMemStore()
	srv := NewServer(backend, 20*time.Millisecond)
	defer srv.Stop()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client, _ := NewHTTPStore(ts.URL)
	cid := [32]byte{5}
	_ = client.Put(cid, []byte("short-lived"), time.Now().Add(30*time.Millisecond))

	// Poll for the eviction instead of sleeping a fixed window: the property
	// is monotone (once reaped, it stays gone), so polling cannot mask a
	// bug, while a fixed sleep can be starved entirely on a loaded runner —
	// the same fixed-window failure class the reap-ticker tests hit
	// ("2 .body files on disk, want 1", 2026-09-18).
	pollDeadline := time.Now().Add(3 * time.Second)
	for {
		if backend.Len() == 0 {
			break
		}
		if time.Now().After(pollDeadline) {
			t.Fatalf("reaper did not evict within 3s: len=%d", backend.Len())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := client.Get(cid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after reap, got %v", err)
	}
}
