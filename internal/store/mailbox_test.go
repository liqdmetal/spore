package store

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestMailboxPushIntegration proves the Model A flow end-to-end without a DERO
// node: a sender PUTs a body to the recipient's inbox server (which persists it
// to a DiskStore), then reads it back through the same durable store. This is
// exactly the daemon's inbox path: the shared store is gone — the recipient's
// own daemon is the only thing that ever holds its ciphertext.
func TestMailboxPushIntegration(t *testing.T) {
	dir := t.TempDir()

	// Recipient side: a durable disk store exposed as an inbox server.
	disk, err := NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(disk, time.Hour)
	defer srv.Stop()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Sender side: an HTTP client pointed at the recipient's inbox.
	sender, err := NewHTTPStore(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	var cid [32]byte
	copy(cid[:], []byte("deadbeefdeadbeefdeadbeefdeadbeef"))
	deadline := time.Now().Add(time.Minute)
	if err := sender.Put(cid, []byte("encrypted body"), deadline); err != nil {
		t.Fatal(err)
	}

	// Recipient reads it back from its own durable store (survives even a
	// fresh DiskStore handle = process restart).
	got, err := disk.Get(cid)
	if err != nil || string(got) != "encrypted body" {
		t.Fatalf("recipient got %q, %v", got, err)
	}

	// Simulate restart: a new handle over the same dir still has the body.
	disk2, _ := NewDiskStore(dir)
	got, err = disk2.Get(cid)
	if err != nil || string(got) != "encrypted body" {
		t.Fatalf("after restart got %q, %v", got, err)
	}

	// TTL reaping still works through the inbox path.
	if n := disk2.Reap(time.Now().Add(time.Hour)); n != 1 {
		t.Fatalf("reap = %d, want 1", n)
	}
	if _, err := disk2.Get(cid); err != ErrNotFound {
		t.Fatalf("expired body should be gone, got %v", err)
	}
}
