package rendezvous

import (
	"context"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/store"
)

// TestFetchRoundTrip: sender encrypts+stores a body, it's available on the
// peer, recipient fetches by CID and gets it back with integrity verified.
func TestFetchRoundTrip(t *testing.T) {
	peer := NewMemTransport()
	body := []byte("ciphertext of a long message that never touches a block")
	cid := crypto.CID(body)
	peer.Put(cid, body)

	got, err := FetchByCID(context.Background(), peer.Fetch, cid)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q, want %q", got, body)
	}
}

// TestTamperedRejected: serving a DIFFERENT body under a cid is rejected by the
// sha256 check before any decrypt.
func TestTamperedRejected(t *testing.T) {
	peer := NewMemTransport()
	cid := crypto.CID([]byte("original"))
	peer.bodies[cid] = []byte("tampered!")

	if _, err := FetchByCID(context.Background(), peer.Fetch, cid); err == nil {
		t.Fatal("expected CID mismatch rejection")
	}
}

// TestMissingBody: fetching a cid nobody serves returns ErrNotFound.
func TestMissingBody(t *testing.T) {
	peer := NewMemTransport()
	var cid [32]byte
	copy(cid[:], "missing-body")
	if _, err := FetchByCID(context.Background(), peer.Fetch, cid); err != store.ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

// TestServeBodyConfirms: server reports availability only if the body exists.
func TestServeBodyConfirms(t *testing.T) {
	srv := NewServer(store.NewMemStore())
	cid := crypto.CID([]byte("x"))
	if srv.ServeBody(cid, time.Now().Add(time.Hour)) {
		t.Fatal("should report unavailable for a body never stored")
	}
}
