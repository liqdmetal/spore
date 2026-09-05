package longmsg

import (
	"context"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/rendezvous"
	"github.com/liqdmetal/spore/internal/store"
)

// TestNobodyButUsRoundTrip: Alice holds the body on her own store; Bob fetches
// it over a peer transport (here in-memory, standing in for the node P2P
// channel) and decrypts. No third party ever holds plaintext or the key.
func TestNobodyButUsRoundTrip(t *testing.T) {
	sender := mustEndpoint(t)
	recv := mustEndpoint(t)
	transport := rendezvous.NewMemTransport()

	longMsg := []byte("this is a long private message that never rides a block " +
		"and never sits on a third-party store, only sender and receiver ever hold it")

	// Alice sends to Bob's long-term pub; the body stays on HER store.
	ptr, err := sender.SendBody(recv.PublicKey(), longMsg, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, err := sender.Store().Get(ptr.CID)
	if err != nil {
		t.Fatal("body should be on sender store")
	}
	// Serve it on the peer transport (the sender's node answering Bob).
	transport.Put(ptr.CID, body)

	// Bob fetches + decrypts.
	got, err := recv.ReceiveBody(ptr, func(c [32]byte) ([]byte, error) {
		return transport.Fetch(context.Background(), c)
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(longMsg) {
		t.Fatalf("got %q, want %q", got, longMsg)
	}
}

// TestWrongKeyFails: a third party with their OWN key cannot decrypt a body
// sent to someone else (ECDH fails).
func TestWrongKeyFails(t *testing.T) {
	sender := mustEndpoint(t)
	realRecv := mustEndpoint(t)
	eve := mustEndpoint(t)
	transport := rendezvous.NewMemTransport()

	ptr, err := sender.SendBody(realRecv.PublicKey(), []byte("secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := sender.Store().Get(ptr.CID)
	transport.Put(ptr.CID, body)

	if _, err := eve.ReceiveBody(ptr, func(c [32]byte) ([]byte, error) {
		return transport.Fetch(context.Background(), c)
	}); err == nil {
		t.Fatal("eve should not decrypt a body meant for bob")
	}
}

// TestTamperRejected: a swapped body fails the CID check before decrypt.
func TestTamperRejected(t *testing.T) {
	sender := mustEndpoint(t)
	recv := mustEndpoint(t)
	ptr, err := sender.SendBody(recv.PublicKey(), []byte("original"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Serve a DIFFERENT body under the same CID reference.
	if _, err := recv.ReceiveBody(ptr, func([32]byte) ([]byte, error) {
		return []byte("tampered"), nil
	}); err == nil {
		t.Fatal("expected CID mismatch")
	}
}

// TestBurnEnforced: a pointer past its deadline must be rejected before fetch,
// so a burned message can never be read.
func TestBurnEnforced(t *testing.T) {
	sender := mustEndpoint(t)
	recv := mustEndpoint(t)
	ptr, err := sender.SendBody(recv.PublicKey(), []byte("expiring secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Age the deadline into the past.
	ptr.BurnDeadline = uint64(time.Now().Add(-time.Minute).Unix())
	// fetch would succeed if called; the deadline check must fire first.
	if _, err := recv.ReceiveBody(ptr, func([32]byte) ([]byte, error) {
		return []byte("should never be fetched"), nil
	}); err == nil {
		t.Fatal("expected burned-message rejection")
	}
}

func mustEndpoint(t *testing.T) *Endpoint {
	t.Helper()
	e, err := NewEndpoint(store.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
