package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/liqdmetal/compost/internal/anchor"
	"github.com/liqdmetal/compost/internal/store"
)

func TestSendReceive(t *testing.T) {
	st := store.NewMemStore()
	alice, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := New(st)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("top secret meeting notes")
	a, err := alice.Send(bob.PublicKey(), msg, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bob.Receive(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %q", pt)
	}
}

func TestGraceWindowAfterRotation(t *testing.T) {
	st := store.NewMemStore()
	alice, _ := New(st)
	bob, _ := New(st)

	// Alice encrypts to Bob's ORIGINAL key, then Bob rotates.
	msg := []byte("in flight during rotation")
	a, err := alice.Send(bob.PublicKey(), msg, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Still decrypts via the grace key.
	pt, err := bob.Receive(a)
	if err != nil {
		t.Fatalf("grace window failed: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %q", pt)
	}
}

func TestBurnRejectsRead(t *testing.T) {
	st := store.NewMemStore()
	alice, _ := New(st)
	bob, _ := New(st)

	a, err := alice.Send(bob.PublicKey(), []byte("burned"), 10*time.Millisecond, false)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := bob.Receive(a); err == nil {
		t.Fatal("expected burn rejection")
	}
}

func TestTamperedBodyFails(t *testing.T) {
	st := store.NewMemStore()
	alice, _ := New(st)
	bob, _ := New(st)

	a, err := alice.Send(bob.PublicKey(), []byte("integrity matters"), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := st.Get(a.CID)
	ct[0] ^= 0xff
	_ = st.Put(a.CID, ct, time.Now().Add(time.Hour))

	if _, err := bob.Receive(a); err == nil {
		t.Fatal("expected AEAD tamper failure")
	}
}

func TestWrongRecipientCannotRead(t *testing.T) {
	st := store.NewMemStore()
	alice, _ := New(st)
	bob, _ := New(st)
	charlie, _ := New(st)

	a, err := alice.Send(bob.PublicKey(), []byte("for bob only"), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := charlie.Receive(a); err == nil {
		t.Fatal("charlie should not decrypt bob's message")
	}
}

func TestAckFlag(t *testing.T) {
	st := store.NewMemStore()
	alice, _ := New(st)
	bob, _ := New(st)
	a, err := alice.Send(bob.PublicKey(), []byte("x"), time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.Flags&anchor.FlagAckRequested == 0 {
		t.Fatal("ack flag not set")
	}
}

func TestRejectNonMessageAnchor(t *testing.T) {
	st := store.NewMemStore()
	bob, _ := New(st)
	a := &anchor.Anchor{Kind: anchor.KindAck}
	if _, err := bob.Receive(a); err == nil {
		t.Fatal("expected non-message rejection")
	}
}

func TestRestoreFromPriv(t *testing.T) {
	st := store.NewMemStore()
	bob, _ := New(st)
	priv := bob.PrivKey()

	alice, _ := New(st)
	msg := []byte("recovered after restart")
	a, err := alice.Send(bob.PublicKey(), msg, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate restart: restore Bob from his persisted key.
	bob2, err := NewFromPriv(st, priv)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := bob2.Receive(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %q", pt)
	}
}
