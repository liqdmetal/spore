package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// A message that fails validation must not use up its one-time prekey. The
// key stays available for the genuine init, and is spent only once that init
// authenticates.
func TestFailedInitDoesNotConsumeOPK(t *testing.T) {
	aliceID, bobID, spk := filled(1), filled(2), filled(3)
	var opk [32]byte
	copy(opk[:], filled(4))
	bundle, err := ratchet.BuildBundle(bobID, spk, 7, &opk, 9)
	if err != nil {
		t.Fatal(err)
	}
	bobSig, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	alice := NewEndpoint(st)
	bob := NewEndpoint(st)
	pool := NewOPKPool()
	if err := pool.Add(9, opk); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	ptr, _, err := alice.SendFirst(aliceID, bundle, bobSig, []byte("first"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tampered := frame
	tampered.Message.Ciphertext = append([]byte(nil), frame.Message.Ciphertext...)
	tampered.Message.Ciphertext[len(tampered.Message.Ciphertext)-1] ^= 1
	if _, err := bob.ReceiveFirstFromOPKPool(bobID, spk, pool, tampered, mustFrameBytes(tampered)); err == nil {
		t.Fatal("tampered init accepted")
	}
	if got := pool.Len(); got != 1 {
		t.Fatalf("failed init changed OPK pool: len=%d, want 1", got)
	}
	if _, err := pool.Peek(9); err != nil {
		t.Fatalf("failed init consumed OPK 9: %v", err)
	}
	if got := bob.Sessions.Count(); got != 0 {
		t.Fatalf("failed init left %d sessions", got)
	}

	plain, err := bob.ReceiveFirstFromOPKPool(bobID, spk, pool, frame, mustFrameBytes(frame))
	if err != nil || string(plain) != "first" {
		t.Fatalf("valid init: plain=%q err=%v", plain, err)
	}
	if got := pool.Len(); got != 0 {
		t.Fatalf("valid init left %d OPKs, want 0 (consumed)", got)
	}
	// The prekey is spent: replaying the same init must not be accepted again.
	if _, err := bob.ReceiveFirstFromOPKPool(bobID, spk, pool, frame, mustFrameBytes(frame)); err == nil {
		t.Fatal("replayed init accepted after its OPK was spent")
	}
}
