package ratchetwire

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

// Rejected prekey handshakes are classified by stage, counted per stage, and
// reported without any key material in the error text.
func TestPrekeyRejectionsAreClassifiedAndCounted(t *testing.T) {
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

	// 0. Validation failure: a different identity cannot establish the handshake
	// (session id mismatch). It is classified as validate, and the prekey stays.
	var pre *PrekeyRejectedError
	wrongIdentity := filled(5)
	_, err = bob.ReceiveFirstFromOPKPool(wrongIdentity, spk, pool, frame, mustFrameBytes(frame))
	if !errors.As(err, &pre) || pre.Stage != StageValidate || pre.OPKID != 9 {
		t.Fatalf("wrong-identity init not classified as validate: %v", err)
	}
	if got := pool.Len(); got != 1 {
		t.Fatalf("validation failure changed OPK pool: len=%d, want 1", got)
	}
	if got := pool.RejectedCounts()[StageValidate]; got != 1 {
		t.Fatalf("validate count=%d, want 1", got)
	}

	// 1. Authentication failure: the error is classified and counted, and it
	// does not leak the prekey or the signed prekey in hex.
	tampered := frame
	tampered.Message.Ciphertext = append([]byte(nil), frame.Message.Ciphertext...)
	tampered.Message.Ciphertext[len(tampered.Message.Ciphertext)-1] ^= 1
	_, err = bob.ReceiveFirstFromOPKPool(bobID, spk, pool, tampered, mustFrameBytes(tampered))
	if !errors.As(err, &pre) {
		t.Fatalf("tampered init error is not a PrekeyRejectedError: %v", err)
	}
	if pre.Stage != StageAuthenticate || pre.OPKID != 9 {
		t.Fatalf("tampered init stage=%q opk=%d, want %q opk 9", pre.Stage, pre.OPKID, StageAuthenticate)
	}
	msg := err.Error()
	for _, secret := range [][]byte{opk[:], spk} {
		if strings.Contains(msg, hex.EncodeToString(secret)) {
			t.Fatalf("rejection error leaks key material: %q", msg)
		}
	}
	if got := pool.RejectedCounts()[StageAuthenticate]; got != 1 {
		t.Fatalf("authenticate count=%d, want 1", got)
	}
	if got := pool.RejectedCounts()[StageValidate]; got != 1 {
		t.Fatalf("validate count=%d after authenticate failure, want still 1", got)
	}

	// 2. A valid init succeeds, and it adds no rejection.
	if _, err := bob.ReceiveFirstFromOPKPool(bobID, spk, pool, frame, mustFrameBytes(frame)); err != nil {
		t.Fatalf("valid init: %v", err)
	}
	if got := pool.RejectedCounts(); got[StageValidate] != 1 || got[StageAuthenticate] != 1 || got[StageLookup] != 0 {
		t.Fatalf("counts after valid init: %v", got)
	}

	// 3. Replay after the prekey is spent: lookup stage, and ErrNoOPK still
	// matches through the wrapper.
	_, err = bob.ReceiveFirstFromOPKPool(bobID, spk, pool, frame, mustFrameBytes(frame))
	if !errors.Is(err, ErrNoOPK) {
		t.Fatalf("replay error %v does not wrap ErrNoOPK", err)
	}
	if !errors.As(err, &pre) || pre.Stage != StageLookup {
		t.Fatalf("replay not classified as lookup: %v", err)
	}
	if got := pool.RejectedCounts()[StageLookup]; got != 1 {
		t.Fatalf("lookup count=%d, want 1", got)
	}
}
