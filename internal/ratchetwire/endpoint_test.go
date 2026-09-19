package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

func TestEndpointFirstAndContinuationRoundTrip(t *testing.T) {
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
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	ptr, pointer, err := alice.SendFirst(aliceID, bundle, bobSig, []byte("first"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	parsedPointer, err := ParsePointerPayload(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if parsedPointer.Pointer() != ptr {
		t.Fatal("pointer changed")
	}
	frame, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A tampered first frame installs a candidate before authentication; the
	// failed attempt must erase it so the valid init is not permanently blocked.
	tampered := frame
	tampered.Message.Ciphertext = append([]byte(nil), frame.Message.Ciphertext...)
	tampered.Message.Ciphertext[len(tampered.Message.Ciphertext)-1] ^= 1
	if _, err := bob.ReceiveFirst(bobID, spk, &opk, tampered, mustFrameBytes(tampered)); err == nil {
		t.Fatal("tampered first frame accepted")
	}
	if got := bob.Sessions.Count(); got != 0 {
		t.Fatalf("tampered init left %d sessions", got)
	}
	plain, err := bob.ReceiveFirst(bobID, spk, &opk, frame, mustFrameBytes(frame))
	if err != nil || string(plain) != "first" {
		t.Fatalf("first=%q err=%v", plain, err)
	}
	// The same session can now continue, and the recipient's state advances.
	id := frame.SessionID
	next, _, err := alice.SendNext(id, []byte("second"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = bob.ReceiveNext(next, time.Now())
	if err != nil || string(plain) != "second" {
		t.Fatalf("second=%q err=%v", plain, err)
	}
}

func mustFrameBytes(f Frame) []byte {
	b, err := f.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}
