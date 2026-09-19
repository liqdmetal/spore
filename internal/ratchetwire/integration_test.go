package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

func TestE2BodyRoundTripKeepsHandshakeOffPointer(t *testing.T) {
	aliceID := filled(1)
	bobID := filled(2)
	spk := filled(3)
	opkPriv := filled(4)
	var opk [32]byte
	copy(opk[:], opkPriv)
	bundle, err := ratchet.BuildBundle(bobID, spk, 7, &opk, 9)
	if err != nil {
		t.Fatal(err)
	}
	bobSig, err := secure.SigPubOf(bobID)
	if err != nil {
		t.Fatal(err)
	}
	alice, hs, err := ratchet.EstablishInitiator(aliceID, bundle, bobSig)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ratchet.EstablishResponder(bobID, spk, &opk, hs)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := alice.Encrypt([]byte("future-private body"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := (Body{Kind: BodyKind, SessionID: hs.SessionID, Handshake: hs.MarshalBinary(), Message: msg}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.IsInit() || !ConstantTimeSessionEqual(parsed.SessionID, hs.SessionID) {
		t.Fatal("E2 identity changed")
	}
	plain, err := bob.Decrypt(parsed.Message)
	if err != nil || string(plain) != "future-private body" {
		t.Fatalf("decrypt: %q, %v", plain, err)
	}

	st := store.NewMemStore()
	frame, err := NewInitFrame(hs, msg, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ptr, err := PutFrame(st, frame)
	if err != nil {
		t.Fatal(err)
	}
	pointer := (PointerPayload{Version: PointerV1, Route: ptr.Route, CID: ptr.CID, BurnDeadline: ptr.BurnDeadline}).MarshalBinary()
	if len(pointer) != pointerLen {
		t.Fatalf("pointer len %d", len(pointer))
	}
	for _, forbidden := range [][]byte{hs.MarshalBinary(), []byte("future-private body")} {
		if hasBytes(pointer, forbidden) {
			t.Fatal("handshake/plaintext leaked into chain pointer")
		}
	}
}

func hasBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
