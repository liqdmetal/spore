package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/store"
)

func TestFrameRoundTripAndPointerIsOpaque(t *testing.T) {
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
	msg, err := alice.Encrypt([]byte("secret ratcheted body"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	frame, err := NewInitFrame(hs, msg, deadline)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SessionID != hs.SessionID || parsed.Kind != FrameInit {
		t.Fatal("frame identity changed")
	}
	if _, err := parsed.HandshakeMessage(); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	ptr, err := PutFrame(st, parsed)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bob.Decrypt(stored.Message)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret ratcheted body" {
		t.Fatalf("got %q", plain)
	}
	if ptr.Route == ptr.CID {
		t.Fatal("route must not equal body cid")
	}
	got, err := st.Get(ptr.CID)
	if err != nil || BodyCID(got) != ptr.CID {
		t.Fatal("stored frame not content addressed")
	}
	for _, forbidden := range [][]byte{[]byte("secret ratcheted body"), aliceID, bobID} {
		for i := 0; i+len(forbidden) <= len(wire); i++ {
			if string(wire[i:i+len(forbidden)]) == string(forbidden) {
				t.Fatal("plaintext or identity secret leaked on wire")
			}
		}
	}
}

func TestParseRejectsMalformedAndZeroDeadline(t *testing.T) {
	if _, err := Parse([]byte("SPR2")); err == nil {
		t.Fatal("short frame accepted")
	}
	var sid [8]byte
	var msg ratchet.Message
	if _, err := NewMessageFrame(sid, msg, time.Time{}); err == nil {
		t.Fatal("zero deadline accepted")
	}
}

func TestFrameRejectsTruncatedCiphertextAndMalformedHandshake(t *testing.T) {
	if _, err := ratchet.UnmarshalMessage(make([]byte, 64)); err == nil {
		t.Fatal("message without AEAD tag accepted")
	}
	handshake := make([]byte, 81)
	handshake[68] = 0xff
	handshake[69] = 0xff
	handshake[70] = 0xff
	handshake[71] = 0xff
	handshake[80] = 2
	if _, err := ratchet.UnmarshalHandshake(handshake); err == nil {
		t.Fatal("invalid handshake flag accepted")
	}
}
