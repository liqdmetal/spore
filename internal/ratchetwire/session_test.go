package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
)

func TestSessionTableRejectsInitReplayAndDecryptsOnce(t *testing.T) {
	aliceID, bobID, spk := filled(1), filled(2), filled(3)
	var opk [32]byte
	copy(opk[:], filled(4))
	bundle, err := ratchet.BuildBundle(bobID, spk, 1, &opk, 1)
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
	msg, err := alice.Encrypt([]byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := NewInitFrame(hs, msg, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tab := NewSessionTable()
	if err := tab.AcceptInit(hs, bob, raw); err != nil {
		t.Fatal(err)
	}
	if err := tab.AcceptInit(hs, bob, raw); err != ErrSessionExists {
		t.Fatalf("replay err=%v", err)
	}
	plain, err := tab.Decrypt(hs.SessionID, msg, time.Now().Add(time.Hour))
	if err != nil || string(plain) != "once" {
		t.Fatalf("decrypt=%q err=%v", plain, err)
	}
	if _, err := tab.Decrypt(hs.SessionID, msg, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("duplicate decrypted")
	}
}
