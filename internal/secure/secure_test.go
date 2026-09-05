package secure

import (
	"strings"
	"testing"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/whisper"
)

// alice/bob keypairs for tests.
func testKeys(t *testing.T) (alicePriv, bobPriv []byte) {
	t.Helper()
	a, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return a.Priv, b.Priv
}

func pub(t *testing.T, priv []byte) []byte {
	t.Helper()
	p, err := PubKeyOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvelopeRoundTrip(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)

	// Alice sends to Bob.
	inner := whisper.CanonicalCodec{}
	send, err := NewSendCodec(inner, alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := send.EncodeText("secret message to bob")
	if err != nil {
		t.Fatal(err)
	}

	// The payload on the wire must NOT contain the plaintext.
	if strings.Contains(string(payload), "secret message") {
		t.Fatal("plaintext leaked onto the wire!")
	}
	if !HasEnvelopeKind(payload) {
		t.Fatal("expected envelope magic")
	}

	// Bob receives and decrypts with his key.
	recv, err := NewRecvCodec(inner, bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	text, ok := recv.DecodeText(payload)
	if !ok || text != "secret message to bob" {
		t.Fatalf("bob got %q ok=%v", text, ok)
	}
}

func TestEavesdropperCannotRead(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)

	inner := whisper.CanonicalCodec{}
	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	payload, _ := send.EncodeText("for bob's eyes only")

	// Mallory has her own unrelated key; she must NOT decode bob's message.
	random, _ := crypto.GenerateKey()
	evil, err := NewRecvCodec(inner, random.Priv)
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := evil.DecodeText(payload); ok {
		t.Fatalf("mallory decrypted: %q", text)
	}

	// Bob still reads it.
	bobRecv, _ := NewRecvCodec(inner, bobPriv)
	if text, ok := bobRecv.DecodeText(payload); !ok || text != "for bob's eyes only" {
		t.Fatalf("bob lost the message: %q %v", text, ok)
	}
}

func TestTamperDetected(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}
	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	payload, _ := send.EncodeText("do not touch")

	// Flip a byte in the ciphertext region.
	bad := append([]byte(nil), payload...)
	bad[len(bad)-1] ^= 0xff

	recv, _ := NewRecvCodec(inner, bobPriv)
	if text, ok := recv.DecodeText(bad); ok {
		t.Fatalf("tampered message decoded: %q", text)
	}
}

func TestLegacyPlaintextPassesThrough(t *testing.T) {
	// Old DERO plaintext whispers (no envelope) must still decode via inner.
	inner := whisper.CanonicalCodec{}
	// A legacy canonical text payload (no envelope magic).
	legacy := whisper.EncodeTextCanonical("old plaintext message")

	// Receiver with any key: unwrap passes non-envelope through.
	bobPriv, _ := testKeys(t)
	recv, _ := NewRecvCodec(inner, bobPriv)
	text, ok := recv.DecodeText(legacy)
	if !ok || text != "old plaintext message" {
		t.Fatalf("legacy did not pass through: %q %v", text, ok)
	}
}

func TestPointerRoundTrip(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}
	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	var eph, cid [32]byte
	copy(eph[:], "ephemeral-pub-key-32-bytes!!")
	copy(cid[:], "body-cid-32-bytes-0000000000000")
	payload, err := send.EncodePointer(eph, cid)
	if err != nil {
		t.Fatal(err)
	}
	recv, _ := NewRecvCodec(inner, bobPriv)
	ge, gc, ok := recv.DecodePointer(payload)
	if !ok || ge != eph || gc != cid {
		t.Fatalf("pointer mismatch ok=%v", ok)
	}
}
