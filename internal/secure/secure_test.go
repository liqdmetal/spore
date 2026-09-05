package secure

import (
	"bytes"
	"crypto/rand"
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

// --- adversarial edge cases (panic-free error paths) ---

// TestDecryptNeverPanicsOnGarbage feeds Decrypt non-envelope and malformed
// inputs and asserts it returns an error (never panics).
func TestDecryptNeverPanicsOnGarbage(t *testing.T) {
	_, bobPriv := testKeys(t)

	cases := map[string][]byte{
		"empty":          {},
		"one byte":       {0x01},
		"short (pub)":    make([]byte, PubLen-1),
		"no ciphertext":  make([]byte, PubLen+NonceLen),    // missing AEAD tag
		"one short of":   make([]byte, PubLen+NonceLen+15), // tag-1
		"exactly header": make([]byte, PubLen+NonceLen+16), // garbage where tag should be
		"random garbage": randBytes(200),
		"all zeros":      make([]byte, 512),
		"all ff":         bytes.Repeat([]byte{0xff}, 512),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			// Must not panic and must not yield plaintext.
			pt, err := Decrypt(bobPriv, env)
			if err == nil {
				t.Fatalf("Decrypt(%s): expected error, got plaintext len=%d", name, len(pt))
			}
		})
	}
}

// TestDecryptRequiresValidKey: a wrong-length or nil receiver key must error,
// never panic.
func TestDecryptRequiresValidKey(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	env, err := Encrypt(alicePriv, pub(t, bobPriv), []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if _, err := Decrypt(key, env); err == nil {
			t.Fatalf("Decrypt with %d-byte key should error", len(key))
		}
	}
}

// TestEncryptRejectsUndersizedKeys: Encrypt with 0/undersized keys must error
// (and not produce a broken envelope that later panics on decrypt).
func TestEncryptRejectsUndersizedKeys(t *testing.T) {
	_, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	short := make([]byte, 31)
	cases := []struct {
		name         string
		priv, pub    []byte
		wantKeyError bool
	}{
		{"nil priv", nil, bobPub, true},
		{"short priv", short, bobPub, true},
		{"nil pub", bobPriv, nil, true},
		{"short pub", bobPriv, short, true},
		{"zeroed 32-byte priv", make([]byte, 32), bobPub, false}, // len-valid; x25519 clamps, no error
		{"valid keys", bobPriv, bobPub, false},
	}
	for _, tc := range cases {
		env, err := Encrypt(tc.priv, tc.pub, []byte("secret"))
		if tc.wantKeyError {
			if err == nil {
				t.Fatalf("%s: expected key-length error", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		// A valid-key envelope must also survive a wrong key decrypt without panic.
		if _, derr := Decrypt(make([]byte, 32), env); derr == nil {
			t.Fatalf("%s: wrong-key decrypt should fail", tc.name)
		}
	}
}

// TestEmptyPlaintextRoundTrip: the boundary zero-length plaintext must seal and
// open cleanly (envelope = header + AEAD tag only).
func TestEmptyPlaintextRoundTrip(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	env, err := Encrypt(alicePriv, pub(t, bobPriv), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != PubLen+NonceLen+16 {
		t.Fatalf("empty-plaintext envelope len = %d, want %d", len(env), PubLen+NonceLen+16)
	}
	pt, err := Decrypt(bobPriv, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("empty plaintext decrypted to %d bytes", len(pt))
	}
}

// TestEnvelopeNonceUniqueAcrossStaticReuse guards the two-time-pad hazard: even
// when the SAME ECDH secret is reused (EncryptStatic with a fixed sender key —
// the one real-traffic-unsafe path), each message must carry a distinct nonce so
// no (key, nonce) pair is ever reused. Two envelopes for the same plaintext
// under the same keys must differ in the nonce region, and each must decrypt.
func TestEnvelopeNonceUniqueAcrossStaticReuse(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	msg := []byte("reused secret must never reuse a nonce")

	e1, err := EncryptStatic(alicePriv, bobPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := EncryptStatic(alicePriv, bobPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(e1, e2) {
		t.Fatal("two EncryptStatic envelopes are byte-identical: (key, nonce) reused!")
	}
	n1, n2 := e1[PubLen:PubLen+NonceLen], e2[PubLen:PubLen+NonceLen]
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across two messages under the same ECDH secret")
	}
	for i, e := range [][]byte{e1, e2} {
		pt, err := Decrypt(bobPriv, e)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("envelope %d failed decrypt: err=%v", i, err)
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
