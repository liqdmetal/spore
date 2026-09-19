package secure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/whisper"
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
	if !HasSignedKind(payload) {
		t.Fatal("expected v2 signed envelope magic 0xE1")
	}

	// Bob receives (strict) and decrypts + verifies with his key.
	recv, err := NewRecvCodec(inner, bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	text, ok := recv.DecodeText(payload)
	if !ok || text != "secret message to bob" {
		t.Fatalf("bob got %q ok=%v", text, ok)
	}
}

func TestSenderAttribution(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}

	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	payload, err := send.EncodeText("from alice, verifiably")
	if err != nil {
		t.Fatal(err)
	}
	wantSig, err := SigPubOf(alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	recv, _ := NewRecvCodec(inner, bobPriv)
	text, sigPub, ok := recv.DecodeTextSender(payload)
	if !ok || text != "from alice, verifiably" {
		t.Fatalf("decode failed: %q ok=%v", text, ok)
	}
	if !bytes.Equal(sigPub, wantSig) {
		t.Fatal("sender sigPub mismatch: attribution lost")
	}
	// Deterministic derivation: the same identity always yields the same sig key.
	again, _ := SigPubOf(alicePriv)
	if !bytes.Equal(again, wantSig) {
		t.Fatal("sig key derivation is not deterministic")
	}
}

func TestForgedSenderRejected(t *testing.T) {
	// Mallory cannot pass as ALICE once the recipient pins alice's sig key:
	// Mallory CAN mint a perfectly valid envelope under her OWN key (that is
	// what signatures prove — who holds the signing key), but pinning turns
	// validity into attribution: unpinned senders never decode (T1).
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}

	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	genuine, _ := send.EncodeText("genuine alice")

	// Mallory builds her own validly-signed envelope claiming the same slot.
	malloryPriv, _ := crypto.GenerateKey()
	mallorySend, _ := NewSendCodec(inner, malloryPriv.Priv, bobPub)
	forged, _ := mallorySend.EncodeText("i am alice, honest")

	// Unpinned receiver: both decode, but each attributes to its true signer.
	open, _ := NewRecvCodec(inner, bobPriv)
	_, sigPub, ok := open.DecodeTextSender(forged)
	if !ok {
		t.Fatal("precondition: unpinned receiver must decode valid envelopes")
	}
	mallorySig, _ := SigPubOf(malloryPriv.Priv)
	if !bytes.Equal(sigPub, mallorySig) {
		t.Fatal("attribution lost: envelope did not attribute to its real signer")
	}

	// Pinned receiver: only alice decodes; mallory's mail never arrives.
	pinned, _ := NewRecvCodec(inner, bobPriv)
	aliceSig, _ := SigPubOf(alicePriv)
	pinned.Pin(aliceSig)
	if text, ok := pinned.DecodeText(forged); ok {
		t.Fatalf("unpinned sender decoded on a pinned inbox: %q", text)
	}
	if text, ok := pinned.DecodeText(genuine); !ok || text != "genuine alice" {
		t.Fatalf("pinned sender rejected: %q %v", text, ok)
	}
}

func TestSignatureTamperRejected(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}
	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	payload, _ := send.EncodeText("do not touch my sig")

	// Flip one bit inside the signature.
	bad := append([]byte(nil), payload...)
	bad[89] ^= 0x01
	recv, _ := NewRecvCodec(inner, bobPriv)
	if _, ok := recv.DecodeText(bad); ok {
		t.Fatal("tampered signature accepted")
	}
}

func TestCrossRecipientReplayRejected(t *testing.T) {
	// An envelope minted for Bob must not verify when presented to Carol, even
	// though Carol's ECDH would (hypothetically) succeed — the transcript binds
	// the recipient's prekey. We simulate the strongest version: Carol IS given
	// a validly-signed envelope whose transcript used BOB's key; her verify
	// (which substitutes her own pub) must fail.
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	inner := whisper.CanonicalCodec{}
	send, _ := NewSendCodec(inner, alicePriv, bobPub)
	payload, _ := send.EncodeText("only bob may accept me")

	// Strip the kind byte, verify manually against CAROL's pub to prove the
	// recipient binding: recompute the transcript with carol's pub and check
	// the original sig does NOT verify.
	_, carolPriv := testKeys(t)
	carolPub, _ := PubKeyOf(carolPriv)
	body := StripKind(payload)
	sigPub := body[:32]
	ephPub := body[32:64]
	nonce := body[64:88]
	sig := body[88 : 88+64]
	ct := body[88+64:]
	bobVerify := append([]byte("spore/env/v2"), sigPub...)
	bobVerify = append(bobVerify, ephPub...)
	bobVerify = append(bobVerify, nonce...)
	bobVerify = append(bobVerify, bobPub...)
	ctHash := sha256.Sum256(ct)
	bobVerify = append(bobVerify, ctHash[:]...)
	if !ed25519.Verify(ed25519.PublicKey(sigPub), bobVerify, sig) {
		t.Fatal("precondition: envelope must verify for its real recipient")
	}
	carolVerify := append([]byte("spore/env/v2"), sigPub...)
	carolVerify = append(carolVerify, ephPub...)
	carolVerify = append(carolVerify, nonce...)
	carolVerify = append(carolVerify, carolPub...)
	carolVerify = append(carolVerify, ctHash[:]...)
	if ed25519.Verify(ed25519.PublicKey(sigPub), carolVerify, sig) {
		t.Fatal("envelope replayed across recipients still verifies — recipient not bound")
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

func TestStrictRejectsLegacyAndPlaintext(t *testing.T) {
	_, bobPriv := testKeys(t)
	inner := whisper.CanonicalCodec{}
	recv, _ := NewRecvCodec(inner, bobPriv)

	// Legacy canonical plaintext (no envelope): must NOT decode in strict mode.
	legacy := whisper.EncodeTextCanonical("injected plaintext")
	if text, ok := recv.DecodeText(legacy); ok {
		t.Fatalf("strict mode accepted plaintext injection: %q", text)
	}

	// A hand-built legacy 0xE0 envelope: also refused in strict mode.
	sender, _ := crypto.GenerateKey()
	var raw bytes.Buffer
	raw.WriteByte(EnvelopeKindPrefix)
	body, err := legacySeal(sender.Priv, pub(t, bobPriv), legacy)
	if err != nil {
		t.Fatal(err)
	}
	raw.Write(body)
	if _, ok := recv.DecodeText(raw.Bytes()); ok {
		t.Fatal("strict mode accepted unsigned legacy envelope")
	}

	// The same payloads DO decode in legacy mode (migration path).
	lrecv, _ := NewRecvCodecLegacy(inner, bobPriv)
	if _, ok := lrecv.DecodeText(legacy); !ok {
		t.Fatal("legacy mode must still decode plaintext passthrough")
	}
	if _, ok := lrecv.DecodeText(raw.Bytes()); !ok {
		t.Fatal("legacy mode must still decode legacy envelopes")
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
	_, _, sigPub, ok := recv.DecodePointerSender(payload)
	if !ok {
		t.Fatal("pointer sender attribution failed")
	}
	want, _ := SigPubOf(alicePriv)
	if !bytes.Equal(sigPub, want) {
		t.Fatal("pointer sender sigPub mismatch")
	}
}

// --- adversarial edge cases (panic-free error paths) ---

// TestDecryptNeverPanicsOnGarbage feeds Decrypt non-envelope and malformed
// inputs and asserts it returns an error (never panics).
func TestDecryptNeverPanicsOnGarbage(t *testing.T) {
	_, bobPriv := testKeys(t)

	mk := func(b []byte) []byte { return append([]byte{EnvelopeKindSigned}, b...) }
	cases := map[string][]byte{
		"empty":          {},
		"one byte":       {0x01},
		"short (pub)":    make([]byte, PubLen-1),
		"no ciphertext":  mk(make([]byte, Overhead-16)),    // missing AEAD tag
		"one short of":   mk(make([]byte, Overhead-16+15)), // tag-1
		"exactly header": mk(make([]byte, Overhead-16+16)), // garbage where tag should be
		"random garbage": mk(randBytes(200)),
		"all zeros":      mk(make([]byte, 512)),
		"all ff":         mk(bytes.Repeat([]byte{0xff}, 512)),
		"legacy short":   append([]byte{EnvelopeKindPrefix}, make([]byte, PubLen+NonceLen)...),
		"legacy garbage": append([]byte{EnvelopeKindPrefix}, randBytes(80)...),
		"unknown kind":   {0xE2, 0x00, 0x01},
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
		name      string
		priv, pub []byte
		wantError bool
	}{
		{"nil priv", nil, bobPub, true},
		{"short priv", short, bobPub, true},
		{"nil pub", bobPriv, nil, true},
		{"short pub", bobPriv, short, true},
		{"zeroed 32-byte priv", make([]byte, 32), bobPub, false}, // len-valid; x25519 clamps
		{"valid keys", bobPriv, bobPub, false},
	}
	for _, tc := range cases {
		env, err := Encrypt(tc.priv, tc.pub, []byte("secret"))
		if tc.wantError {
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
// open cleanly (envelope = kind + sigPub + eph + nonce + sig + AEAD tag only).
func TestEmptyPlaintextRoundTrip(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	env, err := Encrypt(alicePriv, pub(t, bobPriv), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1+Overhead-16+16 {
		t.Fatalf("empty-plaintext envelope len = %d, want %d", len(env), 1+Overhead)
	}
	pt, err := Decrypt(bobPriv, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("empty plaintext decrypted to %d bytes", len(pt))
	}
}

// TestNonceUniqueAcrossMessages guards the two-time-pad hazard: two envelopes
// of the SAME plaintext under the SAME keys must differ (fresh random nonce),
// and each must decrypt.
func TestNonceUniqueAcrossMessages(t *testing.T) {
	alicePriv, bobPriv := testKeys(t)
	bobPub := pub(t, bobPriv)
	msg := []byte("never reuse a (key, nonce) pair")

	nonceAt := 1 + 32 + 32 // kind + sigPub + ephPub
	e1, err := Encrypt(alicePriv, bobPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Encrypt(alicePriv, bobPub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(e1, e2) {
		t.Fatal("two envelopes are byte-identical: nonce reused!")
	}
	n1 := e1[nonceAt : nonceAt+NonceLen]
	n2 := e2[nonceAt : nonceAt+NonceLen]
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across two messages under the same keys")
	}
	for i, e := range [][]byte{e1, e2} {
		pt, err := Decrypt(bobPriv, e)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("envelope %d failed decrypt: err=%v", i, err)
		}
	}
}

// TestHKDFBindingSeparatesPeerPairs: the same shared secret (identical keys)
// under DeriveKeyBound for DIFFERENT peer pairs yields unrelated keys.
func TestHKDFBindingSeparatesPeerPairs(t *testing.T) {
	secret := randBytes(32)
	a, _ := PubKeyOf(randBytes(32))
	b, _ := PubKeyOf(randBytes(32))
	c, _ := PubKeyOf(randBytes(32))

	k1, err := crypto.DeriveKeyBound(secret, a, b)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.DeriveKeyBound(secret, a, c)
	if err != nil {
		t.Fatal(err)
	}
	k3, err := crypto.DeriveKeyBound(secret, c, b)
	if err != nil {
		t.Fatal(err)
	}
	kPlain, err := crypto.DeriveKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string][]byte{"swap-recipient": k2, "swap-sender": k3, "unbound": kPlain} {
		if bytes.Equal(k1, other) {
			t.Fatalf("bound key collides with %s variant", name)
		}
	}
}

// legacySeal builds a v1 (0xE0-era) unsigned envelope body: eph || nonce || ct
// with the old unbound HKDF. Used to prove strict-mode rejection.
func legacySeal(senderPriv, recipientPub, plaintext []byte) ([]byte, error) {
	secret, err := crypto.SharedSecret(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(secret)
	key, err := crypto.DeriveKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	nonce, err := crypto.DeriveNonce(secret)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(plaintext, key, nonce)
	if err != nil {
		return nil, err
	}
	eph, err := PubKeyOf(senderPriv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+24+len(ct))
	out = append(out, eph...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
