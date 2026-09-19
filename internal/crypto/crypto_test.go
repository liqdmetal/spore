package crypto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(255 - i)
	}
	msg := []byte("the fox is in the henhouse")
	ct, err := Seal(msg, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(ct, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("round-trip mismatch: got %q", pt)
	}
}

func TestTamperFails(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	ct, err := Seal([]byte("secret"), key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	if _, err := Open(ct, key, nonce); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1 := make([]byte, KeySize)
	k2 := make([]byte, KeySize)
	k2[0] = 1
	nonce := make([]byte, NonceSize)
	ct, _ := Seal([]byte("secret"), k1, nonce)
	if _, err := Open(ct, k2, nonce); err == nil {
		t.Fatal("expected wrong-key failure")
	}
}

func TestECDHSharedSecretAgreement(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(a.Priv)
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(b.Priv)
	sa, err := SharedSecret(a.Priv, b.Pub)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := SharedSecret(b.Priv, a.Pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sa, sb) {
		t.Fatal("shared secrets disagree")
	}
}

func TestDerivedKeyAndNonceDeterministic(t *testing.T) {
	secret := []byte("s")
	k1, err := DeriveKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := DeriveKey(secret)
	if !bytes.Equal(k1, k2) {
		t.Fatal("key derivation not deterministic")
	}
	if len(k1) != KeySize {
		t.Fatalf("key size %d", len(k1))
	}

	n1, _ := DeriveNonce(secret)
	if len(n1) != NonceSize {
		t.Fatalf("nonce size %d, want %d", len(n1), NonceSize)
	}
	if bytes.Equal(n1, k1[:NonceSize]) {
		t.Fatal("nonce should not equal key prefix")
	}
}

func TestDerivedEndToEnd(t *testing.T) {
	// Two parties derive key+nonce from the same ECDH secret and interoperate.
	a, _ := GenerateKey()
	defer Zero(a.Priv)
	b, _ := GenerateKey()
	defer Zero(b.Priv)

	sa, _ := SharedSecret(a.Priv, b.Pub)
	sb, _ := SharedSecret(b.Priv, a.Pub)
	if !bytes.Equal(sa, sb) {
		t.Fatal("secrets disagree")
	}

	key, _ := DeriveKey(sa)
	nonce, _ := DeriveNonce(sa)
	msg := []byte("derived from the shared secret")
	ct, err := Seal(msg, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(ct, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %q", pt)
	}
}

func TestCIDDeterministic(t *testing.T) {
	ct := []byte("abc")
	c1 := CID(ct)
	c2 := CID([]byte("abc"))
	if c1 != c2 {
		t.Fatal("CID not deterministic")
	}
	ct[0] = 'd'
	if CID(ct) == c1 {
		t.Fatal("CID should change with content")
	}
}

func TestKeyPairFromPriv(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := KeyPairFromPriv(a.Priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Pub, b.Pub) {
		t.Fatal("reconstructed pubkey differs")
	}
}

// TestSharedSecretRejectsLowOrderPoint: ECDH against an invalid (low-order)
// remote public key must return an error, not panic or silently return zeros,
// and must NOT mutate the caller's private or public slices.
func TestSharedSecretRejectsLowOrderPoint(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(a.Priv)
	privCopy := append([]byte(nil), a.Priv...)
	// All-zero is a low-order/invalid X25519 public key.
	badPub := make([]byte, 32)
	if _, err := SharedSecret(a.Priv, badPub); err == nil {
		t.Fatal("expected ECDH failure against low-order public key")
	}
	if !bytes.Equal(a.Priv, privCopy) {
		t.Fatal("SharedSecret mutated the caller's private scalar on failure")
	}
	// badPub itself must be untouched (it is all-zero; ensure it stayed so).
	if !bytes.Equal(badPub, make([]byte, 32)) {
		t.Fatal("SharedSecret mutated the peer public key on failure")
	}
}

// TestKeyPairFromPrivRejectsWrongLength: wrong-length scalars are rejected and
// the caller's buffer is left untouched.
func TestKeyPairFromPrivRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i)
		}
		saved := append([]byte(nil), in...)
		if _, err := KeyPairFromPriv(in); err == nil {
			t.Fatalf("KeyPairFromPriv(%d bytes) should error", n)
		}
		if !bytes.Equal(in, saved) {
			t.Fatalf("KeyPairFromPriv(%d bytes) mutated its input", n)
		}
	}
}

// TestSealOpenRejectBadKeyNonceLengths: wrong nonce/key lengths must error, not
// panic.
func TestSealOpenRejectBadKeyNonceLengths(t *testing.T) {
	msg := []byte("x")
	for _, n := range []int{0, 1, NonceSize - 1, NonceSize + 1} {
		if _, err := Seal(msg, make([]byte, KeySize), make([]byte, n)); err == nil {
			t.Fatalf("Seal with %d-byte nonce should error", n)
		}
	}
	for _, n := range []int{0, 1, KeySize - 1, KeySize + 1} {
		// Nonce must be valid for the key-length error to surface distinctly.
		if _, err := Seal(msg, make([]byte, n), make([]byte, NonceSize)); err == nil {
			t.Fatalf("Seal with %d-byte key should error", n)
		}
	}
	ct, err := Seal(msg, make([]byte, KeySize), make([]byte, NonceSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ct, make([]byte, KeySize), make([]byte, NonceSize-1)); err == nil {
		t.Fatal("Open with short nonce should error")
	}
	if _, err := Open(ct, make([]byte, 0), make([]byte, NonceSize)); err == nil {
		t.Fatal("Open with empty key should error")
	}
}

// TestEmptyPlaintextSeals: the zero-length plaintext boundary is legal.
func TestEmptyPlaintextSeals(t *testing.T) {
	ct, err := Seal(nil, make([]byte, KeySize), make([]byte, NonceSize))
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 16 { // tag only
		t.Fatalf("empty ciphertext len = %d, want 16", len(ct))
	}
	pt, err := Open(ct, make([]byte, KeySize), make([]byte, NonceSize))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("empty open returned %d bytes", len(pt))
	}
}
