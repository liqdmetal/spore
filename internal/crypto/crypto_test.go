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
