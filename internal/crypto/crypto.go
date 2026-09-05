// Package crypto implements the ephemeral-key primitives for compostable
// messages: X25519 one-time ECDH, HKDF-SHA256 key derivation, and
// XChaCha20-Poly1305 authenticated encryption.
//
// Both the AEAD key and the nonce are DERIVED from the shared secret, never
// transmitted. This is safe because the shared secret is unique per message
// (a fresh ephemeral key each time), so no (key, nonce) pair is ever reused.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// NonceSize is the XChaCha20 nonce length (24 bytes).
const NonceSize = chacha20poly1305.NonceSizeX

// KeySize is the AEAD key length (32 bytes).
const KeySize = chacha20poly1305.KeySize

// KeyPair is an ephemeral X25519 keypair. Priv is owned by the caller so it
// can be erased after use.
type KeyPair struct {
	Priv []byte // 32-byte scalar; caller MUST Zero() it after use
	Pub  []byte // 32-byte X25519 public key
}

// GenerateKey returns a fresh ephemeral X25519 keypair.
func GenerateKey() (*KeyPair, error) {
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, err
	}
	return keyPairFromPriv(priv)
}

// KeyPairFromPriv reconstructs a keypair from a 32-byte scalar (used to load
// a persisted medium-term key).
func KeyPairFromPriv(priv []byte) (*KeyPair, error) {
	if len(priv) != 32 {
		return nil, errors.New("crypto: scalar must be 32 bytes")
	}
	return keyPairFromPriv(priv)
}

func keyPairFromPriv(priv []byte) (*KeyPair, error) {
	// NOTE: priv is often the CALLER's own buffer (a persisted scalar loaded via
	// KeyPairFromPriv / session / longmsg). Never Zero it here on failure —
	// wiping a caller's private key without consent is data loss, and it is
	// inconsistent with SharedSecret, which leaves the caller's scalars alone.
	// (ecdh.X25519 clamps scalars and only ever rejects a wrong length, which
	// callers gate before reaching this point, so the wipe would be dead code
	// anyway.)
	curve := ecdh.X25519()
	k, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Priv: priv, Pub: k.PublicKey().Bytes()}, nil
}

// SharedSecret computes the X25519 ECDH secret between our private scalar and
// the peer's 32-byte public key.
func SharedSecret(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != 32 || len(peerPub) != 32 {
		return nil, errors.New("crypto: scalar and pubkey must be 32 bytes")
	}
	curve := ecdh.X25519()
	k, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pk, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return k.ECDH(pk)
}

// DeriveKey expands the shared secret into a 32-byte AEAD key.
func DeriveKey(secret []byte) ([]byte, error) {
	return derive(secret, "compost/v1/key", KeySize)
}

// DeriveNonce expands the shared secret into a 24-byte XChaCha20 nonce.
func DeriveNonce(secret []byte) ([]byte, error) {
	return derive(secret, "compost/v1/nonce", NonceSize)
}

func derive(secret []byte, info string, n int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("crypto: empty secret")
	}
	h := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, n)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Seal encrypts plaintext with XChaCha20-Poly1305 under key/nonce.
func Seal(plaintext, key, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: nonce must be 24 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// Open decrypts and authenticates ciphertext. Any tamper or wrong key fails.
func Open(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: nonce must be 24 bytes")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// CID is the content address of a ciphertext: sha256(ciphertext). It doubles
// as both the off-chain retrieval key and the on-chain commitment.
func CID(ciphertext []byte) [32]byte {
	return sha256.Sum256(ciphertext)
}

// Zero overwrites a buffer. Best-effort in a GC'd language (the runtime may
// have copied the value), but it is the correct hygiene and the only lever a
// portable library has. True erasure additionally relies on process death.
func Zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
