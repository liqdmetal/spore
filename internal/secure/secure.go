// Package secure provides end-to-end encryption for mycelium messages on
// chains that do NOT natively encrypt payloads (EVM calldata, XMR payment id
// are public; only DERO encrypts to the recipient natively).
//
// Design: every chain carries an opaque, self-contained envelope:
//
//	eph_pub(32) || nonce(24) || ciphertext
//
//	ciphertext = XChaCha20-Poly1305(key, nonce, canonical_payload), where the
//	AEAD key is HKDF-derived from ECDH(sender_priv, recipient_pub) and the 24-byte
//	nonce is a fresh random value transmitted in-band (it is public). The sender
//	generates a fresh ephemeral key per message; the recipient derives the same
//	secret from their own priv + the on-wire eph_pub. So the chain (and anyone
//	scanning it) sees only ciphertext — nobody but the recipient can read it,
//	even on a chain that exposes calldata in the clear.
//
// The envelope is what the chain.Chain carries (its Payload). Content
// semantics (text vs pointer) live inside the ciphertext via the canonical
// codec.
package secure

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/liqdmetal/mycelium/internal/crypto"
)

// Envelope layout.
const (
	PubLen   = 32
	NonceLen = 24
	// Overhead = pub(32) + nonce(24) + AEAD tag(16).
	Overhead = PubLen + NonceLen + 16
)

// ErrDecrypt is returned when an envelope cannot be decrypted (wrong key,
// tamper, or not an envelope).
var ErrDecrypt = errors.New("secure: cannot decrypt envelope")

// Encrypt wraps a canonical mycelium payload into a transport envelope for the
// recipient. senderPriv is our long-term key; recipientPub is theirs.
func Encrypt(senderPriv, recipientPub, canonical []byte) ([]byte, error) {
	if len(senderPriv) != 32 || len(recipientPub) != 32 {
		return nil, fmt.Errorf("secure: keys must be 32 bytes (got %d/%d)", len(senderPriv), len(recipientPub))
	}
	eph, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(eph.Priv)
	secret, err := crypto.SharedSecret(eph.Priv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(secret)
	return sealWith(eph.Pub, secret, canonical)
}

// EncryptStatic is like Encrypt but uses senderPriv directly for ECDH (no
// fresh ephemeral per message). It exists for tests / long-lived streams where
// one keypair is reused. Each message still gets a fresh random nonce (see
// sealWith), so no (key, nonce) pair is ever repeated. NOTE: static ECDH means
// the SAME AEAD key is derived for every message — XChaCha20 is safe under key
// reuse only with unique nonces (true here), but there is no forward secrecy
// and no per-message separation. Use Encrypt, never this, for real traffic.
func EncryptStatic(senderPriv, recipientPub, canonical []byte) ([]byte, error) {
	if len(senderPriv) != 32 || len(recipientPub) != 32 {
		return nil, fmt.Errorf("secure: keys must be 32 bytes (got %d/%d)", len(senderPriv), len(recipientPub))
	}
	secret, err := crypto.SharedSecret(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(secret)
	_, pub, _ := pubOf(senderPriv)
	return sealWith(pub, secret, canonical)
}

func pubOf(priv []byte) (kp *crypto.KeyPair, pub []byte, err error) {
	kp, err = crypto.KeyPairFromPriv(priv)
	if err != nil {
		return nil, nil, err
	}
	return kp, kp.Pub, nil
}

func sealWith(ephPub, secret, canonical []byte) ([]byte, error) {
	key, err := crypto.DeriveKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	// The nonce is random and transmitted in-band (it need not be secret). We
	// deliberately do NOT derive it from the secret: a sender that ever reuses
	// an ECDH secret (see EncryptStatic) would otherwise silently re-encrypt
	// under an identical (key, nonce) — a catastrophic two-time pad. A fresh
	// random nonce per message keeps every envelope safe regardless of secret
	// reuse, and Decrypt already reads the nonce from the envelope.
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(canonical, key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, PubLen+NonceLen+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt unwraps an envelope with our private key. Returns the inner
// canonical payload.
func Decrypt(ourPriv, env []byte) ([]byte, error) {
	if len(ourPriv) != 32 {
		return nil, fmt.Errorf("secure: priv must be 32 bytes (got %d)", len(ourPriv))
	}
	if len(env) < PubLen+NonceLen+16 {
		return nil, fmt.Errorf("%w: envelope too short (%d)", ErrDecrypt, len(env))
	}
	ephPub := env[:PubLen]
	nonce := env[PubLen : PubLen+NonceLen]
	ct := env[PubLen+NonceLen:]
	secret, err := crypto.SharedSecret(ourPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	defer crypto.Zero(secret)
	key, err := crypto.DeriveKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	pt, err := crypto.Open(ct, key, nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return pt, nil
}

// EnvelopeKindPrefix is a 1-byte magic so a recipient can cheaply tell an
// envelope from a raw canonical payload (e.g. old messages).
const EnvelopeKindPrefix = 0xE0

// PrependKind tags the envelope with a kind byte (EnvelopeKindPrefix) so
// receivers can distinguish encrypted envelopes from legacy plaintext. Returns
// kind || env.
func PrependKind(env []byte) []byte {
	out := make([]byte, 0, 1+len(env))
	out = append(out, EnvelopeKindPrefix)
	out = append(out, env...)
	return out
}

// HasEnvelopeKind reports whether p begins with the envelope magic.
func HasEnvelopeKind(p []byte) bool { return len(p) > 0 && p[0] == EnvelopeKindPrefix }

// StripKind removes the leading kind byte.
func StripKind(p []byte) []byte {
	if HasEnvelopeKind(p) {
		return p[1:]
	}
	return p
}
