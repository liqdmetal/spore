// Package secure provides end-to-end encryption AND sender authentication for
// spore messages on chains that do NOT natively encrypt payloads (EVM calldata,
// XMR payment id are public; only DERO encrypts to the recipient natively).
//
// Envelope v2 — the wire form is:
//
//	kind(1) || sigPub(32) || eph_pub(32) || nonce(24) || sig(64) || ciphertext
//
// where kind is 0xE1 (signed) and:
//
//	ciphertext   = XChaCha20-Poly1305(key, nonce, canonical_payload)
//	key          = HKDF-SHA256(X25519(eph_priv, recipient_pub),
//	                           info = "spore/e2e/v1/key" || eph_pub || recipient_pub)
//	sig          = Ed25519.Sign(sig_priv, transcript)
//	transcript   = "spore/env/v2" || sigPub || eph_pub || nonce
//	                              || recipient_pub || sha256(ciphertext)
//
// sigPub is the sender's Ed25519 public key, deterministically derived from the
// sender's X25519 identity scalar (see sigKeypair) so no second secret needs to
// be stored or exchanged: publish sigPub alongside the X25519 prekey and
// recipients pin it to attribute messages (T1 in ROADMAP-PRODUCTION.md).
//
// The signature binds the WHOLE envelope — sender key, ephemeral, nonce, the
// RECIPIENT's prekey, and the ciphertext — which kills:
//   - third-party impersonation (forging a message as someone else),
//   - cross-recipient replay (an envelope minted for Bob is provable as such
//     and fails verification when presented to Carol),
//   - ciphertext substitution (swap the body and the sig no longer verifies).
//
// The AEAD key is HKDF-bound to both public keys of the exchange (eph_pub and
// recipient_pub), so a key compromise cannot be laundered across identities
// (UKS resistance) and keys are cryptographically separated per peer pair.
//
// The nonce is a fresh random value transmitted in-band (it is public). The
// sender generates a fresh ephemeral key per message. The chain (and anyone
// scanning it) sees only ciphertext plus public keys — nobody but the
// recipient can read it, even on a chain that exposes calldata in the clear.
//
// Legacy v1 envelopes (kind 0xE0, unsigned: eph_pub || nonce || ciphertext)
// are still decryptable via Decrypt/Open for migration, but NewRecvCodec is
// STRICT: it refuses anything that is not a v2 signed envelope, which is what
// closes the plaintext-injection hole on public chains (see codec.go).
package secure

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/liqdmetal/spore/internal/crypto"
)

// Envelope layout constants.
const (
	PubLen   = 32
	NonceLen = 24
	SigLen   = ed25519.SignatureSize // 64
	// Overhead = sigPub(32) + pub(32) + nonce(24) + sig(64) + AEAD tag(16),
	// excluding the leading kind byte.
	Overhead = PubLen + PubLen + NonceLen + SigLen + 16
)

// Envelope kind bytes (the first byte of a wire payload).
const (
	// EnvelopeKindPrefix is the LEGACY v1 kind (unsigned). Still decryptable
	// for migration; the strict codec rejects it.
	EnvelopeKindPrefix = 0xE0
	// EnvelopeKindSigned is the v2 kind: sender-signed envelope.
	EnvelopeKindSigned = 0xE1
)

// ErrDecrypt is returned when an envelope cannot be decrypted (wrong key,
// tamper, or not an envelope).
var ErrDecrypt = errors.New("secure: cannot decrypt envelope")

// ErrSig is returned when a signed envelope's Ed25519 signature does not
// verify (forgery, tamper, or cross-recipient replay).
var ErrSig = errors.New("secure: sender signature invalid")

// sigKeypair derives the sender's Ed25519 signing keypair deterministically
// from their 32-byte X25519 identity scalar, so one secret at rest yields both
// the encryption key and the signing key (they live and die together by
// design; publishing SigPubOf(priv) alongside the X25519 pub is all the
// out-of-band key exchange a recipient needs).
func sigKeypair(identityPriv []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(identityPriv) != 32 {
		return nil, nil, fmt.Errorf("secure: identity priv must be 32 bytes (got %d)", len(identityPriv))
	}
	seed := sha256.Sum256(append([]byte("spore/sig/v1/seed"), identityPriv...))
	k := ed25519.NewKeyFromSeed(seed[:])
	return k, k.Public().(ed25519.PublicKey), nil
}

// SigPubOf returns the Ed25519 public key (32 bytes) that Encrypt signs with
// for this identity — what senders publish and recipients pin.
func SigPubOf(identityPriv []byte) ([]byte, error) {
	_, pub, err := sigKeypair(identityPriv)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), pub...), nil
}

// Encrypt wraps a canonical spore payload into a signed transport envelope for
// the recipient. senderPriv is our long-term X25519 scalar (it also derives
// our Ed25519 signing key); recipientPub is theirs. Returns the full wire
// payload INCLUDING the 0xE1 kind byte.
func Encrypt(senderPriv, recipientPub, canonical []byte) ([]byte, error) {
	if len(senderPriv) != 32 || len(recipientPub) != 32 {
		return nil, fmt.Errorf("secure: keys must be 32 bytes (got %d/%d)", len(senderPriv), len(recipientPub))
	}
	eph, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(eph.Priv)
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return EncryptDeterministic(eph.Priv, nonce, senderPriv, recipientPub, canonical)
}

// EncryptDeterministic is Encrypt with caller-supplied ephemeral scalar and
// nonce. Production code must use Encrypt (fresh randomness); this variant
// exists for the WIRE SPEC test vectors (docs/WIRE_SPEC.md) and for testing —
// fixed inputs make the whole envelope reproducible across implementations.
func EncryptDeterministic(ephPriv, nonce, senderPriv, recipientPub, canonical []byte) ([]byte, error) {
	if len(senderPriv) != 32 || len(recipientPub) != 32 || len(ephPriv) != 32 || len(nonce) != NonceLen {
		return nil, fmt.Errorf("secure: keys must be 32 bytes, nonce %d bytes", NonceLen)
	}
	sigPriv, sigPub, err := sigKeypair(senderPriv)
	if err != nil {
		return nil, err
	}
	ephPub, err := PubKeyOf(ephPriv)
	if err != nil {
		return nil, err
	}
	secret, err := crypto.SharedSecret(ephPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(secret)
	return sealWith(sigPriv, sigPub, ephPub, recipientPub, secret, canonical, nonce)
}

// sealWith derives the AEAD key (bound to both public keys), seals the
// canonical payload under a fresh random nonce, signs the transcript, and
// assembles the kind-prefixed v2 envelope.
func sealWith(sigPriv ed25519.PrivateKey, sigPub, ephPub, recipientPub, secret, canonical, nonce []byte) ([]byte, error) {
	key, err := crypto.DeriveKeyBound(secret, ephPub, recipientPub)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	// The nonce is caller-supplied (Encrypt generates a fresh random one; the
	// wire-spec vectors fix it). Random-per-message nonces keep every envelope
	// safe even if an ECDH secret were ever reused.
	ct, err := crypto.Seal(canonical, key, nonce)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(sigPriv, transcript(sigPub, ephPub, nonce, recipientPub, ct))
	out := make([]byte, 0, 1+Overhead-16+len(ct))
	out = append(out, EnvelopeKindSigned)
	out = append(out, sigPub...)
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, sig...)
	out = append(out, ct...)
	return out, nil
}

// transcript is the exact byte string the sender signs. It binds the sender's
// signing key, the ephemeral key, the nonce, the RECIPIENT's prekey, and the
// ciphertext — nothing about the envelope can be moved, swapped, or replayed
// to another recipient without invalidating the signature.
func transcript(sigPub, ephPub, nonce, recipientPub, ct []byte) []byte {
	ctHash := sha256.Sum256(ct)
	msg := make([]byte, 0, len("spore/env/v2")+32+32+24+32+32)
	msg = append(msg, "spore/env/v2"...)
	msg = append(msg, sigPub...)
	msg = append(msg, ephPub...)
	msg = append(msg, nonce...)
	msg = append(msg, recipientPub...)
	msg = append(msg, ctHash[:]...)
	return msg
}

// Open unwraps a wire payload (with kind byte) with our private key. Returns
// the inner canonical payload and the sender's Ed25519 public key (nil for
// unsigned legacy envelopes). The signature is verified BEFORE the payload is
// trusted; a bad signature aborts regardless of AEAD success.
func Open(ourPriv, p []byte) (plain, senderSigPub []byte, err error) {
	if len(ourPriv) != 32 {
		return nil, nil, fmt.Errorf("secure: priv must be 32 bytes (got %d)", len(ourPriv))
	}
	if len(p) < 1 {
		return nil, nil, fmt.Errorf("%w: empty payload", ErrDecrypt)
	}
	switch p[0] {
	case EnvelopeKindSigned:
		return openSigned(ourPriv, p[1:])
	case EnvelopeKindPrefix:
		// Legacy v1: unsigned. Decryptable for migration only.
		pt, err := openLegacy(ourPriv, p[1:])
		return pt, nil, err
	default:
		return nil, nil, fmt.Errorf("%w: unknown kind byte 0x%02x", ErrDecrypt, p[0])
	}
}

// Decrypt unwraps a wire payload with our private key, verifying the sender
// signature when present. Returns the inner canonical payload.
func Decrypt(ourPriv, p []byte) ([]byte, error) {
	pt, _, err := Open(ourPriv, p)
	return pt, err
}

func openSigned(ourPriv, body []byte) (plain, senderSigPub []byte, err error) {
	if len(body) < Overhead-16 {
		return nil, nil, fmt.Errorf("%w: signed envelope too short (%d)", ErrDecrypt, len(body))
	}
	sigPub := body[:32]
	ephPub := body[32 : 32+PubLen]
	nonce := body[32+PubLen : 32+PubLen+NonceLen]
	sig := body[32+PubLen+NonceLen : 32+PubLen+NonceLen+SigLen]
	ct := body[32+PubLen+NonceLen+SigLen:]

	ourPub, err := PubKeyOf(ourPriv)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(sigPub), transcript(sigPub, ephPub, nonce, ourPub, ct), sig) {
		return nil, nil, ErrSig
	}
	secret, err := crypto.SharedSecret(ourPriv, ephPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	defer crypto.Zero(secret)
	key, err := crypto.DeriveKeyBound(secret, ephPub, ourPub)
	if err != nil {
		return nil, nil, err
	}
	defer crypto.Zero(key)
	pt, err := crypto.Open(ct, key, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return pt, append([]byte(nil), sigPub...), nil
}

func openLegacy(ourPriv, body []byte) ([]byte, error) {
	if len(body) < PubLen+NonceLen+16 {
		return nil, fmt.Errorf("%w: envelope too short (%d)", ErrDecrypt, len(body))
	}
	ephPub := body[:PubLen]
	nonce := body[PubLen : PubLen+NonceLen]
	ct := body[PubLen+NonceLen:]
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

// HasEnvelopeKind reports whether p begins with a recognized envelope magic
// (signed 0xE1 or legacy 0xE0).
func HasEnvelopeKind(p []byte) bool {
	return len(p) > 0 && (p[0] == EnvelopeKindSigned || p[0] == EnvelopeKindPrefix)
}

// HasSignedKind reports whether p begins with the v2 signed-envelope magic.
func HasSignedKind(p []byte) bool { return len(p) > 0 && p[0] == EnvelopeKindSigned }

// StripKind removes the leading kind byte (any kind).
func StripKind(p []byte) []byte {
	if HasEnvelopeKind(p) {
		return p[1:]
	}
	return p
}

// PrependKind tags a raw body with the signed kind byte. Kept for callers that
// assemble envelopes manually (tests, tooling); Encrypt already returns a
// kind-prefixed payload.
func PrependKind(env []byte) []byte {
	out := make([]byte, 0, 1+len(env))
	out = append(out, EnvelopeKindSigned)
	out = append(out, env...)
	return out
}
