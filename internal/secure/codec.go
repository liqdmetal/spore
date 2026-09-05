// SecureCodec wraps a base codec (canonical or DERO) so that every payload the
// chain carries is an ECDH-encrypted envelope, never plaintext. This is the
// hardening that makes EVM/XMR (public calldata/payment-id) as private as
// DERO's native encryption.
package secure

import (
	"errors"
	"fmt"

	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/whisper"
)

// ErrNoKey is returned when the codec is missing a needed key.
var ErrNoKey = errors.New("secure: codec missing key (sender needs -key and -peer-pub; receiver needs -key)")

// Codec is a secure wrapper around a base whisper.Codec.
//
// For SENDING it needs our priv (senderKey) + the recipient's pub
// (recipientPub). For RECEIVING it needs our priv to decrypt envelopes others
// send us; the recipient pub is unused on receive.
type Codec struct {
	// inner is the plaintext codec used to build/parse the cleartext payload
	// inside the envelope.
	inner whisper.Codec
	// senderKey is our persistent X25519 private key (for sending).
	senderKey []byte
	// recipientPub is the target's public key (for sending).
	recipientPub []byte
}

// NewCodec builds a secure codec over inner. senderKey is required (the sender
// encrypts with it via a fresh ephemeral; the receiver decrypts with it).
// recipientPub is required for sending but may be nil when only receiving.
func NewCodec(inner whisper.Codec, senderKey []byte, recipientPub []byte) *Codec {
	return &Codec{inner: inner, senderKey: senderKey, recipientPub: recipientPub}
}

// NewSendCodec is a convenience: sender-only codec (encrypt to recipientPub).
func NewSendCodec(inner whisper.Codec, senderKey, recipientPub []byte) (*Codec, error) {
	if len(senderKey) != 32 || len(recipientPub) != 32 {
		return nil, fmt.Errorf("%w: send needs 32-byte -key and -peer-pub", ErrNoKey)
	}
	return NewCodec(inner, senderKey, recipientPub), nil
}

// NewRecvCodec is a convenience: receiver-only codec (decrypt with our key).
func NewRecvCodec(inner whisper.Codec, ourKey []byte) (*Codec, error) {
	if len(ourKey) != 32 {
		return nil, fmt.Errorf("%w: recv needs 32-byte -key", ErrNoKey)
	}
	return NewCodec(inner, ourKey, nil), nil
}

// EncodeText implements whisper.Codec: encrypts the canonical text to
// recipientPub.
func (c *Codec) EncodeText(text string) (chain.Payload, error) {
	if c.recipientPub == nil {
		return nil, ErrNoKey
	}
	plain, err := c.inner.EncodeText(text)
	if err != nil {
		return nil, err
	}
	env, err := Encrypt(c.senderKey, c.recipientPub, plain)
	if err != nil {
		return nil, err
	}
	return PrependKind(env), nil
}

// EncodePointer implements whisper.Codec.
func (c *Codec) EncodePointer(ephPub, bodyCID [32]byte) (chain.Payload, error) {
	if c.recipientPub == nil {
		return nil, ErrNoKey
	}
	plain, err := c.inner.EncodePointer(ephPub, bodyCID)
	if err != nil {
		return nil, err
	}
	env, err := Encrypt(c.senderKey, c.recipientPub, plain)
	if err != nil {
		return nil, err
	}
	return PrependKind(env), nil
}

// DecodeText implements whisper.Codec: decrypts an envelope, then decodes text.
// Non-envelope payloads (legacy/plaintext) are passed through to inner so old
// DERO whispers still decode.
func (c *Codec) DecodeText(p chain.Payload) (string, bool) {
	plain, ok := c.unwrap(p)
	if !ok {
		return "", false
	}
	return c.inner.DecodeText(plain)
}

// DecodePointer implements whisper.Codec.
func (c *Codec) DecodePointer(p chain.Payload) ([32]byte, [32]byte, bool) {
	plain, ok := c.unwrap(p)
	if !ok {
		return [32]byte{}, [32]byte{}, false
	}
	return c.inner.DecodePointer(plain)
}

// unwrap decrypts p if it is an envelope; returns inner plaintext. Legacy
// plaintext payloads (not envelope-kind) pass through untouched so existing
// DERO whispers still decode.
func (c *Codec) unwrap(p chain.Payload) ([]byte, bool) {
	if !HasEnvelopeKind(p) {
		// Not one of ours (e.g. native DERO plaintext whisper, or an SC msg) —
		// pass through so the inner codec can try.
		return p, true
	}
	if c.senderKey == nil {
		return nil, false
	}
	env := StripKind(p)
	plain, err := Decrypt(c.senderKey, env)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// PubKeyOf derives the public half of a 32-byte X25519 private key (for
// keygen output / display).
func PubKeyOf(priv []byte) ([]byte, error) {
	kp, err := crypto.KeyPairFromPriv(priv)
	if err != nil {
		return nil, err
	}
	return kp.Pub, nil
}
