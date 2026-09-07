// SecureCodec wraps a base codec (canonical or DERO) so that every payload the
// chain carries is a SIGNED, E2E-encrypted envelope, never plaintext. This is
// the hardening that makes EVM/XMR (public calldata/payment-id) as private as
// DERO's native encryption — and, in strict mode (the default for public
// chains), makes impersonation and plaintext injection impossible: only
// sender-signed v2 envelopes decode.
package secure

import (
	"crypto/ed25519"
	"encoding/hex"
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
// (recipientPub); the envelope is signed with the Ed25519 key derived from
// senderKey. For RECEIVING it needs our priv to decrypt + verify; the
// recipient pub is unused on receive.
//
// Receive strictness:
//
//   - strict=true (default, NewRecvCodec): ONLY kind-0xE1 signed envelopes
//     decode. Anything else — legacy 0xE0 envelopes, canonical plaintext, a
//     DERO native payload — is refused. This is the public-chain posture: an
//     attacker who sees your calldata cannot inject unsigned messages into
//     your inbox.
//   - strict=false (NewRecvCodecLegacy): signed envelopes, legacy envelopes,
//     and non-envelope payloads (passing through to the inner codec) all
//     decode. Use ONLY where the inner codec's secrecy is native and trusted
//     (DERO's point-to-point payload encryption) or for explicit migration.
type Codec struct {
	// inner is the plaintext codec used to build/parse the cleartext payload
	// inside the envelope.
	inner whisper.Codec
	// senderKey is our persistent X25519 private key (for sending).
	senderKey []byte
	// recipientPub is the target's public key (for sending).
	recipientPub []byte
	// strict: refuse anything but a signed v2 envelope on receive.
	strict bool
	// pinned is the recipient's contact list of Ed25519 sender signing keys
	// (hex). When non-empty, ONLY envelopes signed by a pinned key decode —
	// this is what turns signature validity into attribution (T1): Mallory
	// can sign with her own key, but her mail simply never arrives once the
	// recipient pins who they accept. Empty = accept any valid signature.
	pinned map[string]bool
}

// Pin adds a sender's Ed25519 signing public key (from SigPubOf, hex or raw —
// raw 32-byte is accepted and hex-encoded internally) to the accept list.
// Once at least one key is pinned, unpinned senders are refused. Pass the hex
// 'sig' line printed by keygen / msg keygen.
func (c *Codec) Pin(sigPub []byte) {
	if c.pinned == nil {
		c.pinned = map[string]bool{}
	}
	if len(sigPub) == ed25519.PublicKeySize {
		enc := make([]byte, 64)
		hex.Encode(enc, sigPub)
		sigPub = enc
	}
	c.pinned[string(sigPub)] = true
}

// NewCodec builds a secure codec over inner. senderKey is required (the sender
// encrypts and signs with it; the receiver decrypts and verifies with it).
// recipientPub is required for sending but may be nil when only receiving.
// The codec is created in NON-strict mode; prefer NewSendCodec/NewRecvCodec.
func NewCodec(inner whisper.Codec, senderKey []byte, recipientPub []byte) *Codec {
	return &Codec{inner: inner, senderKey: senderKey, recipientPub: recipientPub, strict: false}
}

// NewSendCodec is a convenience: sender-only codec (encrypt + sign to
// recipientPub).
func NewSendCodec(inner whisper.Codec, senderKey, recipientPub []byte) (*Codec, error) {
	if len(senderKey) != 32 || len(recipientPub) != 32 {
		return nil, fmt.Errorf("%w: send needs 32-byte -key and -peer-pub", ErrNoKey)
	}
	return &Codec{inner: inner, senderKey: senderKey, recipientPub: recipientPub, strict: false}, nil
}

// NewRecvCodec builds a STRICT receiver-only codec (decrypt + verify with our
// key): only kind-0xE1 signed envelopes decode. This is the default for
// public-chain inboxes — plaintext and legacy payloads are refused, closing
// the injection hole.
func NewRecvCodec(inner whisper.Codec, ourKey []byte) (*Codec, error) {
	if len(ourKey) != 32 {
		return nil, fmt.Errorf("%w: recv needs 32-byte -key", ErrNoKey)
	}
	return &Codec{inner: inner, senderKey: ourKey, strict: true}, nil
}

// NewRecvCodecLegacy builds a receiver-only codec that also accepts legacy
// unsigned envelopes and non-envelope payloads via the inner codec. Use only
// where the inner codec's secrecy is native and trusted (DERO) or for
// explicit migration windows.
func NewRecvCodecLegacy(inner whisper.Codec, ourKey []byte) (*Codec, error) {
	c, err := NewRecvCodec(inner, ourKey)
	if err != nil {
		return nil, err
	}
	c.strict = false
	return c, nil
}

// EncodeText implements whisper.Codec: encrypts the canonical text to
// recipientPub (and signs it).
func (c *Codec) EncodeText(text string) (chain.Payload, error) {
	if c.recipientPub == nil {
		return nil, ErrNoKey
	}
	plain, err := c.inner.EncodeText(text)
	if err != nil {
		return nil, err
	}
	return Encrypt(c.senderKey, c.recipientPub, plain)
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
	return Encrypt(c.senderKey, c.recipientPub, plain)
}

// DecodeText implements whisper.Codec: decrypts and verifies an envelope, then
// decodes text. In strict mode, only signed envelopes decode.
func (c *Codec) DecodeText(p chain.Payload) (string, bool) {
	plain, ok := c.unwrap(p)
	if !ok {
		return "", false
	}
	return c.inner.DecodeText(plain)
}

// DecodeTextSender is DecodeText plus sender attribution: on success it also
// returns the Ed25519 public key the envelope was signed with, which the
// recipient pins against their contact list (the signature proves the message
// was minted by the holder of that identity; the pinning decision is the
// recipient's). sigPub is nil for legacy unsigned envelopes.
func (c *Codec) DecodeTextSender(p chain.Payload) (text string, senderSigPub []byte, ok bool) {
	plain, sigPub, ok := c.unwrapSender(p)
	if !ok {
		return "", nil, false
	}
	text, tok := c.inner.DecodeText(plain)
	return text, sigPub, tok
}

// DecodePointer implements whisper.Codec.
func (c *Codec) DecodePointer(p chain.Payload) ([32]byte, [32]byte, bool) {
	plain, ok := c.unwrap(p)
	if !ok {
		return [32]byte{}, [32]byte{}, false
	}
	return c.inner.DecodePointer(plain)
}

// DecodePointerSender is DecodePointer plus sender attribution (see
// DecodeTextSender).
func (c *Codec) DecodePointerSender(p chain.Payload) (ephPub, bodyCID [32]byte, senderSigPub []byte, ok bool) {
	plain, sigPub, ok := c.unwrapSender(p)
	if !ok {
		return [32]byte{}, [32]byte{}, nil, false
	}
	eph, cid, tok := c.inner.DecodePointer(plain)
	return eph, cid, sigPub, tok
}

// unwrap decrypts p, enforcing the codec's strictness policy.
func (c *Codec) unwrap(p chain.Payload) ([]byte, bool) {
	plain, _, ok := c.unwrapSender(p)
	return plain, ok
}

// unwrapSender decrypts p and returns the sender's signing key when the
// payload is a signed envelope, enforcing the strictness policy.
func (c *Codec) unwrapSender(p chain.Payload) (plain, senderSigPub []byte, ok bool) {
	if !HasEnvelopeKind(p) {
		// Not an envelope (e.g. DERO native plaintext whisper, or an SC msg).
		// STRICT mode refuses it outright; legacy mode passes it through so
		// the inner codec can try.
		if c.strict {
			return nil, nil, false
		}
		return p, nil, true
	}
	if c.senderKey == nil {
		return nil, nil, false
	}
	plain, sigPub, err := Open(c.senderKey, p)
	if err != nil {
		return nil, nil, false
	}
	// STRICT mode additionally refuses legacy unsigned envelopes even though
	// they decrypt: on a public chain an unsigned payload is an injection
	// attempt, not an old friend.
	if c.strict && !HasSignedKind(p) {
		return nil, nil, false
	}
	// Contact pinning: when the recipient has pinned any sender keys, only
	// envelopes signed by a pinned identity decode at all. This enforces
	// attribution instead of merely exposing it.
	if len(c.pinned) > 0 {
		if sigPub == nil {
			return nil, nil, false
		}
		hexKey := make([]byte, 64)
		hex.Encode(hexKey, sigPub)
		if !c.pinned[string(hexKey)] {
			return nil, nil, false
		}
	}
	return plain, sigPub, true
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
