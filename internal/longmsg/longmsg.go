// Package longmsg is Model-A long-message delivery: an encrypted body that
// never touches a block or a third-party store, fetched peer-to-peer when both
// parties are online. A whisper/anchor carries only the pointer (sender
// ephemeral pub + body CID); the body stays sender-side until the recipient
// pulls it over rendezvous, then keys rotate + erase.
//
// This is the "nobody but sender and receiver, ever" path. Bulk content never
// rides the 111-byte whisper; the whisper is the signal.
package longmsg

import (
	"errors"
	"time"

	"github.com/liqdmetal/mycelium/internal/crypto"
	"github.com/liqdmetal/mycelium/internal/store"
)

// Endpoint is one party's long-message state. It owns its long-term X25519
// key (used to encrypt bodies to a recipient) and a durable store where it
// holds bodies it has sent (outbound, until fetched) or received.
type Endpoint struct {
	key   *crypto.KeyPair
	store store.Store
}

// NewEndpoint builds an endpoint with a fresh long-term key.
func NewEndpoint(st store.Store) (*Endpoint, error) {
	k, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Endpoint{key: k, store: st}, nil
}

// NewEndpointFromPriv restores an endpoint from a persisted 32-byte long-term
// scalar (so a receiver can decrypt long bodies across restarts).
func NewEndpointFromPriv(st store.Store, priv []byte) (*Endpoint, error) {
	kp, err := crypto.KeyPairFromPriv(priv)
	if err != nil {
		return nil, err
	}
	return &Endpoint{key: kp, store: st}, nil
}

// PrivKey returns a copy of the long-term scalar, for persistence.
func (e *Endpoint) PrivKey() []byte {
	out := make([]byte, 32)
	copy(out, e.key.Priv)
	return out
}

// PublicKey returns our long-term public key; senders encrypt bodies to it.
func (e *Endpoint) PublicKey() []byte { return e.key.Pub }

// Pointer is what the whisper/anchor carries on-chain: sender ephemeral pub +
// body CID + deadline. Nothing else. It points at a body held by the sender.
type Pointer struct {
	EphemeralPub [32]byte
	CID          [32]byte
	BurnDeadline uint64
}

// BodyPaddingBucket is the fixed size bucket long bodies are padded to before
// encryption, so all ciphertext bodies are indistinguishable by size (defeats
// size-based fingerprinting of message length). A body is padded up to the next
// multiple of this bucket with 0x00 bytes; a length-prefix header lets the
// receiver strip exactly the padding.
const BodyPaddingBucket = 1024

// padBody returns plaintext padded to a multiple of BodyPaddingBucket, prefixed
// with the original length (8 bytes, little-endian) so ReceiveBody can strip it.
// Format: [orig_len:8][plaintext][0x00 padding].
func padBody(plaintext []byte) []byte {
	header := 8
	total := header + len(plaintext)
	bucket := BodyPaddingBucket
	rounded := (total + bucket - 1) / bucket * bucket
	out := make([]byte, rounded)
	for i := 0; i < 8; i++ {
		out[i] = byte(len(plaintext) >> (8 * i))
	}
	copy(out[header:], plaintext)
	return out
}

// unpadBody reverses padBody, returning just the original plaintext.
func unpadBody(padded []byte) ([]byte, error) {
	if len(padded) < 8 {
		return nil, errors.New("longmsg: body too short to unpad")
	}
	n := 0
	for i := 0; i < 8; i++ {
		n |= int(padded[i]) << (8 * i)
	}
	if n < 0 || 8+n > len(padded) {
		return nil, errors.New("longmsg: bad padding length")
	}
	return padded[8 : 8+n], nil
}

// SendBody encrypts plaintext to the recipient's long-term pub under a fresh
// ephemeral key, stores the ciphertext locally (the sender holds its own
// outbound), and returns the pointer to put in a whisper. The sender erases
// the ephemeral secret after storing — only the recipient (who shares ECDH
// with that ephemeral) can decrypt, and only while the body is retained.
func (e *Endpoint) SendBody(recipientPub, plaintext []byte, ttl time.Duration) (*Pointer, error) {
	if len(recipientPub) != 32 {
		return nil, errors.New("longmsg: recipient pub must be 32 bytes")
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
	key, err := crypto.DeriveKey(secret)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(key)
	nonce, err := crypto.DeriveNonce(secret)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.Seal(padBody(plaintext), key, nonce)
	if err != nil {
		return nil, err
	}
	cid := crypto.CID(ct)
	if err := e.store.Put(cid, ct, time.Now().Add(ttl)); err != nil {
		return nil, err
	}
	var ptr Pointer
	copy(ptr.EphemeralPub[:], eph.Pub)
	ptr.CID = cid
	ptr.BurnDeadline = uint64(time.Now().Add(ttl).Unix())
	return &ptr, nil
}

// ReceiveBody fetches the body the pointer references from the peer (via a
// rendezvous FetchFunc), verifies its CID + not-yet-burned, and decrypts it
// with our long-term key + the sender's ephemeral pub. Returns the plaintext.
func (e *Endpoint) ReceiveBody(p *Pointer, fetch func(cid [32]byte) ([]byte, error)) ([]byte, error) {
	if p.BurnDeadline > 0 && time.Now().Unix() > int64(p.BurnDeadline) {
		return nil, errors.New("longmsg: message burned (past deadline)")
	}
	ct, err := fetch(p.CID)
	if err != nil {
		return nil, err
	}
	if crypto.CID(ct) != p.CID {
		return nil, errors.New("longmsg: body CID mismatch")
	}
	secret, err := crypto.SharedSecret(e.key.Priv, p.EphemeralPub[:])
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
	plain, err := crypto.Open(ct, key, nonce)
	if err != nil {
		return nil, err
	}
	return unpadBody(plain)
}

// Store exposes the endpoint's durable store (used by a rendezvous server to
// serve outbound bodies to the recipient).
func (e *Endpoint) Store() store.Store { return e.store }
