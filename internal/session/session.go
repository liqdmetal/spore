// Package session binds the layers into a working endpoint: a medium-term
// X25519 key (rotated, previous one kept as a grace window), the off-chain
// store, and send/receive with per-message ephemeral keys that are erased
// after use.
//
// Lifecycle that produces "compost":
//
//	send:   one-time (a,aG) → ECDH with recipient's (bG) → derive key+nonce
//	        → encrypt body → store body off-chain w/ TTL → build on-chain
//	        anchor (aG, CID, deadline) → erase a.
//	recv:   read anchor → fetch body by CID → ECDH with own b (or prev b) →
//	        derive key+nonce → decrypt → erase b on rotation.
//
// Once both sides erase their ephemeral secrets, the on-chain anchor is inert
// and the off-chain body is evicted — unrecoverable by anyone, including the
// participants.
package session

import (
	"errors"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/store"
)

// Endpoint is one party's messenger state.
type Endpoint struct {
	store store.Store

	key     *crypto.KeyPair // current medium-term key (advertised as bG)
	prevKey *crypto.KeyPair // grace window for in-flight messages
}

// New creates an endpoint with a fresh medium-term key.
func New(st store.Store) (*Endpoint, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Endpoint{store: st, key: key}, nil
}

// NewFromPriv restores an endpoint from a persisted 32-byte medium-term
// scalar (so the recipient can decrypt after a restart).
func NewFromPriv(st store.Store, priv []byte) (*Endpoint, error) {
	key, err := crypto.KeyPairFromPriv(priv)
	if err != nil {
		return nil, err
	}
	return &Endpoint{store: st, key: key}, nil
}

// PublicKey returns the endpoint's current medium-term public key (bG).
// Senders encrypt to this. It must be published out-of-band or via a
// KEYROTATE anchor.
func (e *Endpoint) PublicKey() []byte {
	return e.key.Pub
}

// PrivKey returns a copy of the current medium-term scalar, for persistence.
func (e *Endpoint) PrivKey() []byte {
	out := make([]byte, 32)
	copy(out, e.key.Priv)
	return out
}

// Rotate generates a new medium-term key, demoting the current one to the
// grace window and erasing the previous grace key. Messages encrypted to the
// old key still decrypt until the next rotation.
func (e *Endpoint) Rotate() error {
	key, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	if e.prevKey != nil {
		crypto.Zero(e.prevKey.Priv)
	}
	e.prevKey = e.key
	e.key = key
	return nil
}

// Send encrypts plaintext to peerPub (the recipient's medium-term key), stores
// the ciphertext off-chain with a TTL, and returns the on-chain anchor to
// post. The sender's ephemeral secret is erased before returning.
func (e *Endpoint) Send(peerPub, plaintext []byte, ttl time.Duration, requestAck bool) (*anchor.Anchor, error) {
	if len(peerPub) != 32 {
		return nil, errors.New("session: peer pubkey must be 32 bytes")
	}
	eph, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(eph.Priv)

	secret, err := crypto.SharedSecret(eph.Priv, peerPub)
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
	cid := crypto.CID(ct)
	deadline := time.Now().Add(ttl)
	if err := e.store.Put(cid, ct, deadline); err != nil {
		return nil, err
	}

	a := &anchor.Anchor{
		Version:      anchor.Version,
		Kind:         anchor.KindMessage,
		BurnDeadline: uint64(deadline.Unix()),
	}
	copy(a.EphemeralPub[:], eph.Pub)
	a.CID = cid
	if requestAck {
		a.Flags |= anchor.FlagAckRequested
	}
	return a, nil
}

// Receive fetches the body referenced by the anchor and decrypts it. It
// enforces the burn deadline and rejects expired messages.
func (e *Endpoint) Receive(a *anchor.Anchor) ([]byte, error) {
	if a.Kind != anchor.KindMessage {
		return nil, errors.New("session: not a message anchor")
	}
	if a.Expired(time.Now()) {
		return nil, errors.New("session: message burned")
	}
	ct, err := e.store.Get(a.CID)
	if err != nil {
		return nil, err
	}
	return e.decrypt(a, ct)
}

// decrypt tries the current key, then the grace key. A wrong key produces an
// AEAD failure — indistinguishable from a tampered body, which is the point.
func (e *Endpoint) decrypt(a *anchor.Anchor, ct []byte) ([]byte, error) {
	for _, k := range []*crypto.KeyPair{e.key, e.prevKey} {
		if k == nil {
			continue
		}
		secret, err := crypto.SharedSecret(k.Priv, a.EphemeralPub[:])
		if err != nil {
			continue
		}
		key, err := crypto.DeriveKey(secret)
		if err != nil {
			crypto.Zero(secret)
			continue
		}
		nonce, err := crypto.DeriveNonce(secret)
		if err != nil {
			crypto.Zero(secret)
			crypto.Zero(key)
			continue
		}
		pt, err := crypto.Open(ct, key, nonce)
		crypto.Zero(secret)
		crypto.Zero(key)
		if err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("session: decrypt failed")
}
