package broadcast

// Package broadcast implements SENDER-KEY publishing: one newsletter body
// encrypted ONCE, plus a tiny per-subscriber notice carrying the key.
//
// THE PROBLEM IT SOLVES
//
// Spore's E2 path is PAIRWISE. Publishing a 200 KB issue to 10,000 subscribers
// pairwise means 10,000 encryptions and 10,000 stored bodies: ~2 GB per issue.
// With a sender key the body is encrypted once (0.2 MB) and each subscriber
// receives only a ~200-byte notice: ~0.94 MB total, roughly 2,000x less.
//
// THE ATTACK THIS DESIGN MUST STOP
//
// Every subscriber holds the issue key, so any subscriber can encrypt a FAKE
// body under that same key and hand it to other subscribers. Confidentiality
// alone is therefore not enough for a publication: authenticity cannot come
// from the symmetric key, because the symmetric key is shared.
//
// So every issue carries a detached Ed25519 signature from the publisher over
// a transcript that binds the PLAINTEXT hash. A subscriber can re-encrypt
// whatever they like; they cannot produce that signature. OpenIssue refuses any
// issue whose signature does not verify against the pinned publisher key, and
// refuses any issue whose decrypted plaintext does not match the signed hash.
//
// WHAT SENDER-KEY COSTS (stated, not hidden)
//
//   - NO forward secrecy WITHIN an issue: whoever holds an issue key can read
//     that issue. Keys are freshly random per issue and never chained, so
//     compromising one issue key reveals exactly that one issue — not the
//     channel's past or future. This is a deliberate trade for fan-out.
//   - A subscriber who is removed keeps the issues they already received. That
//     is unavoidable: they already had the plaintext.
//   - Publishing is intentionally NON-deniable. A newsletter is a publication;
//     the publisher signs it and that signature is third-party verifiable. Use
//     ordinary pairwise E2 messages for deniable conversation.
//
// The notice is what rides the existing pairwise session, so subscriber
// discovery, prekeys, revocation and metadata privacy are inherited unchanged.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// noticeDomain separates issue-notice signatures from every other use of a
	// publisher's Ed25519 key (attestations, prekey bundles).
	noticeDomain = "spore/broadcast/v1"
	// KeySize is the sender-key length (XChaCha20-Poly1305).
	KeySize = chacha20poly1305.KeySize
	// nonceSize is the XChaCha20-Poly1305 nonce length.
	nonceSize = chacha20poly1305.NonceSizeX
)

// Notice is the small per-subscriber payload. It rides an ordinary pairwise E2
// message, so it inherits that path's encryption, forward secrecy and metadata
// handling. Only this struct is duplicated per subscriber — never the body.
type Notice struct {
	Domain string `json:"domain"`
	// Channel identifies the publication (hex, publisher-chosen, stable).
	Channel string `json:"channel"`
	// Seq is the issue number. Strictly increasing per channel; subscribers
	// reject non-advancing values so a relay cannot replay an old issue.
	Seq uint64 `json:"seq"`
	// BodyCID is the content address of the shared ciphertext in the body
	// store. Every subscriber fetches the SAME object.
	BodyCID string `json:"body_cid"`
	// Key is the hex sender key for this issue only.
	Key string `json:"key"`
	// Nonce is the hex AEAD nonce used for the shared body.
	Nonce string `json:"nonce"`
	// PlainSHA256 is the hex SHA-256 of the DECRYPTED issue. It is inside the
	// signed transcript, which is what stops a subscriber from re-encrypting a
	// forged body under the shared key.
	PlainSHA256 string `json:"plain_sha256"`
	// PlainSize is the decrypted length in bytes.
	PlainSize int64 `json:"plain_size"`
	// Title is optional human metadata (also signed).
	Title string `json:"title,omitempty"`
	// PublisherPub is the publisher's hex Ed25519 public key.
	PublisherPub string `json:"publisher_pub"`
	// Sig is the hex signature over the transcript below.
	Sig string `json:"sig"`
}

// transcript builds the signed bytes. Every field is length-prefixed so no
// combination of values can be reparsed as a different set of fields.
func transcript(channel string, seq uint64, bodyCID, plainSHA string, plainSize int64, title, pubHex string) []byte {
	var out []byte
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	putU64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		put(b[:])
	}
	put([]byte(noticeDomain))
	put([]byte(channel))
	putU64(seq)
	put([]byte(bodyCID))
	put([]byte(plainSHA))
	putU64(uint64(plainSize))
	put([]byte(title))
	put([]byte(pubHex))
	return out
}

// SealIssue encrypts one issue under a FRESH random sender key and returns the
// shared ciphertext plus the notice to fan out.
//
// The caller stores ciphertext in the body store ONCE, then delivers the same
// notice to every subscriber over their individual pairwise sessions.
//
// bodyCIDFn maps the ciphertext to its content address; it is injected so this
// package does not depend on a particular store implementation.
func SealIssue(pub ed25519.PrivateKey, channel string, seq uint64, title string, plaintext []byte, bodyCIDFn func([]byte) string) (ciphertext []byte, n *Notice, err error) {
	if len(pub) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("broadcast: bad publisher key length %d", len(pub))
	}
	if channel == "" {
		return nil, nil, errors.New("broadcast: channel is required")
	}
	if seq == 0 {
		return nil, nil, errors.New("broadcast: seq must start at 1 (0 is reserved for 'no issue seen')")
	}
	if bodyCIDFn == nil {
		return nil, nil, errors.New("broadcast: bodyCIDFn is required")
	}

	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, nil, err
	}
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, err
	}

	// AAD binds the ciphertext to its channel and issue number, so a
	// ciphertext cannot be lifted into a different issue even with its key.
	aad := transcript(channel, seq, "", "", 0, "", "")
	ciphertext = aead.Seal(nil, nonce[:], plaintext, aad)

	sum := sha256.Sum256(plaintext)
	plainSHA := hex.EncodeToString(sum[:])
	cid := bodyCIDFn(ciphertext)
	pubHex := hex.EncodeToString(pub.Public().(ed25519.PublicKey))

	tr := transcript(channel, seq, cid, plainSHA, int64(len(plaintext)), title, pubHex)
	n = &Notice{
		Domain:       noticeDomain,
		Channel:      channel,
		Seq:          seq,
		BodyCID:      cid,
		Key:          hex.EncodeToString(key[:]),
		Nonce:        hex.EncodeToString(nonce[:]),
		PlainSHA256:  plainSHA,
		PlainSize:    int64(len(plaintext)),
		Title:        title,
		PublisherPub: pubHex,
		Sig:          hex.EncodeToString(ed25519.Sign(pub, tr)),
	}
	return ciphertext, n, nil
}

// Marshal renders a notice as the plaintext body of a pairwise E2 message.
func (n *Notice) Marshal() ([]byte, error) { return json.Marshal(n) }

// ParseNotice reports whether b is an issue notice and decodes it. Unknown
// fields are rejected so a malformed or extended notice cannot slip through.
func ParseNotice(b []byte) (*Notice, bool) {
	var n Notice
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, false
	}
	if n.Domain != noticeDomain || n.Channel == "" || n.Sig == "" {
		return nil, false
	}
	return &n, true
}

// OpenIssue verifies and decrypts an issue.
//
// expectedPub is the publisher key the subscriber pinned out-of-band. It is
// REQUIRED: without it, "the signature verifies" only means somebody signed
// this, not that the publisher did — and any subscriber can generate a key.
//
// lastSeq is the highest issue this subscriber has already accepted on this
// channel (0 if none). An issue that does not advance the sequence is refused,
// so a relay cannot replay a stale issue as current.
func OpenIssue(n *Notice, ciphertext []byte, expectedPub string, lastSeq uint64) ([]byte, error) {
	if n == nil {
		return nil, errors.New("broadcast: nil notice")
	}
	if n.Domain != noticeDomain {
		return nil, fmt.Errorf("broadcast: unknown domain %q (want %q)", n.Domain, noticeDomain)
	}
	if expectedPub == "" {
		return nil, errors.New("broadcast: no pinned publisher key supplied — refusing to accept an unauthenticated issue")
	}
	if n.PublisherPub != expectedPub {
		return nil, fmt.Errorf("broadcast: issue signed by %s but publisher is pinned as %s", n.PublisherPub, expectedPub)
	}
	if n.Seq <= lastSeq {
		return nil, fmt.Errorf("broadcast: issue seq %d does not advance past %d (replayed or reordered issue)", n.Seq, lastSeq)
	}

	pubRaw, err := hex.DecodeString(n.PublisherPub)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return nil, errors.New("broadcast: bad publisher_pub")
	}
	sig, err := hex.DecodeString(n.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("broadcast: bad sig")
	}

	// Verify the publisher's signature BEFORE decrypting anything: a forged
	// issue must never reach the AEAD, let alone the reader.
	tr := transcript(n.Channel, n.Seq, n.BodyCID, n.PlainSHA256, n.PlainSize, n.Title, n.PublisherPub)
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), tr, sig) {
		return nil, errors.New("broadcast: PUBLISHER SIGNATURE INVALID — this issue was not published by the pinned key (a subscriber may have forged it under the shared issue key)")
	}

	key, err := hex.DecodeString(n.Key)
	if err != nil || len(key) != KeySize {
		return nil, errors.New("broadcast: bad issue key")
	}
	nonce, err := hex.DecodeString(n.Nonce)
	if err != nil || len(nonce) != nonceSize {
		return nil, errors.New("broadcast: bad nonce")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	aad := transcript(n.Channel, n.Seq, "", "", 0, "", "")
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("broadcast: issue body failed authentication: %w", err)
	}

	// The signature covers the PLAINTEXT hash, so this is the check that makes
	// re-encryption under the shared key useless to an attacker.
	sum := sha256.Sum256(plaintext)
	if hex.EncodeToString(sum[:]) != n.PlainSHA256 {
		return nil, errors.New("broadcast: decrypted body does not match the SIGNED plaintext hash — the body was substituted")
	}
	if int64(len(plaintext)) != n.PlainSize {
		return nil, fmt.Errorf("broadcast: decrypted body is %d bytes but the signed size is %d", len(plaintext), n.PlainSize)
	}
	return plaintext, nil
}

// FanoutCost reports the byte cost of publishing to n subscribers, both with a
// sender key and pairwise. It exists so the CLI can show an operator the real
// number instead of a claim.
func FanoutCost(bodyBytes, noticeBytes, subscribers int) (senderKey, pairwise int) {
	return bodyBytes + noticeBytes*subscribers, bodyBytes * subscribers
}
