package attest

// Package attest implements DETACHED, THIRD-PARTY-VERIFIABLE signatures over a
// document — the "can I e-sign a contract" primitive (DocuSign-equivalent).
//
// WHY THIS IS A SEPARATE MECHANISM, NOT A REUSE OF THE MESSAGE PATH
//
// Spore messages are authenticated with a SYMMETRIC AEAD key derived from the
// Double Ratchet (internal/ratchet: "there is NO outer envelope signature").
// That gives DENIABILITY: the recipient knows the message came from the sender,
// but CANNOT prove it to a third party, because the recipient holds the same
// symmetric key and could have forged the ciphertext themselves.
//
// Deniability is a feature for chat and a fatal flaw for a signature. An
// e-signature must be verifiable by someone who was never in the conversation
// (a court, a counterparty's lawyer, an auditor). So an attestation is an
// explicit, opt-in, NON-deniable artifact: a detached Ed25519 signature over a
// hash of the document, verifiable by anyone holding the signer's public key.
//
// The signer's key is the SAME Ed25519 key whose public half users already
// exchange out-of-band as `-pinned-sig`. That is the whole trust story: the
// anchor people already pin to start a conversation is exactly the key that
// verifies their signatures. No new PKI, no CA, no notary.
//
// DOMAIN SEPARATION (security requirement, not decoration)
//
// The same Ed25519 key also signs SPK prekey bundles (internal/ratchet/x3dh).
// If an attestation signed a bare hash, a signature harvested from one context
// could potentially be replayed as the other. Every attestation therefore signs
// a transcript with a distinct, length-prefixed domain tag, so an attestation
// signature is not a valid bundle signature and vice versa.
//
// WHAT AN ATTESTATION DOES AND DOES NOT PROVE
//
// Proves: the holder of a specific private key signed THIS exact byte sequence,
// and asserted a specific statement about it at a claimed time.
// Does NOT prove: the signer's legal identity (that is the out-of-band pinning
// step), nor WHEN they signed it (self-claimed `SignedAt` is not trustworthy on
// its own — anchor the attestation hash on-chain for that; see AnchorDigest).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// domainTag separates attestation signatures from every other use of the same
// Ed25519 key. Changing this string invalidates all existing attestations.
const domainTag = "spore/attest/v1"

// Envelope is the detached signature artifact. It is plain JSON so it can be
// mailed, printed, pasted, or archived independently of the document, and
// verified by any implementation.
type Envelope struct {
	// Domain pins the transcript construction this signature commits to.
	Domain string `json:"domain"`
	// DocSHA256 is the hex SHA-256 of the exact document bytes.
	DocSHA256 string `json:"doc_sha256"`
	// DocSize is the document length in bytes. Hash equality already implies
	// this, but carrying it makes a truncation mismatch obvious to a human
	// reading the envelope.
	DocSize int64 `json:"doc_size"`
	// Statement is what the signer asserts (e.g. "I agree to these terms").
	// It is INSIDE the signed transcript: a signature over a document with no
	// statement of intent is ambiguous about what was agreed to.
	Statement string `json:"statement"`
	// SignerPub is the signer's hex Ed25519 public key — the same value peers
	// exchange out-of-band as `-pinned-sig`.
	SignerPub string `json:"signer_pub"`
	// SignedAt is the signer's CLAIMED time (RFC3339). Self-asserted and NOT
	// independently trustworthy; anchor on-chain for a real timestamp.
	SignedAt string `json:"signed_at"`
	// Sig is the hex Ed25519 signature over the canonical transcript.
	Sig string `json:"sig"`
}

// transcript builds the exact bytes that get signed. Every field is
// length-prefixed so no combination of field values can be reinterpreted as a
// different set of fields (canonicalization / concatenation ambiguity).
func transcript(docHash []byte, docSize int64, statement, signerPub, signedAt string) []byte {
	var out []byte
	put := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		out = append(out, n[:]...)
		out = append(out, b...)
	}
	put([]byte(domainTag))
	put(docHash)
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], uint64(docSize))
	put(sz[:])
	put([]byte(statement))
	put([]byte(signerPub))
	put([]byte(signedAt))
	return out
}

// HashDocument streams a document and returns its SHA-256 and length. Streaming
// means a multi-gigabyte file never has to fit in memory.
func HashDocument(r io.Reader) (sum []byte, n int64, err error) {
	h := sha256.New()
	n, err = io.Copy(h, r)
	if err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), n, nil
}

// Sign produces a detached attestation over an already-hashed document.
//
// statement must be non-empty: an attestation whose meaning is unstated is a
// signature nobody can interpret later, which is exactly the ambiguity that
// makes e-signatures contested.
func Sign(priv ed25519.PrivateKey, docHash []byte, docSize int64, statement string, at time.Time) (*Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attest: bad private key length %d", len(priv))
	}
	if len(docHash) != sha256.Size {
		return nil, fmt.Errorf("attest: doc hash must be %d bytes, got %d", sha256.Size, len(docHash))
	}
	if statement == "" {
		return nil, errors.New("attest: statement is required (what is the signer asserting about this document?)")
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	ts := at.UTC().Format(time.RFC3339)
	sig := ed25519.Sign(priv, transcript(docHash, docSize, statement, pub, ts))
	return &Envelope{
		Domain:    domainTag,
		DocSHA256: hex.EncodeToString(docHash),
		DocSize:   docSize,
		Statement: statement,
		SignerPub: pub,
		SignedAt:  ts,
		Sig:       hex.EncodeToString(sig),
	}, nil
}

// Verify checks an envelope against the document's actual hash.
//
// It returns an error on ANY mismatch. Callers must treat a non-nil error as
// "this signature does not stand", never as a warning.
func (e *Envelope) Verify(docHash []byte) error {
	if e.Domain != domainTag {
		return fmt.Errorf("attest: unknown domain %q (want %q) — refusing to verify a signature from a different scheme", e.Domain, domainTag)
	}
	want, err := hex.DecodeString(e.DocSHA256)
	if err != nil {
		return fmt.Errorf("attest: bad doc_sha256: %w", err)
	}
	if len(want) != sha256.Size {
		return fmt.Errorf("attest: doc_sha256 must be %d bytes, got %d", sha256.Size, len(want))
	}
	if len(docHash) != len(want) {
		return fmt.Errorf("attest: document hash length %d != envelope %d", len(docHash), len(want))
	}
	// Constant time not required (public values), but equality must be exact.
	for i := range want {
		if want[i] != docHash[i] {
			return errors.New("attest: DOCUMENT DOES NOT MATCH this attestation (the file was altered, or this signature belongs to a different document)")
		}
	}
	pub, err := hex.DecodeString(e.SignerPub)
	if err != nil {
		return fmt.Errorf("attest: bad signer_pub: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("attest: signer_pub must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("attest: bad sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("attest: sig must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if e.Statement == "" {
		return errors.New("attest: envelope has an empty statement")
	}
	tr := transcript(want, e.DocSize, e.Statement, e.SignerPub, e.SignedAt)
	if !ed25519.Verify(ed25519.PublicKey(pub), tr, sig) {
		return errors.New("attest: SIGNATURE INVALID for this signer and document")
	}
	return nil
}

// VerifyPinned additionally requires the signature to come from an EXPECTED
// key. Verify alone proves "somebody with key X signed this"; it does not prove
// X is your counterparty. This is the call that binds an attestation to the
// identity you pinned out-of-band, and it is the one applications should use.
func (e *Envelope) VerifyPinned(docHash []byte, expectedPubHex string) error {
	if err := e.Verify(docHash); err != nil {
		return err
	}
	if expectedPubHex == "" {
		return errors.New("attest: no expected signer key supplied")
	}
	got, err := hex.DecodeString(e.SignerPub)
	if err != nil {
		return fmt.Errorf("attest: bad signer_pub: %w", err)
	}
	want, err := hex.DecodeString(expectedPubHex)
	if err != nil {
		return fmt.Errorf("attest: bad expected signer key: %w", err)
	}
	if len(want) != ed25519.PublicKeySize {
		return fmt.Errorf("attest: expected signer key must be %d bytes, got %d", ed25519.PublicKeySize, len(want))
	}
	if len(got) != len(want) {
		return errors.New("attest: signer key length mismatch")
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("attest: SIGNED BY THE WRONG KEY: envelope is signed by %s, but you expected %s", e.SignerPub, expectedPubHex)
		}
	}
	return nil
}

// AnchorDigest is the value to publish on-chain to prove an attestation existed
// no later than a given block. It commits to the whole envelope (including the
// claimed time and statement), so anchoring pins the entire assertion, not just
// the document.
//
// Anchoring is what upgrades SignedAt from "the signer says so" to "it existed
// by block N". The chain never sees the document or the signature — only this
// opaque 32-byte digest.
func (e *Envelope) AnchorDigest() ([32]byte, error) {
	// Marshal through a fixed field order (struct order) for determinism.
	b, err := json.Marshal(e)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte(domainTag+"/anchor\x00"), b...)), nil
}

// Sheet is a multi-signer collection over ONE document: a contract with several
// counterparties, each contributing an independent attestation.
//
// Every signature is standalone — there is no signing order, no coordinator,
// and no shared secret. Signers can sign offline, in any order, and a verifier
// can check any subset. That is deliberately unlike a centralized e-sign
// service, which is a trusted third party holding the whole workflow.
type Sheet struct {
	DocSHA256 string      `json:"doc_sha256"`
	DocSize   int64       `json:"doc_size"`
	Sigs      []*Envelope `json:"sigs"`
}

// Add appends an attestation, enforcing that every signature in a sheet covers
// the SAME document and that no key signs twice.
func (s *Sheet) Add(e *Envelope) error {
	if e == nil {
		return errors.New("attest: nil envelope")
	}
	if s.DocSHA256 == "" {
		s.DocSHA256, s.DocSize = e.DocSHA256, e.DocSize
	}
	if e.DocSHA256 != s.DocSHA256 {
		return fmt.Errorf("attest: envelope covers document %s but sheet is for %s", e.DocSHA256, s.DocSHA256)
	}
	for _, existing := range s.Sigs {
		if existing.SignerPub == e.SignerPub {
			return fmt.Errorf("attest: %s has already signed this sheet", e.SignerPub)
		}
	}
	s.Sigs = append(s.Sigs, e)
	return nil
}

// VerifyAll checks every attestation on the sheet against the document, and
// reports which of requiredPubs are still missing. A sheet is only "fully
// executed" when err == nil AND missing is empty.
func (s *Sheet) VerifyAll(docHash []byte, requiredPubs []string) (missing []string, err error) {
	seen := map[string]bool{}
	for _, e := range s.Sigs {
		if err := e.Verify(docHash); err != nil {
			return nil, fmt.Errorf("attest: signature by %s does not stand: %w", e.SignerPub, err)
		}
		seen[e.SignerPub] = true
	}
	for _, want := range requiredPubs {
		if !seen[want] {
			missing = append(missing, want)
		}
	}
	return missing, nil
}
