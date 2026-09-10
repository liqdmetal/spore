// Package invite builds the one artifact a beta user hands to a new contact:
// a self-contained, SIGNED introduction carrying everything needed to start a
// 0xE2 conversation, and nothing that must stay secret.
//
// # Why it is signed
//
// The bundle alone is not enough to pin a contact. A prekey bundle is verified
// against `pinned_sig`, which authenticates the BUNDLE — but the chain ADDRESS
// is not covered by that signature. An attacker who can modify an invite in
// transit (a chat app, an email, a paste into a public channel) could redirect
// the address and receive every pointer, while the bundle still verified
// perfectly. The invite therefore signs its whole payload with the same
// identity-derived Ed25519 key that signs prekey bundles, so name, address,
// chain, and bundle are bound together and any edit invalidates the artifact.
//
// # What it deliberately does not carry
//
// No private keys, no mailbox tokens, no store credentials. An invite is meant
// to be pasted into a channel you do not control, so everything in it must be
// safe to publish. The only credential-shaped thing a recipient still needs —
// the body-store token — is intentionally ABSENT and must be obtained
// separately.
//
// # The prekey subtlety
//
// A bundle may embed a one-time prekey (OPK). Sharing one OPK with several
// recipients would reuse a one-time key, so an invite carrying an OPK is meant
// for a single recipient. An invite with no OPK is in "degraded" 2-DH mode:
// still forward-private per message via the ratchet, but without the extra
// X3DH DH. Invite issuance therefore refuses to embed an OPK unless the caller
// explicitly acknowledges the single-recipient constraint.
package invite

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/secure"
)

// Version is the invite wire version.
const Version = 1

// Prefix makes an encoded invite recognizable and version-tagged, so a paste
// into the wrong tool fails loudly instead of silently.
const Prefix = "spore-invite-v1:"

// domainTag separates this signature from every other signature the identity
// key produces (envelopes, prekey bundles, attestations). Without it, a
// signature over an invite payload could be replayed as a signature over some
// other artifact that happens to share a prefix.
const domainTag = "spore/invite/v1"

// MaxEncoded bounds a pasted invite. An invite is a few hundred bytes; anything
// far larger is either corrupt or an attempt to make a parser do work.
const MaxEncoded = 16 << 10

// Invite is the shareable introduction.
type Invite struct {
	V       int               `json:"v"`
	Name    string            `json:"name,omitempty"`
	Chain   string            `json:"chain"`
	Address string            `json:"address"`
	Bundle  ratchet.SPKBundle `json:"bundle"`
	// PinnedSig is the hex Ed25519 identity public key the recipient pins.
	// It both verifies the bundle and is the key that signed this invite.
	PinnedSig string `json:"pinned_sig"`
	// PrekeyURL is optional: where a sender may fetch a FRESH single-use
	// prekey bundle. The embedded bundle still applies if it is unreachable.
	PrekeyURL string `json:"prekey_url,omitempty"`
	StoreURL  string `json:"store_url,omitempty"`
	Note      string `json:"note,omitempty"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// Sig is the hex Ed25519 signature over transcript(Invite) with Sig unset.
	Sig string `json:"sig"`
}

var (
	// ErrNoInvite means the input is not an invite at all.
	ErrNoInvite = errors.New("invite: not a spore invite")
	// ErrSignature means the invite was altered or forged.
	ErrSignature = errors.New("invite: signature does not verify")
	// ErrExpired means the invite is past its stated expiry.
	ErrExpired = errors.New("invite: expired")
)

// transcript is the exact bytes the signature covers.
//
// Every field is length-prefixed and written in a fixed order. Length prefixes
// matter: with plain concatenation, name="ab" address="c" and name="a"
// address="bc" would produce identical bytes, so a signature over one would
// also validate the other. That is the classic structured-signature flaw, and
// prefixing every field removes it.
func transcript(i *Invite) []byte {
	var b []byte
	putU32 := func(n uint64) {
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	putStr := func(s string) {
		putU32(uint64(len(s)))
		b = append(b, s...)
	}
	putBytes := func(p []byte) {
		putU32(uint64(len(p)))
		b = append(b, p...)
	}

	b = append(b, domainTag...)
	putU32(uint64(i.V))
	putStr(i.Name)
	putStr(i.Chain)
	putStr(i.Address)
	// Bundle fields, each individually bound.
	putBytes(i.Bundle.IKPub[:])
	putBytes(i.Bundle.SPKPub[:])
	putU32(uint64(i.Bundle.SPKID))
	putBytes(i.Bundle.SPKSig[:])
	if i.Bundle.OPKPub == nil {
		putU32(0) // explicit "absent" marker, distinct from a zero-length value
	} else {
		putU32(1)
		putBytes(i.Bundle.OPKPub[:])
	}
	putU32(uint64(i.Bundle.OPKID))
	putBytes(i.Bundle.OPKHash[:])
	putStr(i.PinnedSig)
	putStr(i.PrekeyURL)
	putStr(i.StoreURL)
	putStr(i.Note)
	putStr(i.IssuedAt)
	putStr(i.ExpiresAt)
	return b
}

// Fingerprint returns a short, human-comparable rendering of the identity key.
//
// This is the real defence against a swapped address: the two humans read the
// fingerprint to each other over a channel the attacker does not control. The
// signature stops silent tampering; the fingerprint catches a COMPLETE
// substitution (attacker's own signed invite, correct signature, wrong person).
func (i *Invite) Fingerprint() string {
	raw, err := hex.DecodeString(i.PinnedSig)
	if err != nil || len(raw) != 32 {
		return ""
	}
	sum := sha256.Sum256(append([]byte("spore/invite/fingerprint/v1"), raw...))
	short := hex.EncodeToString(sum[:8])
	// Group in fours so it is readable aloud.
	var parts []string
	for n := 0; n < len(short); n += 4 {
		end := n + 4
		if end > len(short) {
			end = len(short)
		}
		parts = append(parts, short[n:end])
	}
	return strings.Join(parts, "-")
}

// Sign fills PinnedSig (if the caller left it empty) and Sig using the
// identity-derived signing key, then returns the invite.
func (i *Invite) Sign(identityPriv []byte) error {
	pub, err := secure.SigPubOf(identityPriv)
	if err != nil {
		return fmt.Errorf("invite: derive identity signing key: %w", err)
	}
	if i.PinnedSig == "" {
		i.PinnedSig = hex.EncodeToString(pub)
	}
	// Signing with a key that does not match the advertised pin would produce
	// an invite that can never verify. Catch it here, where the cause is
	// obvious, rather than at the recipient.
	if i.PinnedSig != hex.EncodeToString(pub) {
		return errors.New("invite: pinned_sig does not match the signing identity")
	}
	key, err := secure.SigKeypairOf(identityPriv)
	if err != nil {
		return fmt.Errorf("invite: derive signing key: %w", err)
	}
	i.V = Version
	i.Sig = ""
	i.Sig = hex.EncodeToString(ed25519.Sign(key, transcript(i)))
	return nil
}

// Verify checks the invite end to end:
//
//  1. the version is understood;
//  2. the signature verifies against the embedded pinned key;
//  3. the BUNDLE verifies against that same pinned key (so a valid invite
//     cannot carry a bundle belonging to someone else);
//  4. the address is well formed for its chain;
//  5. the expiry, if stated, has not passed.
func (i *Invite) Verify(now time.Time) error {
	if i == nil {
		return ErrNoInvite
	}
	if i.V != Version {
		return fmt.Errorf("invite: unsupported version %d", i.V)
	}
	if i.PinnedSig == "" {
		return fmt.Errorf("%w: no pinned_sig", ErrSignature)
	}
	pub, err := hex.DecodeString(i.PinnedSig)
	if err != nil || len(pub) != 32 {
		return fmt.Errorf("invite: pinned_sig is not a 32-byte hex key")
	}
	sig, err := hex.DecodeString(i.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrSignature)
	}
	if i.Sig == "" {
		return fmt.Errorf("%w: absent", ErrSignature)
	}

	// Recompute over the invite with Sig cleared, exactly as Sign did.
	probe := *i
	probe.Sig = ""
	if !ed25519.Verify(ed25519.PublicKey(pub), transcript(&probe), sig) {
		return fmt.Errorf("%w: invite payload was altered", ErrSignature)
	}

	// The bundle must belong to the same identity that signed the invite.
	if err := i.Bundle.Verify(pub); err != nil {
		return fmt.Errorf("%w: bundle is not bound to the pinned key: %v", ErrSignature, err)
	}

	if i.Chain == "" {
		return errors.New("invite: no chain")
	}
	if i.Address == "" {
		return errors.New("invite: no address")
	}
	if i.Chain == "dero" {
		if _, err := dero.ValidateAddress(i.Address); err != nil {
			return fmt.Errorf("invite: bad destination address: %w", err)
		}
	}
	if i.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, i.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invite: unparseable expires_at: %w", err)
		}
		if !now.Before(exp) {
			return fmt.Errorf("%w (at %s)", ErrExpired, exp.Format(time.RFC3339))
		}
	}
	return nil
}

// Encode renders the invite as a single pasteable line.
func (i *Invite) Encode() (string, error) {
	raw, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses a pasteable invite. It does NOT verify it — call Verify.
func Decode(s string) (*Invite, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Prefix) {
		return nil, fmt.Errorf("%w (expected a %q prefix)", ErrNoInvite, Prefix)
	}
	body := strings.TrimPrefix(s, Prefix)
	if len(body) > MaxEncoded {
		return nil, fmt.Errorf("invite: encoded body is %d bytes, limit is %d", len(body), MaxEncoded)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("invite: not valid base64url: %w", err)
	}
	var i Invite
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&i); err != nil {
		return nil, fmt.Errorf("invite: malformed payload: %w", err)
	}
	// A JSON literal such as `null` decodes into a zero-valued struct WITHOUT
	// error, so a payload that carries no version at all would otherwise slip
	// through as an "invite". Reject it here; Verify still does the real work.
	if i.V == 0 {
		return nil, fmt.Errorf("%w: payload carries no version", ErrNoInvite)
	}
	return &i, nil
}

// DecodeAndVerify is the safe entry point: it parses and immediately verifies.
func DecodeAndVerify(s string, now time.Time) (*Invite, error) {
	i, err := Decode(s)
	if err != nil {
		return nil, err
	}
	if err := i.Verify(now); err != nil {
		return nil, err
	}
	return i, nil
}

// Options configures issuance.
type Options struct {
	Name    string
	Chain   string
	Address string
	Bundle  ratchet.SPKBundle
	// PrekeyURL is optional.
	PrekeyURL string
	StoreURL  string
	Note      string
	// TTL optionally bounds the invite's validity. Zero means no expiry.
	TTL time.Duration
	// AllowOPK acknowledges the single-recipient constraint when Bundle
	// carries a one-time prekey. Without it, issuance refuses an OPK-bearing
	// bundle rather than silently encouraging reuse.
	AllowOPK bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// New builds and signs an invite.
func New(identityPriv []byte, o Options) (*Invite, error) {
	if o.Address == "" {
		return nil, errors.New("invite: address is required")
	}
	chain := o.Chain
	if chain == "" {
		chain = "dero"
	}
	if chain == "dero" {
		addr, err := dero.ValidateAddress(o.Address)
		if err != nil {
			return nil, fmt.Errorf("invite: %w", err)
		}
		o.Address = addr
	}
	// A bundle with no identity is not a bundle: the recipient could never
	// verify it, so refuse rather than emit an unusable invite.
	if o.Bundle.IKPub == [32]byte{} || o.Bundle.SPKPub == [32]byte{} {
		return nil, errors.New("invite: bundle is missing public key material")
	}
	if o.Bundle.OPKPub != nil && !o.AllowOPK {
		return nil, errors.New("invite: bundle carries a one-time prekey, which must not be shared " +
			"with more than one recipient; pass AllowOPK to acknowledge that this invite goes to a single person")
	}

	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	i := &Invite{
		V:         Version,
		Name:      o.Name,
		Chain:     chain,
		Address:   o.Address,
		Bundle:    o.Bundle,
		PrekeyURL: o.PrekeyURL,
		StoreURL:  o.StoreURL,
		Note:      o.Note,
		IssuedAt:  now().UTC().Format(time.RFC3339),
	}
	if o.TTL > 0 {
		i.ExpiresAt = now().Add(o.TTL).UTC().Format(time.RFC3339)
	}
	if err := i.Sign(identityPriv); err != nil {
		return nil, err
	}
	return i, nil
}
