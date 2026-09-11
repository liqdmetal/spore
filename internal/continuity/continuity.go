// Package continuity implements an explicit dead-man continuity vault.
//
// A vault encrypts one payload to one or more designated recipients. The owner
// periodically signs check-ins. If the latest signed deadline passes without a
// check-in, a recipient may decrypt the payload. This package does not contact
// a network, move funds, or automatically release anything: an external
// observer must choose when to evaluate Status and call Release.
package continuity

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

const domain = "spore/continuity/v1"

var (
	ErrInvalidVault      = errors.New("continuity: invalid vault")
	ErrNotDue            = errors.New("continuity: release deadline has not passed")
	ErrDeadlinePassed    = errors.New("continuity: check-in deadline has passed")
	ErrRecipientNotFound = errors.New("continuity: recipient is not designated")
)

// Vault is JSON-safe public state plus encrypted recipient envelopes. It never
// contains the plaintext payload, the payload key, or owner private material.
type Vault struct {
	Version           uint8           `json:"version"`
	VaultID           string          `json:"vault_id"`
	PolicyID          string          `json:"policy_id"`
	OwnerPub          string          `json:"owner_pub"`
	OwnerSigPub       string          `json:"owner_sig_pub"`
	CreatedAt         int64           `json:"created_at"`
	IntervalSeconds   int64           `json:"interval_seconds"`
	GraceSeconds      int64           `json:"grace_seconds"`
	PayloadNonce      string          `json:"payload_nonce"`
	PayloadCiphertext string          `json:"payload_ciphertext"`
	Recipients        []RecipientWrap `json:"recipients"`
	Checkins          []CheckInRecord `json:"checkins"`
}

// RecipientWrap contains a payload-key envelope for one recipient.
type RecipientWrap struct {
	RecipientPub string `json:"recipient_pub"`
	EphemeralPub string `json:"ephemeral_pub"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// CiphertextBytes returns the encoded recipient envelope bytes for diagnostics
// and tests. It returns nil for malformed hex.
func (r RecipientWrap) CiphertextBytes() []byte {
	b, err := hex.DecodeString(r.Ciphertext)
	if err != nil {
		return nil
	}
	return b
}

// CheckInRecord is an owner-signed liveness statement. Seq 0 is the creation
// statement; later records chain to the previous record's digest.
type CheckInRecord struct {
	Seq      uint64 `json:"seq"`
	At       int64  `json:"at"`
	Deadline int64  `json:"deadline"`
	Prev     string `json:"prev"`
	Sig      string `json:"sig"`
}

// CreateOptions controls vault creation. OwnerPriv and recipient public keys
// are raw 32-byte X25519 scalars/keys and must remain in the caller's memory.
type CreateOptions struct {
	OwnerPriv  []byte
	Recipients [][]byte
	Payload    []byte
	CreatedAt  int64
	Interval   time.Duration
	Grace      time.Duration
}

// Status is a read-only evaluation at a caller-supplied time.
type Status struct {
	VaultID      string `json:"vault_id"`
	DueAt        int64  `json:"due_at"`
	LastCheckIn  int64  `json:"last_check_in"`
	Releasable   bool   `json:"releasable"`
	CheckInCount int    `json:"checkin_count"`
}

const vaultVersion uint8 = 1

// Create encrypts payload once and wraps its random payload key separately for
// each designated recipient. The owner identity is used only to authenticate
// the check-in chain; it is never used as a static encryption key.
func Create(opts CreateOptions) (*Vault, error) {
	if len(opts.OwnerPriv) != 32 {
		return nil, fmt.Errorf("%w: owner private key must be 32 bytes", ErrInvalidVault)
	}
	if len(opts.Payload) == 0 {
		return nil, fmt.Errorf("%w: payload must not be empty", ErrInvalidVault)
	}
	if len(opts.Recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one recipient is required", ErrInvalidVault)
	}
	if opts.CreatedAt <= 0 {
		return nil, fmt.Errorf("%w: created-at must be positive", ErrInvalidVault)
	}
	interval, grace, err := durationSeconds(opts.Interval, opts.Grace)
	if err != nil {
		return nil, err
	}
	ownerKey := append([]byte(nil), opts.OwnerPriv...)
	defer sporecrypto.Zero(ownerKey)
	owner, err := sporecrypto.KeyPairFromPriv(ownerKey)
	if err != nil {
		return nil, fmt.Errorf("%w: owner key: %v", ErrInvalidVault, err)
	}
	defer sporecrypto.Zero(owner.Priv)
	sigPriv := signingKey(ownerKey)
	defer sporecrypto.Zero(sigPriv)
	sigPub := sigPriv.Public().(ed25519.PublicKey)

	pubs := make([]string, 0, len(opts.Recipients))
	seen := make(map[string]struct{}, len(opts.Recipients))
	for _, raw := range opts.Recipients {
		if len(raw) != 32 {
			return nil, fmt.Errorf("%w: recipient public keys must be 32 bytes", ErrInvalidVault)
		}
		pub := hex.EncodeToString(raw)
		if _, ok := seen[pub]; ok {
			return nil, fmt.Errorf("%w: duplicate recipient", ErrInvalidVault)
		}
		seen[pub] = struct{}{}
		pubs = append(pubs, pub)
	}
	sort.Strings(pubs)

	payloadKey := make([]byte, sporecrypto.KeySize)
	if _, err := crand.Read(payloadKey); err != nil {
		return nil, err
	}
	defer sporecrypto.Zero(payloadKey)
	payloadNonce := make([]byte, sporecrypto.NonceSize)
	if _, err := crand.Read(payloadNonce); err != nil {
		return nil, err
	}
	policyCoreID := hashJSON(policyMaterial{
		OwnerPub: owner.Pub, OwnerSigPub: sigPub, CreatedAt: opts.CreatedAt,
		Interval: interval, Grace: grace, Recipients: pubs,
		PayloadNonce: payloadNonce, PayloadCiphertext: nil,
	})
	payloadCiphertext, err := sporecrypto.SealAAD(opts.Payload, payloadKey, payloadNonce, bodyAAD(policyCoreID))
	if err != nil {
		return nil, err
	}
	policyID := hashJSON(policyMaterial{
		OwnerPub: owner.Pub, OwnerSigPub: sigPub, CreatedAt: opts.CreatedAt,
		Interval: interval, Grace: grace, Recipients: pubs,
		PayloadNonce: payloadNonce, PayloadCiphertext: payloadCiphertext,
	})

	wraps := make([]RecipientWrap, 0, len(pubs))
	for _, pubHex := range pubs {
		recipientPub, _ := hex.DecodeString(pubHex)
		ephemeral, err := sporecrypto.GenerateKey()
		if err != nil {
			return nil, err
		}
		secret, err := sporecrypto.SharedSecret(ephemeral.Priv, recipientPub)
		sporecrypto.Zero(ephemeral.Priv)
		if err != nil {
			return nil, fmt.Errorf("%w: recipient agreement: %v", ErrInvalidVault, err)
		}
		wrapKey, err := sporecrypto.DeriveKeyBound(secret, ephemeral.Pub, recipientPub)
		sporecrypto.Zero(secret)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, sporecrypto.NonceSize)
		if _, err := crand.Read(nonce); err != nil {
			return nil, err
		}
		ct, err := sporecrypto.SealAAD(payloadKey, wrapKey, nonce, wrapAAD(policyID, ephemeral.Pub, recipientPub))
		sporecrypto.Zero(wrapKey)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, RecipientWrap{
			RecipientPub: pubHex,
			EphemeralPub: hex.EncodeToString(ephemeral.Pub),
			Nonce:        hex.EncodeToString(nonce),
			Ciphertext:   hex.EncodeToString(ct),
		})
	}

	vaultID := hashJSON(vaultMaterial{PolicyID: policyID, PayloadNonce: payloadNonce, PayloadCiphertext: payloadCiphertext, Recipients: wraps})
	deadline, ok := safeAdd(opts.CreatedAt, interval+grace)
	if !ok {
		return nil, fmt.Errorf("%w: deadline overflow", ErrInvalidVault)
	}
	v := &Vault{
		Version: vaultVersion, VaultID: vaultID, PolicyID: policyID,
		OwnerPub: hex.EncodeToString(owner.Pub), OwnerSigPub: hex.EncodeToString(sigPub),
		CreatedAt: opts.CreatedAt, IntervalSeconds: interval, GraceSeconds: grace,
		PayloadNonce: hex.EncodeToString(payloadNonce), PayloadCiphertext: hex.EncodeToString(payloadCiphertext),
		Recipients: wraps,
	}
	v.Checkins = []CheckInRecord{{Seq: 0, At: opts.CreatedAt, Deadline: deadline, Sig: ""}}
	v.Checkins[0].Sig = signCheckin(sigPriv, v.VaultID, v.Checkins[0])
	if err := v.Verify(); err != nil {
		return nil, err
	}
	return v, nil
}

// CheckIn appends a signed liveness statement. It fails at the exact deadline:
// the owner must check in strictly before the current deadline.
func CheckIn(v *Vault, ownerPriv []byte, now int64) error {
	if v == nil {
		return ErrInvalidVault
	}
	if err := v.Verify(); err != nil {
		return err
	}
	last := v.Checkins[len(v.Checkins)-1]
	if now >= last.Deadline {
		return ErrDeadlinePassed
	}
	if now <= last.At {
		return fmt.Errorf("%w: check-in time must advance", ErrInvalidVault)
	}
	ownerKey := append([]byte(nil), ownerPriv...)
	defer sporecrypto.Zero(ownerKey)
	owner, err := sporecrypto.KeyPairFromPriv(ownerKey)
	if err != nil || hex.EncodeToString(owner.Pub) != v.OwnerPub {
		return ErrInvalidVault
	}
	defer sporecrypto.Zero(owner.Priv)
	sigPriv := signingKey(ownerKey)
	defer sporecrypto.Zero(sigPriv)
	deadline, ok := safeAdd(now, v.IntervalSeconds+v.GraceSeconds)
	if !ok {
		return fmt.Errorf("%w: deadline overflow", ErrInvalidVault)
	}
	next := CheckInRecord{Seq: last.Seq + 1, At: now, Deadline: deadline, Prev: checkinDigest(last)}
	next.Sig = signCheckin(sigPriv, v.VaultID, next)
	v.Checkins = append(v.Checkins, next)
	return v.Verify()
}

// Status evaluates the signed chain without mutating the vault.
func (v *Vault) Status(now int64) (Status, error) {
	if err := v.Verify(); err != nil {
		return Status{}, err
	}
	last := v.Checkins[len(v.Checkins)-1]
	return Status{VaultID: v.VaultID, DueAt: last.Deadline, LastCheckIn: last.At, Releasable: now >= last.Deadline, CheckInCount: len(v.Checkins)}, nil
}

// Release decrypts the payload for a designated recipient after the signed
// deadline. It is intentionally caller-triggered; no network side effect is
// hidden inside this function.
func Release(v *Vault, recipientPriv []byte, now int64) ([]byte, error) {
	status, err := v.Status(now)
	if err != nil {
		return nil, err
	}
	if !status.Releasable {
		return nil, ErrNotDue
	}
	recipientKey := append([]byte(nil), recipientPriv...)
	defer sporecrypto.Zero(recipientKey)
	recipient, err := sporecrypto.KeyPairFromPriv(recipientKey)
	if err != nil {
		return nil, ErrRecipientNotFound
	}
	defer sporecrypto.Zero(recipient.Priv)
	recipientHex := hex.EncodeToString(recipient.Pub)
	for _, wrap := range v.Recipients {
		if wrap.RecipientPub != recipientHex {
			continue
		}
		ephemeralPub, err := hex.DecodeString(wrap.EphemeralPub)
		if err != nil {
			return nil, ErrInvalidVault
		}
		nonce, err := hex.DecodeString(wrap.Nonce)
		if err != nil {
			return nil, ErrInvalidVault
		}
		ciphertext, err := hex.DecodeString(wrap.Ciphertext)
		if err != nil {
			return nil, ErrInvalidVault
		}
		secret, err := sporecrypto.SharedSecret(recipientKey, ephemeralPub)
		if err != nil {
			return nil, ErrInvalidVault
		}
		key, err := sporecrypto.DeriveKeyBound(secret, ephemeralPub, recipient.Pub)
		sporecrypto.Zero(secret)
		if err != nil {
			return nil, err
		}
		payloadKey, err := sporecrypto.OpenAAD(ciphertext, key, nonce, wrapAAD(v.PolicyID, ephemeralPub, recipient.Pub))
		sporecrypto.Zero(key)
		if err != nil || len(payloadKey) != sporecrypto.KeySize {
			return nil, ErrRecipientNotFound
		}
		defer sporecrypto.Zero(payloadKey)
		bodyNonce, err := hex.DecodeString(v.PayloadNonce)
		if err != nil {
			return nil, ErrInvalidVault
		}
		bodyCiphertext, err := hex.DecodeString(v.PayloadCiphertext)
		if err != nil {
			return nil, ErrInvalidVault
		}
		ownerPub, err := hex.DecodeString(v.OwnerPub)
		if err != nil {
			return nil, ErrInvalidVault
		}
		sigPub, err := hex.DecodeString(v.OwnerSigPub)
		if err != nil {
			return nil, ErrInvalidVault
		}
		pubs := make([]string, 0, len(v.Recipients))
		for _, r := range v.Recipients {
			pubs = append(pubs, r.RecipientPub)
		}
		policyCoreID := hashJSON(policyMaterial{OwnerPub: ownerPub, OwnerSigPub: sigPub, CreatedAt: v.CreatedAt, Interval: v.IntervalSeconds, Grace: v.GraceSeconds, Recipients: pubs, PayloadNonce: bodyNonce, PayloadCiphertext: nil})
		plain, err := sporecrypto.OpenAAD(bodyCiphertext, payloadKey, bodyNonce, bodyAAD(policyCoreID))
		if err != nil {
			return nil, ErrInvalidVault
		}
		return plain, nil
	}
	return nil, ErrRecipientNotFound
}

// Verify authenticates the entire vault structure and check-in chain without
// requiring any private key. It detects tampered recipient envelopes, body,
// policy, identity, deadlines, and signatures.
func (v *Vault) Verify() error {
	if v == nil || v.Version != vaultVersion || v.VaultID == "" || v.PolicyID == "" || len(v.Recipients) == 0 || len(v.Checkins) == 0 {
		return ErrInvalidVault
	}
	ownerPub, err := decodeFixed(v.OwnerPub, 32)
	if err != nil {
		return err
	}
	sigPub, err := decodeFixed(v.OwnerSigPub, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	payloadNonce, err := decodeFixed(v.PayloadNonce, sporecrypto.NonceSize)
	if err != nil {
		return err
	}
	payloadCiphertext, err := hex.DecodeString(v.PayloadCiphertext)
	if err != nil || len(payloadCiphertext) < sporecrypto.KeySize/2 {
		return ErrInvalidVault
	}
	if v.CreatedAt <= 0 || v.IntervalSeconds <= 0 || v.GraceSeconds < 0 {
		return ErrInvalidVault
	}
	pubs := make([]string, 0, len(v.Recipients))
	for _, r := range v.Recipients {
		if _, err := decodeFixed(r.RecipientPub, 32); err != nil {
			return err
		}
		if _, err := decodeFixed(r.EphemeralPub, 32); err != nil {
			return err
		}
		if _, err := decodeFixed(r.Nonce, sporecrypto.NonceSize); err != nil {
			return err
		}
		ct, err := hex.DecodeString(r.Ciphertext)
		if err != nil || len(ct) < sporecrypto.KeySize/2 {
			return ErrInvalidVault
		}
		pubs = append(pubs, r.RecipientPub)
	}
	sorted := append([]string(nil), pubs...)
	sort.Strings(sorted)
	if !equalStrings(pubs, sorted) {
		return fmt.Errorf("%w: recipients are not canonicalized", ErrInvalidVault)
	}
	policyID := hashJSON(policyMaterial{OwnerPub: ownerPub, OwnerSigPub: sigPub, CreatedAt: v.CreatedAt, Interval: v.IntervalSeconds, Grace: v.GraceSeconds, Recipients: pubs, PayloadNonce: payloadNonce, PayloadCiphertext: payloadCiphertext})
	if policyID != v.PolicyID {
		return fmt.Errorf("%w: policy commitment mismatch", ErrInvalidVault)
	}
	vaultID := hashJSON(vaultMaterial{PolicyID: policyID, PayloadNonce: payloadNonce, PayloadCiphertext: payloadCiphertext, Recipients: v.Recipients})
	if vaultID != v.VaultID {
		return fmt.Errorf("%w: vault commitment mismatch", ErrInvalidVault)
	}
	for i, c := range v.Checkins {
		if c.Seq != uint64(i) || c.At <= 0 || c.Deadline <= c.At || (i != 0 && c.Prev == "") {
			return fmt.Errorf("%w: malformed check-in %d", ErrInvalidVault, i)
		}
		if i == 0 {
			if c.At != v.CreatedAt {
				return fmt.Errorf("%w: genesis time mismatch", ErrInvalidVault)
			}
		} else {
			if c.At <= v.Checkins[i-1].At || c.Prev != checkinDigest(v.Checkins[i-1]) {
				return fmt.Errorf("%w: check-in chain mismatch at %d", ErrInvalidVault, i)
			}
		}
		expectedDeadline, ok := safeAdd(c.At, v.IntervalSeconds+v.GraceSeconds)
		if !ok || c.Deadline != expectedDeadline {
			return fmt.Errorf("%w: deadline mismatch at %d", ErrInvalidVault, i)
		}
		sig, err := hex.DecodeString(c.Sig)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(sigPub), checkinTranscript(v.VaultID, c), sig) {
			return fmt.Errorf("%w: check-in signature %d", ErrInvalidVault, i)
		}
	}
	return nil
}

type policyMaterial struct {
	OwnerPub          []byte   `json:"owner_pub"`
	OwnerSigPub       []byte   `json:"owner_sig_pub"`
	CreatedAt         int64    `json:"created_at"`
	Interval          int64    `json:"interval"`
	Grace             int64    `json:"grace"`
	Recipients        []string `json:"recipients"`
	PayloadNonce      []byte   `json:"payload_nonce"`
	PayloadCiphertext []byte   `json:"payload_ciphertext"`
}

type vaultMaterial struct {
	PolicyID          string          `json:"policy_id"`
	PayloadNonce      []byte          `json:"payload_nonce"`
	PayloadCiphertext []byte          `json:"payload_ciphertext"`
	Recipients        []RecipientWrap `json:"recipients"`
}

func durationSeconds(interval, grace time.Duration) (int64, int64, error) {
	if interval <= 0 || interval%time.Second != 0 || grace < 0 || grace%time.Second != 0 {
		return 0, 0, fmt.Errorf("%w: interval must be whole positive seconds and grace whole non-negative seconds", ErrInvalidVault)
	}
	i, g := int64(interval/time.Second), int64(grace/time.Second)
	if i > 0 && g > (int64(^uint64(0)>>1)-i) {
		return 0, 0, fmt.Errorf("%w: interval plus grace overflows", ErrInvalidVault)
	}
	return i, g, nil
}

func safeAdd(a, b int64) (int64, bool) {
	if b < 0 || a > int64(^uint64(0)>>1)-b {
		return 0, false
	}
	return a + b, true
}

func signingKey(ownerPriv []byte) ed25519.PrivateKey {
	h := sha256.New()
	h.Write([]byte(domain + "/owner-sign/v1"))
	h.Write(ownerPriv)
	seed := h.Sum(nil)
	return ed25519.NewKeyFromSeed(seed)
}

func signCheckin(priv ed25519.PrivateKey, vaultID string, c CheckInRecord) string {
	return hex.EncodeToString(ed25519.Sign(priv, checkinTranscript(vaultID, c)))
}

func checkinTranscript(vaultID string, c CheckInRecord) []byte {
	b, _ := json.Marshal(struct {
		Domain string `json:"domain"`
		Vault  string `json:"vault_id"`
		Seq    uint64 `json:"seq"`
		At     int64  `json:"at"`
		Due    int64  `json:"deadline"`
		Prev   string `json:"prev"`
	}{domain, vaultID, c.Seq, c.At, c.Deadline, c.Prev})
	return b
}

func checkinDigest(c CheckInRecord) string {
	b, _ := json.Marshal(struct {
		Seq      uint64 `json:"seq"`
		At       int64  `json:"at"`
		Deadline int64  `json:"deadline"`
		Prev     string `json:"prev"`
		Sig      string `json:"sig"`
	}{c.Seq, c.At, c.Deadline, c.Prev, c.Sig})
	s := sha256.Sum256(append([]byte(domain+"/checkin/v1"), b...))
	return hex.EncodeToString(s[:])
}

func bodyAAD(policyID string) []byte { return []byte(domain + "/body/" + policyID) }

func wrapAAD(policyID string, eph, recipient []byte) []byte {
	b := append([]byte(domain+"/wrap/"+policyID+"/"), eph...)
	return append(b, recipient...)
}

func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(append([]byte(domain+"/commit/"), b...))
	return hex.EncodeToString(s[:])
}

func decodeFixed(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, ErrInvalidVault
	}
	return b, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// MarshalBinary gives callers a stable JSON representation for files and
// transport. It is intentionally just JSON so operators can inspect metadata
// without exposing plaintext.
func (v *Vault) MarshalBinary() ([]byte, error) { return json.Marshal(v) }

// Parse decodes and verifies a vault before returning it.
func Parse(raw []byte) (*Vault, error) {
	var v Vault
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if err := v.Verify(); err != nil {
		return nil, err
	}
	return &v, nil
}
