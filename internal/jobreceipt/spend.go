package jobreceipt

// Spend receipts: the client-side, provider-blind accounting record
// (docs/JOB_RECEIPT_V1.md §4).
//
// WHY THIS IS A SEPARATE DOCUMENT AND NOT A FLAG ON THE ATTESTED RECEIPT
//
// An attested receipt names the provider's key, so it can never be published as
// an expense row without linking client to provider. A spend receipt is what a
// client keeps for bookkeeping: what it paid, when, in which asset, backed by a
// txid — and no provider identity beyond an optional salted commitment the
// client alone can open. It is deliberately NOT a reputation signal: nothing
// here is co-signed, so a rating derived from one would be a self-declaration.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// SpendProtocol and its kind are distinct from the attested receipt, so a
	// reader can never mistake one for the other.
	SpendProtocol = "spore.spend-receipt"
	KindSpend     = "spend"

	// SpendStatement is the only statement a spend receipt may carry.
	SpendStatement = "spore.spend-receipt/v1 client declaration"

	// CommitmentScheme is inside the commitment's hash, so a value computed for
	// this scheme cannot be reinterpreted as an attestation digest.
	CommitmentScheme = "spore/provider-commitment/v1"

	// EvidenceChain means every settlement line carries a txid the reader can go
	// and check; EvidenceSelf means at least one does not, and the row is the
	// client's word. An export must print which, per row.
	EvidenceChain = "chain-backed"
	EvidenceSelf  = "self-declared"
)

// SpendRecord is one client declaration covering one period (or one job).
type SpendRecord struct {
	Protocol           string              `json:"protocol"`
	Version            int                 `json:"version"`
	Kind               string              `json:"kind"`
	ClientPub          string              `json:"client_pub"`
	Period             *Period             `json:"period,omitempty"`
	Service            Service             `json:"service"`
	Settlement         []Settlement        `json:"settlement"`
	Evidence           string              `json:"evidence"`
	ProviderCommitment *ProviderCommitment `json:"provider_commitment,omitempty"`
}

type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type ProviderCommitment struct {
	Scheme string `json:"scheme"`
	Value  string `json:"value"`
}

// CommitmentFor hashes the scheme, the provider's public key and the client's
// salt. The salt is what keeps the record blind; losing it means the link can
// never be proven, which is the honest trade (see OpenItems in the doc).
func CommitmentFor(providerPub string, salt []byte) (string, error) {
	if !reHex64.MatchString(providerPub) {
		return "", errors.New("jobreceipt: provider public key must be 64 lowercase hex characters")
	}
	if len(salt) != 32 {
		return "", fmt.Errorf("jobreceipt: commitment salt must be 32 bytes, got %d", len(salt))
	}
	pub, err := hex.DecodeString(providerPub)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(CommitmentScheme))
	h.Write(pub)
	h.Write(salt)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// OpensCommitment reports whether salt opens value to providerPub — the check an
// auditor runs when a client claims a row refers to a particular provider.
func OpensCommitment(providerPub string, salt []byte, value string) (bool, error) {
	got, err := CommitmentFor(providerPub, salt)
	if err != nil {
		return false, err
	}
	return got == value, nil
}

// DeriveEvidence is the only writing of `evidence` the format allows: claimed
// chain backing must match the data, so a row with a missing txid cannot be
// labelled as verified.
func DeriveEvidence(lines []Settlement) string {
	for _, s := range lines {
		if s.TxID == "" {
			return EvidenceSelf
		}
	}
	return EvidenceChain
}

// Encode returns the canonical bytes, validating first.
func (r *SpendRecord) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return Canonical(r)
}

func (r *SpendRecord) Validate() error {
	if r.Protocol != SpendProtocol {
		return fmt.Errorf("jobreceipt: protocol %q, want %q", r.Protocol, SpendProtocol)
	}
	if r.Version != Version {
		return fmt.Errorf("jobreceipt: version %d, want %d", r.Version, Version)
	}
	if r.Kind != KindSpend {
		return fmt.Errorf("jobreceipt: kind %q, want %q", r.Kind, KindSpend)
	}
	if err := checkPub(RoleClient, r.ClientPub); err != nil {
		return err
	}
	if r.Period != nil {
		from, err := checkStamp("period.from", r.Period.From)
		if err != nil {
			return err
		}
		to, err := checkStamp("period.to", r.Period.To)
		if err != nil {
			return err
		}
		if to.Before(from) {
			return errors.New("jobreceipt: period.to precedes period.from")
		}
	}
	if r.Service.Category == "" {
		return errors.New("jobreceipt: service.category is required")
	}
	if r.Service.Summary == "" {
		return errors.New("jobreceipt: service.summary is required")
	}
	if len(r.Settlement) == 0 {
		return errors.New("jobreceipt: at least one settlement line is required")
	}
	for i, s := range r.Settlement {
		if err := checkSettlementLine(fmt.Sprintf("settlement[%d]", i), s, false); err != nil {
			return err
		}
	}
	want := DeriveEvidence(r.Settlement)
	if r.Evidence != want {
		return fmt.Errorf("jobreceipt: evidence %q contradicts the settlement lines (they derive %q): a line without a txid cannot be called chain-backed", r.Evidence, want)
	}
	if c := r.ProviderCommitment; c != nil {
		if c.Scheme != CommitmentScheme {
			return fmt.Errorf("jobreceipt: provider_commitment.scheme %q, want %q", c.Scheme, CommitmentScheme)
		}
		if !reDigest.MatchString(c.Value) {
			return errors.New("jobreceipt: provider_commitment.value must be \"sha256:\" plus 64 lowercase hex characters")
		}
	}
	return nil
}

// ParseSpend decodes and validates a spend receipt, rejecting unknown fields and
// non-canonical bytes exactly as Parse does for the attested kind.
func ParseSpend(body []byte) (*SpendRecord, error) {
	var rec SpendRecord
	if err := parseStrict(body, &rec); err != nil {
		return nil, err
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	want, err := rec.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, body) {
		return nil, fmt.Errorf("jobreceipt: record is not in canonical form (§2): re-emit it with `spore sign receipt spend`; this file is %d bytes, canonical form is %d", len(body), len(want))
	}
	return &rec, nil
}

// ProtocolOf sniffs the protocol field so a verifier can dispatch before it
// decodes the record, and so an unknown protocol is rejected by name.
func ProtocolOf(body []byte) (string, error) {
	var head struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return "", fmt.Errorf("jobreceipt: not JSON: %w", err)
	}
	return head.Protocol, nil
}

// parseStrict decodes one object with unknown fields rejected, and refuses
// trailing data.
func parseStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("jobreceipt: %w", err)
	}
	if dec.More() {
		return errors.New("jobreceipt: trailing data after the record object")
	}
	return nil
}
