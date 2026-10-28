// Package jobreceipt implements the signed job receipt specified in
// docs/JOB_RECEIPT_V1.md: the record type, its canonical byte form, the
// per-role signing statements, and the checks a verifier must perform.
//
// # WHY THE BYTES ARE THE FORMAT
//
// A receipt is signed with attest.Sign, which signs the SHA-256 and length of a
// FILE plus a statement — there is no canonicalization inside the signature. Two
// parties who serialize the same record differently therefore sign two different
// documents and produce two records that cannot be joined. So Canonical here is
// not a convenience printer: it is the definition of the artifact, and Parse
// rejects a file that is not in that form rather than silently accepting bytes
// no other implementation would reproduce.
package jobreceipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const (
	// Protocol and Version are the only values a v1 reader accepts.
	Protocol = "spore.job-receipt"
	Version  = 1

	// KindAttested is the dual-signature receipt. A spend receipt is a different
	// document (docs/JOB_RECEIPT_V1.md §4) and is not emitted here yet.
	KindAttested = "attested"

	// CoverageProviderOnly marks a one-signer record: the provider attested, the
	// client did not. It is not a reputation entry.
	CoverageProviderOnly = "provider-only"

	// The statements are INSIDE the signed transcript, so they are protocol
	// constants. Changing either invalidates every receipt ever produced.
	ClientStatement   = "spore.job-receipt/v1 client acceptance"
	ProviderStatement = "spore.job-receipt/v1 provider attestation"

	// Role names for command surfaces and error messages.
	RoleClient   = "client"
	RoleProvider = "provider"

	// SchemeMoneroTxProofV1 is the only tx-proof scheme v1 defines: a Monero
	// get_tx_proof signature, verifiable with check_tx_proof in any wallet that
	// holds the payment (docs/MONERO_SETTLEMENT.md §4).
	SchemeMoneroTxProofV1 = "monero-tx-proof-v1"

	// ProofPrefix begins the message a tx proof must be about; the rest is the
	// record's identity with its proofs stripped (ProofMessage).
	ProofPrefix = "spore.job-receipt/v1 tx-proof "
)

// schemeRail maps a proof scheme to the rail it can be evidence on. A proof
// names the chain that produced it, so a line citing a different rail cannot
// carry it: a Monero proof is not evidence about a DERO payment.
var schemeRail = map[string]string{SchemeMoneroTxProofV1: "xmr"}

// SchemeRail reports the rail a proof scheme belongs to.
func SchemeRail(scheme string) (string, bool) {
	rail, ok := schemeRail[scheme]
	return rail, ok
}

// Record is one job receipt. Field order here is irrelevant to the artifact —
// Canonical sorts keys — but the tags are the wire names and must not drift.
type Record struct {
	Protocol      string         `json:"protocol"`
	Version       int            `json:"version"`
	Kind          string         `json:"kind"`
	Coverage      string         `json:"coverage,omitempty"`
	Service       Service        `json:"service"`
	Parties       Parties        `json:"parties"`
	Work          Work           `json:"work"`
	Settlement    []Settlement   `json:"settlement"`
	Deliverables  []Deliverable  `json:"deliverables,omitempty"`
	ClientVerdict *ClientVerdict `json:"client_verdict,omitempty"`
	Links         *Links         `json:"links,omitempty"`
	Supersedes    string         `json:"supersedes,omitempty"`
}

type Service struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
}

type Parties struct {
	// ClientPub is empty exactly when Coverage is provider-only.
	ClientPub   string `json:"client_pub,omitempty"`
	ProviderPub string `json:"provider_pub"`
}

type Work struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type Settlement struct {
	Rail         string `json:"rail"`
	Network      string `json:"network"`
	Asset        string `json:"asset"`
	AmountAtomic string `json:"amount_atomic"`
	// TxID is required by the attested kind and optional on a spend receipt,
	// where an absent txid is exactly what makes the row self-declared.
	TxID      string `json:"txid,omitempty"`
	SettledAt string `json:"settled_at"`
	// TxProof is OPTIONAL evidence that this payment exists on-chain — the
	// chain's own answer rather than the payer's claim. Absent is the default
	// and costs nothing: §7's table then applies unchanged ("only as far as the
	// cited txid verifies on-chain") and it is the VIEWER who has to find that
	// out. Present, it is bound to this record's identity (ProofMessage), so it
	// cannot be moved to another record or kept after an amount was edited.
	TxProof *TxProof `json:"tx_proof,omitempty"`
}

// TxProof is one chain proof, bound to the record it sits in. Deliberately not
// a free-form blob: the scheme says which chain and how to check it, the address
// is what the chain proved a payment TO, and message/signature are the artifact
// itself. What it proves is narrow — this txid paid that address, for this
// record's sake — and the caveats in MONERO_SETTLEMENT §4 (no proof that the
// work happened, or that the funds are still spendable, or who the parties are)
// travel with every row that carries one.
type TxProof struct {
	Scheme    string `json:"scheme"`
	Address   string `json:"address"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// ProofMessage is the exact message a tx proof must be about: this record's
// identity with every tx_proof block removed.
//
// The circularity is real, and this is the way out of it. A proof cannot be
// bound to the digest of the document that CONTAINS it, because attaching the
// block changes that digest — the binding would be false the moment it became
// true. Binding to the proof-less record is stable instead: a signer computes it
// before attaching anything, a verifier recomputes it by stripping the blocks and
// re-printing canonically (Canonical sorts every key, so both sides get identical
// bytes), and a proof carried to another record, or taken before an amount was
// changed, simply does not match.
//
// v is a *Record or a *SpendRecord; both carry a "settlement" array.
func ProofMessage(v any) (string, error) {
	pre, err := canonicalWithoutProofs(v)
	if err != nil {
		return "", err
	}
	return ProofPrefix + ID(pre), nil
}

func canonicalWithoutProofs(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	top, ok := generic.(map[string]any)
	if !ok {
		return nil, errors.New("jobreceipt: record is not a JSON object")
	}
	// Drop the proof from every line, so the message depends only on the facts
	// the proof is evidence FOR.
	if lines, ok := top["settlement"].([]any); ok {
		for _, line := range lines {
			if m, ok := line.(map[string]any); ok {
				delete(m, "tx_proof")
			}
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type Deliverable struct {
	Label  string `json:"label"`
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

type ClientVerdict struct {
	Accepted bool   `json:"accepted"`
	Rating   int    `json:"rating,omitempty"`
	Note     string `json:"note,omitempty"`
}

type Links struct {
	WorkOrderID   string `json:"work_order_id,omitempty"`
	ThreadSession string `json:"thread_session,omitempty"`
}

var (
	reHex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reDigest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reAmount   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	reStampUTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
)

// Canonical prints v in the form §2 defines: two-space indent, keys sorted at
// every depth, no HTML escaping, "\n" line endings, one trailing newline. It
// round-trips through a generic map so struct field order can never leak into
// the artifact.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Encode returns the record's canonical bytes.
func (r *Record) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return Canonical(r)
}

// ID is the receipt's identity: the SHA-256 of its canonical bytes. A verifier
// computes it; a signer never reports it.
func ID(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Parse decodes a record from bytes and runs every semantic check. Unknown
// fields are rejected, because a reader that ignores them would accept "the
// same" record with extra signed content it does not understand.
func Parse(body []byte) (*Record, error) {
	var rec Record
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
		return nil, fmt.Errorf("jobreceipt: record is not in canonical form (§2): re-emit it with `spore sign receipt create`; this file is %d bytes, canonical form is %d", len(body), len(want))
	}
	return &rec, nil
}

// Validate checks the record's internal consistency. It says nothing about
// signatures — that is Verify's job, and the two questions must stay separate.
func (r *Record) Validate() error {
	if r.Protocol != Protocol {
		return fmt.Errorf("jobreceipt: protocol %q, want %q", r.Protocol, Protocol)
	}
	if r.Version != Version {
		return fmt.Errorf("jobreceipt: version %d, want %d", r.Version, Version)
	}
	if r.Kind != KindAttested {
		return fmt.Errorf("jobreceipt: kind %q is not supported (v1 emits %q)", r.Kind, KindAttested)
	}
	if r.Service.Category == "" {
		return errors.New("jobreceipt: service.category is required")
	}
	if r.Service.Summary == "" {
		return errors.New("jobreceipt: service.summary is required")
	}
	if err := checkPub(RoleProvider, r.Parties.ProviderPub); err != nil {
		return err
	}
	switch r.Coverage {
	case "":
		if err := checkPub(RoleClient, r.Parties.ClientPub); err != nil {
			return err
		}
	case CoverageProviderOnly:
		if r.Parties.ClientPub != "" {
			return errors.New("jobreceipt: a provider-only record must not name a client key")
		}
		if r.ClientVerdict != nil {
			return errors.New("jobreceipt: a provider-only record cannot carry a client verdict")
		}
		if r.Parties.ClientPub == r.Parties.ProviderPub {
			return errors.New("jobreceipt: client and provider keys must differ")
		}
	default:
		return fmt.Errorf("jobreceipt: coverage %q is not defined (want empty or %q)", r.Coverage, CoverageProviderOnly)
	}
	if r.Parties.ClientPub != "" && r.Parties.ClientPub == r.Parties.ProviderPub {
		return errors.New("jobreceipt: client and provider keys must differ")
	}
	start, err := checkStamp("work.started_at", r.Work.StartedAt)
	if err != nil {
		return err
	}
	finish, err := checkStamp("work.finished_at", r.Work.FinishedAt)
	if err != nil {
		return err
	}
	if finish.Before(start) {
		return errors.New("jobreceipt: work.finished_at precedes work.started_at")
	}
	if len(r.Settlement) == 0 {
		return errors.New("jobreceipt: at least one settlement line is required")
	}
	// Every tx_proof must be about THIS record. The binding is computed once,
	// over the record with its proofs stripped, so a proof lifted from another
	// receipt — or taken before an amount was edited — fails here rather than
	// passing as evidence.
	var binding string
	for _, s := range r.Settlement {
		if s.TxProof != nil {
			binding, err = ProofMessage(r)
			if err != nil {
				return err
			}
			break
		}
	}
	for i, s := range r.Settlement {
		// An attested receipt always cites the payment: without a txid there is
		// nothing for the provider's signature to be about.
		if err := checkSettlementLine(fmt.Sprintf("settlement[%d]", i), s, true, binding); err != nil {
			return err
		}
	}
	for i, d := range r.Deliverables {
		where := fmt.Sprintf("deliverables[%d]", i)
		if d.Label == "" {
			return fmt.Errorf("jobreceipt: %s.label is required", where)
		}
		if !reDigest.MatchString(d.Digest) {
			return fmt.Errorf("jobreceipt: %s.digest %q must be \"sha256:\" plus 64 lowercase hex characters", where, d.Digest)
		}
		if d.Bytes < 0 {
			return fmt.Errorf("jobreceipt: %s.bytes must not be negative", where)
		}
	}
	if v := r.ClientVerdict; v != nil {
		if v.Rating != 0 && (v.Rating < 1 || v.Rating > 5) {
			return fmt.Errorf("jobreceipt: client_verdict.rating %d is outside 1..5", v.Rating)
		}
		if v.Rating != 0 && !v.Accepted {
			return errors.New("jobreceipt: a declined job cannot carry a rating")
		}
	}
	if r.Supersedes != "" && !reDigest.MatchString(r.Supersedes) {
		return errors.New("jobreceipt: supersedes must be \"sha256:\" plus 64 lowercase hex characters")
	}
	return nil
}

// checkSettlementLine validates one money row. requireTx is true for the
// attested kind (the payment is what the provider attests to) and false for a
// spend receipt, where a self-declared bookkeeping row may cite none. binding is
// the record's ProofMessage, or "" when no line carries a proof.
func checkSettlementLine(where string, s Settlement, requireTx bool, binding string) error {
	for name, v := range map[string]string{"rail": s.Rail, "network": s.Network, "asset": s.Asset} {
		if v == "" {
			return fmt.Errorf("jobreceipt: %s.%s is required", where, name)
		}
	}
	if !reAmount.MatchString(s.AmountAtomic) {
		return fmt.Errorf("jobreceipt: %s.amount_atomic %q must be a decimal string of non-negative integer atomic units (no sign, no decimal point)", where, s.AmountAtomic)
	}
	if requireTx {
		if !reHex64.MatchString(s.TxID) {
			return fmt.Errorf("jobreceipt: %s.txid must be 64 lowercase hex characters", where)
		}
	} else if s.TxID != "" && !reHex64.MatchString(s.TxID) {
		return fmt.Errorf("jobreceipt: %s.txid must be empty or 64 lowercase hex characters", where)
	}
	if _, err := checkStamp(where+".settled_at", s.SettledAt); err != nil {
		return err
	}
	if p := s.TxProof; p != nil {
		if s.TxID == "" {
			return fmt.Errorf("jobreceipt: %s carries a tx_proof but no txid — a proof of nothing is not evidence", where)
		}
		rail, known := SchemeRail(p.Scheme)
		if !known {
			return fmt.Errorf("jobreceipt: %s.tx_proof.scheme %q is not defined (v1 defines %q)", where, p.Scheme, SchemeMoneroTxProofV1)
		}
		if rail != s.Rail {
			return fmt.Errorf("jobreceipt: %s.tx_proof.scheme %q is a %s proof, but the line settles on rail %q", where, p.Scheme, rail, s.Rail)
		}
		if p.Address == "" {
			return fmt.Errorf("jobreceipt: %s.tx_proof.address is required (a proof answers for a payment TO an address)", where)
		}
		if p.Signature == "" {
			return fmt.Errorf("jobreceipt: %s.tx_proof.signature is required", where)
		}
		if p.Message != binding {
			return fmt.Errorf("jobreceipt: %s.tx_proof.message is not this record's binding — a proof must be about THIS record (§7); want %q", where, binding)
		}
	}
	return nil
}

func checkPub(role, pub string) error {
	if pub == "" {
		return fmt.Errorf("jobreceipt: parties.%s_pub is required", role)
	}
	if !reHex64.MatchString(pub) {
		return fmt.Errorf("jobreceipt: parties.%s_pub must be 64 lowercase hex characters", role)
	}
	return nil
}

func checkStamp(field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("jobreceipt: %s is required", field)
	}
	if !reStampUTC.MatchString(value) {
		return time.Time{}, fmt.Errorf("jobreceipt: %s %q must be RFC 3339 UTC with a literal Z and no fractional seconds", field, value)
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("jobreceipt: %s %q: %w", field, value, err)
	}
	return t, nil
}

// RoleOf maps a signer key to the role it holds in this record. A key that is
// not a party cannot contribute to the receipt, no matter how valid its
// signature is.
func (r *Record) RoleOf(pub string) (string, error) {
	if pub != "" && pub == r.Parties.ProviderPub {
		return RoleProvider, nil
	}
	if pub != "" && pub == r.Parties.ClientPub {
		return RoleClient, nil
	}
	return "", fmt.Errorf("jobreceipt: %s is not a party to this record", pub)
}

// StatementFor is the statement a role MUST have signed. A signature carrying
// any other statement is a valid signature over a different assertion, which is
// why every verifier has to compare it instead of trusting the envelope.
func StatementFor(role string) (string, error) {
	switch role {
	case RoleClient:
		return ClientStatement, nil
	case RoleProvider:
		return ProviderStatement, nil
	}
	return "", fmt.Errorf("jobreceipt: unknown role %q (want %q or %q)", role, RoleClient, RoleProvider)
}

// SortSettlements orders lines the way §9 requires an export to print them —
// by settlement time, then txid — so two emitters of the same facts produce the
// same bytes and therefore the same receipt id.
func SortSettlements(lines []Settlement) {
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].SettledAt != lines[j].SettledAt {
			return lines[i].SettledAt < lines[j].SettledAt
		}
		return lines[i].TxID < lines[j].TxID
	})
}

// PubFor is the key that role must sign with.
func (r *Record) PubFor(role string) (string, error) {
	switch role {
	case RoleClient:
		if r.Parties.ClientPub == "" {
			return "", errors.New("jobreceipt: this record has no client key (coverage: provider-only)")
		}
		return r.Parties.ClientPub, nil
	case RoleProvider:
		return r.Parties.ProviderPub, nil
	}
	return "", fmt.Errorf("jobreceipt: unknown role %q (want %q or %q)", role, RoleClient, RoleProvider)
}
