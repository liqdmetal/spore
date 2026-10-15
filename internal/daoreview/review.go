// Package daoreview coordinates explicit human review, not DAO membership
// discovery, consensus, execution, spending authority, or independent truth.
package daoreview

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/secure"
)

const (
	ManifestDomain    = "spore/dao-review/manifest/v1"
	DecisionDomain    = "spore/dao-review/decision/v1"
	CertificateDomain = "spore/dao-review/certificate/v1"
	MaxReviewers      = 16
	MaxCertificate    = 64 << 10
)

type Manifest struct {
	Version      int            `json:"version"`
	ID           string         `json:"id"`
	DAO          string         `json:"dao"`
	Proposal     string         `json:"proposal"`
	Epoch        uint64         `json:"epoch"`
	Coordinator  handoff.Peer   `json:"coordinator"`
	EvidenceHash string         `json:"evidence_hash"`
	PolicyHash   string         `json:"policy_hash"`
	Reviewers    []handoff.Peer `json:"reviewers"`
	Threshold    int            `json:"threshold"`
	CreatedAt    int64          `json:"created_at"`
	Deadline     int64          `json:"deadline"`
	ExpiresAt    int64          `json:"expires_at"`
}

type SignedManifest struct {
	Domain    string   `json:"domain"`
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}

// Packet travels as a handoff's private policy bytes. Only its signed manifest
// is exported in a certificate; Policy and the handoff's evidence stay private.
type Packet struct {
	Review SignedManifest `json:"review"`
	Policy []byte         `json:"policy"`
}

type Decision struct {
	Version    int          `json:"version"`
	ReviewHash string       `json:"review_hash"`
	HandoffID  string       `json:"handoff_id"`
	BriefHash  string       `json:"brief_hash"`
	Reviewer   handoff.Peer `json:"reviewer"`
	Choice     string       `json:"choice"`
	At         int64        `json:"at"`
}

type SignedDecision struct {
	Domain    string   `json:"domain"`
	Decision  Decision `json:"decision"`
	Signature string   `json:"signature"`
}

type Certificate struct {
	Domain    string           `json:"domain"`
	Version   int              `json:"version"`
	Review    SignedManifest   `json:"review"`
	Approvals []SignedDecision `json:"approvals"`
}

func validHex(s string, n int) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == n && hex.EncodeToString(raw) == s
}
func validHash(s string) bool {
	return strings.HasPrefix(s, "sha256:") && validHex(strings.TrimPrefix(s, "sha256:"), 32)
}
func label(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n")
}
func hash(v any) string               { raw, _ := json.Marshal(v); return handoff.Commitment(raw) }
func (s SignedManifest) Hash() string { return hash(s) }

func (m Manifest) Validate() error {
	if m.Version != 1 || !validHex(m.ID, 16) || !label(m.DAO) || !label(m.Proposal) || m.Epoch == 0 || !validHash(m.EvidenceHash) || !validHash(m.PolicyHash) {
		return errors.New("dao-review: invalid manifest identifiers/commitments")
	}
	if err := m.Coordinator.Validate(); err != nil {
		return err
	}
	if len(m.Reviewers) < 1 || len(m.Reviewers) > MaxReviewers || m.Threshold <= len(m.Reviewers)/2 || m.Threshold > len(m.Reviewers) {
		return errors.New("dao-review: threshold must be a strict majority of 1..16 explicit reviewers")
	}
	if m.CreatedAt <= 0 || m.Deadline <= m.CreatedAt || m.ExpiresAt <= m.Deadline || m.ExpiresAt-m.CreatedAt > int64((30*24*time.Hour)/time.Second) {
		return errors.New("dao-review: invalid deadline/expiry (maximum 30 days)")
	}
	addresses, pins := map[string]bool{}, map[string]bool{}
	prior := ""
	for _, p := range m.Reviewers {
		if err := p.Validate(); err != nil {
			return err
		}
		if p.Address == m.Coordinator.Address || p.Pinned == m.Coordinator.Pinned || addresses[p.Address] || pins[p.Pinned] || p.Pinned <= prior {
			return errors.New("dao-review: roster must be sorted by distinct pins, unique addresses, and exclude coordinator")
		}
		addresses[p.Address], pins[p.Pinned], prior = true, true, p.Pinned
	}
	return nil
}

func sign(domain string, body any, identity []byte, pin string) (string, error) {
	pub, err := secure.SigPubOf(identity)
	if err != nil {
		return "", err
	}
	if hex.EncodeToString(pub) != pin {
		return "", errors.New("dao-review: local signing identity mismatch")
	}
	key, err := secure.SigKeypairOf(identity)
	if err != nil {
		return "", err
	}
	defer clear(key)
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(key, append([]byte(domain+"\x00"), raw...))), nil
}
func verify(domain string, body any, pin, sig string) error {
	if !validHex(pin, 32) || !validHex(sig, 64) {
		return errors.New("dao-review: invalid signature encoding")
	}
	pub, _ := hex.DecodeString(pin)
	signature, _ := hex.DecodeString(sig)
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, append([]byte(domain+"\x00"), raw...), signature) {
		return errors.New("dao-review: signature mismatch")
	}
	return nil
}
func SignManifest(m Manifest, key []byte) (SignedManifest, error) {
	m.Reviewers = append([]handoff.Peer(nil), m.Reviewers...)
	sort.Slice(m.Reviewers, func(i, j int) bool { return m.Reviewers[i].Pinned < m.Reviewers[j].Pinned })
	if err := m.Validate(); err != nil {
		return SignedManifest{}, err
	}
	sig, err := sign(ManifestDomain, m, key, m.Coordinator.Pinned)
	return SignedManifest{ManifestDomain, m, sig}, err
}
func (s SignedManifest) Verify() error {
	if s.Domain != ManifestDomain {
		return errors.New("dao-review: wrong manifest domain")
	}
	if err := s.Manifest.Validate(); err != nil {
		return err
	}
	return verify(s.Domain, s.Manifest, s.Manifest.Coordinator.Pinned, s.Signature)
}

// InvitationID prevents duplicate invitation histories for one review/key.
func InvitationID(review SignedManifest, peer handoff.Peer) string {
	return strings.TrimPrefix(hash(struct {
		ReviewHash string       `json:"review_hash"`
		Reviewer   handoff.Peer `json:"reviewer"`
	}{review.Hash(), peer}), "sha256:")[:32]
}

func (m Manifest) Allows(p handoff.Peer) bool {
	for _, r := range m.Reviewers {
		if r == p {
			return true
		}
	}
	return false
}
func EncodePacket(p Packet) ([]byte, error) {
	if err := p.Review.Verify(); err != nil {
		return nil, err
	}
	if len(p.Policy) == 0 || handoff.Commitment(p.Policy) != p.Review.Manifest.PolicyHash {
		return nil, errors.New("dao-review: private policy commitment mismatch")
	}
	raw, err := json.Marshal(p)
	if len(raw) > handoff.MaxPolicy {
		return nil, errors.New("dao-review: manifest plus policy exceeds handoff's 8 KiB policy limit")
	}
	return raw, err
}
func DecodePacket(raw []byte) (Packet, error) {
	var p Packet
	if err := handoff.DecodeJSON(raw, &p, handoff.MaxPolicy); err != nil {
		return p, err
	}
	_, err := EncodePacket(p)
	return p, err
}

// FromBrief validates the whole private packet against the signed immutable
// manifest, including actual evidence, exact buyer/reviewer and retention.
func FromBrief(e handoff.Envelope) (Packet, error) {
	if err := e.Verify(); err != nil {
		return Packet{}, err
	}
	if e.Message.Kind != "brief" {
		return Packet{}, errors.New("dao-review: expected original handoff brief")
	}
	p, err := DecodePacket(e.Message.Policy)
	if err != nil {
		return p, err
	}
	m := p.Review.Manifest
	t := e.Message.Terms
	if t.Registration.Source != "local-dao-review" || t.Registration.Objective.ObjectiveID != "dao-review:"+m.ID || t.Registration.Objective.OwnerPseudonym != m.Coordinator.Pinned || t.ID != InvitationID(p.Review, t.Provider) || t.Buyer != m.Coordinator || !m.Allows(t.Provider) || t.ExpiresAt != m.ExpiresAt || handoff.Commitment(e.Message.Content) != m.EvidenceHash {
		return p, errors.New("dao-review: handoff does not match proposal commitments/participants")
	}
	return p, nil
}
func SignDecision(brief handoff.Envelope, reviewer handoff.Peer, choice string, identity []byte, now time.Time) (SignedDecision, error) {
	packet, err := FromBrief(brief)
	if err != nil {
		return SignedDecision{}, err
	}
	if brief.Message.Recipient() != reviewer {
		return SignedDecision{}, errors.New("dao-review: not this reviewer's invitation")
	}
	d := Decision{1, packet.Review.Hash(), brief.Message.Terms.ID, brief.Hash(), reviewer, choice, now.Unix()}
	s := SignedDecision{Domain: DecisionDomain, Decision: d}
	s.Signature, err = sign(s.Domain, d, identity, reviewer.Pinned)
	if err != nil {
		return s, err
	}
	return s, s.VerifyFor(packet.Review)
}
func (s SignedDecision) VerifyFor(review SignedManifest) error {
	if err := review.Verify(); err != nil {
		return err
	}
	d := s.Decision
	m := review.Manifest
	if s.Domain != DecisionDomain || d.Version != 1 || d.ReviewHash != review.Hash() || d.HandoffID != InvitationID(review, d.Reviewer) || !validHash(d.BriefHash) || !m.Allows(d.Reviewer) || (d.Choice != "approve" && d.Choice != "reject") || d.At < m.CreatedAt || d.At >= m.Deadline {
		return errors.New("dao-review: decision is outside immutable review membership/window/bindings")
	}
	return verify(s.Domain, d, d.Reviewer.Pinned, s.Signature)
}
func DecodeDecision(raw []byte, review SignedManifest) (SignedDecision, error) {
	var d SignedDecision
	if err := handoff.DecodeJSON(raw, &d, handoff.MaxContent); err != nil {
		return d, err
	}
	return d, d.VerifyFor(review)
}
func DecisionFromRecord(r handoff.Record) (SignedDecision, error) {
	if len(r.Events) < 2 {
		return SignedDecision{}, errors.New("dao-review: awaiting reviewer decision")
	}
	packet, err := FromBrief(r.Events[0])
	if err != nil {
		return SignedDecision{}, err
	}
	e := r.Events[1]
	if err := e.Verify(); err != nil {
		return SignedDecision{}, err
	}
	d, err := DecodeDecision(e.Message.Content, packet.Review)
	if err != nil {
		return d, err
	}
	if e.Message.Terms != r.Events[0].Message.Terms || e.Message.Sequence != 2 || e.Message.Kind != "deliver" || e.Message.Previous != r.Events[0].Hash() || e.Message.Sender() != d.Decision.Reviewer || d.Decision.HandoffID != r.Events[0].Message.Terms.ID || d.Decision.BriefHash != r.Events[0].Hash() {
		return d, errors.New("dao-review: decision does not bind this invitation")
	}
	return d, nil
}

func NewCertificate(review SignedManifest, decisions []SignedDecision, now time.Time) (Certificate, error) {
	if err := review.Verify(); err != nil {
		return Certificate{}, err
	}
	if len(decisions) > MaxReviewers {
		return Certificate{}, errors.New("dao-review: too many decisions")
	}
	if now.Unix() < review.Manifest.CreatedAt || now.Unix() >= review.Manifest.ExpiresAt {
		return Certificate{}, errors.New("dao-review: review expired")
	}
	seen := map[string]bool{}
	approvals := make([]SignedDecision, 0)
	for _, d := range decisions {
		if err := d.VerifyFor(review); err != nil {
			return Certificate{}, err
		}
		if d.Decision.At > now.Unix() {
			return Certificate{}, errors.New("dao-review: future decision")
		}
		pin := d.Decision.Reviewer.Pinned
		if seen[pin] {
			return Certificate{}, errors.New("dao-review: duplicate or conflicting reviewer decision")
		}
		seen[pin] = true
		if d.Decision.Choice == "approve" {
			approvals = append(approvals, d)
		}
	}
	if len(approvals) < review.Manifest.Threshold {
		return Certificate{}, errors.New("dao-review: approval quorum not met")
	}
	sort.Slice(approvals, func(i, j int) bool {
		return approvals[i].Decision.Reviewer.Pinned < approvals[j].Decision.Reviewer.Pinned
	})
	return Certificate{CertificateDomain, 1, review, approvals}, nil
}

// Verify requires the independently authenticated exact review hash. A
// certificate cannot establish its own DAO membership or proposal authority.
func (c Certificate) Verify(expected string, now time.Time) error {
	if !validHash(expected) || c.Review.Hash() != expected || c.Domain != CertificateDomain || c.Version != 1 {
		return errors.New("dao-review: certificate does not match trusted review hash/domain/version")
	}
	if len(c.Approvals) > MaxReviewers {
		return errors.New("dao-review: too many certificate approvals")
	}
	for _, d := range c.Approvals {
		if d.Decision.Choice != "approve" {
			return errors.New("dao-review: certificate contains non-approval")
		}
	}
	built, err := NewCertificate(c.Review, c.Approvals, now)
	if err != nil {
		return err
	}
	if hash(built) != hash(c) {
		return errors.New("dao-review: certificate approvals must be canonically sorted")
	}
	return nil
}
func DecodeCertificate(raw []byte, expected string, now time.Time) (Certificate, error) {
	var c Certificate
	if err := handoff.DecodeJSON(raw, &c, MaxCertificate); err != nil {
		return c, err
	}
	return c, c.Verify(expected, now)
}
func (c Certificate) Summary() string {
	return fmt.Sprintf("%d/%d distinct approvals for %s/%s epoch %d", len(c.Approvals), c.Review.Manifest.Threshold, c.Review.Manifest.DAO, c.Review.Manifest.Proposal, c.Review.Manifest.Epoch)
}
