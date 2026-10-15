package daoreview

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/secure"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func peer(t *testing.T, n byte) (handoff.Peer, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{n}, 32)
	pub, err := secure.SigPubOf(key)
	must(t, err)
	return handoff.Peer{Address: hex.EncodeToString([]byte{n}), Pinned: hex.EncodeToString(pub)}, key
}
func kit(t *testing.T) (SignedManifest, []handoff.Envelope, [][]byte, []byte, time.Time) {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	coordinator, key := peer(t, 11)
	var reviewers []handoff.Peer
	keys := map[string][]byte{}
	for _, n := range []byte{22, 33, 44} {
		p, k := peer(t, n)
		reviewers = append(reviewers, p)
		keys[p.Pinned] = k
	}
	evidence, policy := []byte("private proposal evidence\x00\xff"), []byte("two of three distinct humans approve the exact evidence")
	id, err := handoff.NewID()
	must(t, err)
	m := Manifest{Version: 1, ID: id, DAO: "dao:example", Proposal: "proposal:17", Epoch: 8, Coordinator: coordinator, EvidenceHash: handoff.Commitment(evidence), PolicyHash: handoff.Commitment(policy), Reviewers: reviewers, Threshold: 2, CreatedAt: now.Add(-time.Minute).Unix(), Deadline: now.Add(time.Hour).Unix(), ExpiresAt: now.Add(24 * time.Hour).Unix()}
	s, err := SignManifest(m, key)
	must(t, err)
	packet, err := EncodePacket(Packet{s, policy})
	must(t, err)
	var briefs []handoff.Envelope
	var orderedKeys [][]byte
	for _, p := range s.Manifest.Reviewers {
		eventID, err := handoff.NewID()
		must(t, err)
		reg := handoff.Registration{Source: "local-dao-review", Version: 1, ObservedAt: m.CreatedAt, Objective: sporrelay.WorkOrder{ObjectiveID: "dao-review:" + id, OwnerPseudonym: coordinator.Pinned, DescriptionCommitment: m.EvidenceHash, PolicyHash: handoff.Commitment(packet)}}
		msg := handoff.Message{Version: 1, Terms: handoff.Terms{ID: InvitationID(s, p), Registration: reg, Buyer: coordinator, Provider: p, ExpiresAt: m.ExpiresAt}, EventID: eventID, Sequence: 1, Kind: "brief", Content: evidence, Policy: packet}
		e, err := handoff.Sign(msg, key)
		must(t, err)
		briefs = append(briefs, e)
		orderedKeys = append(orderedKeys, keys[p.Pinned])
	}
	return s, briefs, orderedKeys, key, now
}
func decisions(t *testing.T, s SignedManifest, briefs []handoff.Envelope, keys [][]byte, now time.Time) []SignedDecision {
	t.Helper()
	var ds []SignedDecision
	for i, b := range briefs {
		choice := "approve"
		if i == 2 {
			choice = "reject"
		}
		d, err := SignDecision(b, s.Manifest.Reviewers[i], choice, keys[i], now)
		must(t, err)
		ds = append(ds, d)
	}
	return ds
}

func TestDAOReviewTwoOfThreeCertificateOfflineAndPrivate(t *testing.T) {
	s, briefs, keys, _, now := kit(t)
	ds := decisions(t, s, briefs, keys, now)
	c, err := NewCertificate(s, ds, now)
	must(t, err)
	must(t, c.Verify(s.Hash(), now))
	raw, err := json.MarshalIndent(c, "", "  ")
	must(t, err)
	decoded, err := DecodeCertificate(raw, s.Hash(), now)
	must(t, err)
	if len(decoded.Approvals) != 2 || decoded.Review.Manifest.Threshold != 2 {
		t.Fatal("wrong tally")
	}
	if bytes.Contains(raw, briefs[0].Message.Content) || bytes.Contains(raw, []byte("two of three distinct humans")) {
		t.Fatal("certificate leaks private evidence/policy")
	}
	for _, b := range briefs {
		p, err := FromBrief(b)
		must(t, err)
		if p.Review.Hash() != s.Hash() {
			t.Fatal("reviewer received different immutable terms")
		}
	}
	if c.Verify("", now) == nil || c.Verify(handoff.Commitment([]byte("untrusted roster")), now) == nil {
		t.Fatal("certificate self-established authority")
	}
	if _, err := NewCertificate(s, ds[:1], now); err == nil {
		t.Fatal("one vote formed quorum")
	}
	if _, err := NewCertificate(s, []SignedDecision{ds[0], ds[0]}, now); err == nil {
		t.Fatal("duplicate key counted twice")
	}
	if _, err := NewCertificate(s, []SignedDecision{ds[0], ds[2]}, now); err == nil {
		t.Fatal("rejection counted as approval")
	}
}

func TestDAOReviewManifestRejectsMembershipAndCommitmentChanges(t *testing.T) {
	s, _, _, key, _ := kit(t)
	tests := map[string]func(*Manifest){
		"duplicate pin":       func(m *Manifest) { m.Reviewers[1].Pinned = m.Reviewers[0].Pinned },
		"duplicate address":   func(m *Manifest) { m.Reviewers[1].Address = m.Reviewers[0].Address },
		"coordinator review":  func(m *Manifest) { m.Reviewers[0] = m.Coordinator },
		"minority threshold":  func(m *Manifest) { m.Threshold = 1 },
		"oversized threshold": func(m *Manifest) { m.Threshold = 4 },
		"zero epoch":          func(m *Manifest) { m.Epoch = 0 },
		"expiry bound":        func(m *Manifest) { m.ExpiresAt = m.CreatedAt + 31*24*3600 },
		"bad commitment":      func(m *Manifest) { m.PolicyHash = "sha256:policy" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			m := s.Manifest
			m.Reviewers = append([]handoff.Peer(nil), m.Reviewers...)
			change(&m)
			if _, err := SignManifest(m, key); err == nil {
				t.Fatal("invalid manifest signed")
			}
		})
	}
	for _, change := range []func(*Manifest){func(m *Manifest) { m.Threshold = 3 }, func(m *Manifest) { m.Epoch++ }, func(m *Manifest) { m.Proposal = "other" }, func(m *Manifest) { m.EvidenceHash = handoff.Commitment([]byte("other")) }} {
		tampered := s
		tampered.Manifest = s.Manifest
		change(&tampered.Manifest)
		if tampered.Verify() == nil {
			t.Fatal("signed manifest mutable")
		}
	}
}

func TestDAOReviewDecisionRejectsForeignEpochReviewerWindowAndBrief(t *testing.T) {
	s, briefs, keys, key, now := kit(t)
	d, err := SignDecision(briefs[0], s.Manifest.Reviewers[0], "approve", keys[0], now)
	must(t, err)
	for name, change := range map[string]func(*Decision){
		"review hash":     func(d *Decision) { d.ReviewHash = handoff.Commitment([]byte("other epoch")) },
		"membership":      func(d *Decision) { d.Reviewer = s.Manifest.Coordinator },
		"invitation":      func(d *Decision) { d.HandoffID = strings.Repeat("0", 32) },
		"choice":          func(d *Decision) { d.Choice = "abstain" },
		"before creation": func(d *Decision) { d.At = s.Manifest.CreatedAt - 1 },
		"deadline":        func(d *Decision) { d.At = s.Manifest.Deadline },
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			change(&bad.Decision)
			bad.Signature, err = sign(DecisionDomain, bad.Decision, keys[0], s.Manifest.Reviewers[0].Pinned)
			must(t, err)
			if bad.VerifyFor(s) == nil {
				t.Fatal("invalid decision verified")
			}
		})
	}
	if _, err := SignDecision(briefs[0], s.Manifest.Reviewers[0], "approve", key, now); err == nil {
		t.Fatal("coordinator impersonated reviewer")
	}
	if _, err := SignDecision(briefs[0], s.Manifest.Reviewers[1], "approve", keys[1], now); err == nil {
		t.Fatal("another reviewer's invitation accepted")
	}
	// A validly signed decision from another proposal epoch must not transplant.
	changed := s.Manifest
	changed.Epoch++
	other, err := SignManifest(changed, key)
	must(t, err)
	if d.VerifyFor(other) == nil {
		t.Fatal("cross-epoch replay accepted")
	}
	wrong := briefs[0]
	wrong.Message.Content = []byte("different private evidence")
	wrong.Message.Terms.Registration.Objective.DescriptionCommitment = handoff.Commitment(wrong.Message.Content)
	wrong, err = handoff.Sign(wrong.Message, key)
	must(t, err)
	if _, err := FromBrief(wrong); err == nil {
		t.Fatal("changed evidence accepted")
	}
	wrong = briefs[0]
	wrong.Message.Terms.ID = strings.Repeat("f", 32)
	wrong, err = handoff.Sign(wrong.Message, key)
	must(t, err)
	if _, err := FromBrief(wrong); err == nil {
		t.Fatal("second invitation accepted")
	}
}

func TestDAOReviewCertificateRejectsTamperingDuplicateAliasExpiryAndFuture(t *testing.T) {
	s, briefs, keys, _, now := kit(t)
	ds := decisions(t, s, briefs, keys, now)
	c, err := NewCertificate(s, ds, now)
	must(t, err)
	raw, err := json.Marshal(c)
	must(t, err)
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"unknown":true`), 1), append(append([]byte{}, raw...), []byte(`{}`)...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1)} {
		if _, err := DecodeCertificate(bad, s.Hash(), now); err == nil {
			t.Fatal("ambiguous certificate accepted")
		}
	}
	dup := c
	dup.Approvals = []SignedDecision{ds[0], ds[0]}
	if dup.Verify(s.Hash(), now) == nil {
		t.Fatal("duplicate certificate approval accepted")
	}
	reject := c
	reject.Approvals = append([]SignedDecision(nil), c.Approvals...)
	reject.Approvals[1] = ds[2]
	if reject.Verify(s.Hash(), now) == nil {
		t.Fatal("rejection certificate accepted")
	}
	sorted := c
	sorted.Approvals = []SignedDecision{c.Approvals[1], c.Approvals[0]}
	if sorted.Verify(s.Hash(), now) == nil {
		t.Fatal("noncanonical certificate accepted")
	}
	if c.Verify(s.Hash(), time.Unix(s.Manifest.ExpiresAt, 0)) == nil {
		t.Fatal("expired certificate accepted")
	}
	future, err := SignDecision(briefs[0], s.Manifest.Reviewers[0], "approve", keys[0], now.Add(time.Minute))
	must(t, err)
	if _, err := NewCertificate(s, []SignedDecision{future, ds[1]}, now); err == nil {
		t.Fatal("future timestamp counted")
	}
	// Conflicting decisions by one key must be surfaced, not last-value-wins.
	opposite, err := SignDecision(briefs[0], s.Manifest.Reviewers[0], "reject", keys[0], now)
	must(t, err)
	if _, err := NewCertificate(s, []SignedDecision{ds[0], opposite, ds[1]}, now); err == nil {
		t.Fatal("equivocation silently counted")
	}
}

func TestDAOReviewPacketSizeAndPrivatePolicyBinding(t *testing.T) {
	s, _, _, _, _ := kit(t)
	if _, err := EncodePacket(Packet{s, []byte("changed policy")}); err == nil {
		t.Fatal("policy hash ignored")
	}
	_, key := peer(t, 11)
	m := s.Manifest
	m.PolicyHash = handoff.Commitment(bytes.Repeat([]byte{'p'}, handoff.MaxPolicy))
	big, err := SignManifest(m, key)
	must(t, err)
	if _, err := EncodePacket(Packet{big, bytes.Repeat([]byte{'p'}, handoff.MaxPolicy)}); err == nil {
		t.Fatal("oversized private packet accepted")
	}
}
