package daoreview

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/sporrelay"
)

const (
	handoffVectorPath   = "testdata/conformance/dao-review-handoff-v1.json"
	handoffVectorFormat = "spore/dao-review/handoff-conformance/v1"
)

type handoffConformanceVector struct {
	Name           string `json:"name"`
	Expect         string `json:"expect"`
	Description    string `json:"description"`
	BriefBase64    string `json:"brief_base64"`
	DecisionBase64 string `json:"decision_base64,omitempty"`
	DeliverBase64  string `json:"deliver_base64,omitempty"`
}

type handoffConformanceFile struct {
	Format      string                     `json:"format"`
	Description string                     `json:"description"`
	Briefs      []handoffConformanceVector `json:"briefs"`
	Decisions   []handoffConformanceVector `json:"decisions"`
	Records     []handoffConformanceVector `json:"records"`
}

type handoffConformanceKit struct {
	review         SignedManifest
	coordinator    handoff.Peer
	coordinatorKey []byte
	reviewer       handoff.Peer
	reviewerKey    []byte
	outsider       handoff.Peer
	outsiderKey    []byte
	evidence       []byte
	policy         []byte
	brief          handoff.Envelope
	now            time.Time
}

func makeHandoffConformanceKit(t *testing.T) handoffConformanceKit {
	t.Helper()
	coordinator, coordinatorKey := peer(t, 0x11)
	reviewers := make([]handoff.Peer, 0, 3)
	keys := map[string][]byte{}
	for _, n := range []byte{0x22, 0x33, 0x44} {
		p, key := peer(t, n)
		reviewers = append(reviewers, p)
		keys[p.Pinned] = key
	}
	outsider, outsiderKey := peer(t, 0x55)
	evidence := []byte("conformance evidence")
	policy := []byte("conformance policy")
	created := int64(1900000000)
	s, err := SignManifest(Manifest{
		Version: 1, ID: "00112233445566778899aabbccddeeff", DAO: "dao:conformance", Proposal: "proposal:1", Epoch: 3,
		Coordinator: coordinator, EvidenceHash: handoff.Commitment(evidence), PolicyHash: handoff.Commitment(policy),
		Reviewers: reviewers, Threshold: 2, CreatedAt: created, Deadline: created + 3600, ExpiresAt: created + 86400,
	}, coordinatorKey)
	must(t, err)
	var reviewer handoff.Peer
	for _, p := range s.Manifest.Reviewers {
		if keys[p.Pinned] != nil {
			reviewer = p
			break
		}
	}
	packet, err := EncodePacket(Packet{Review: s, Policy: policy})
	must(t, err)
	reg := handoff.Registration{Source: "local-dao-review", Version: 1, ObservedAt: created,
		Objective: sporrelay.WorkOrder{ObjectiveID: "dao-review:" + s.Manifest.ID, OwnerPseudonym: coordinator.Pinned,
			DescriptionCommitment: handoff.Commitment(evidence), PolicyHash: handoff.Commitment(packet)}}
	msg := handoff.Message{Version: 1,
		Terms:   handoff.Terms{ID: InvitationID(s, reviewer), Registration: reg, Buyer: coordinator, Provider: reviewer, ExpiresAt: s.Manifest.ExpiresAt},
		EventID: "102132435465768798a9babbdcddedef", Sequence: 1, Kind: "brief", Content: evidence, Policy: packet}
	brief, err := handoff.Sign(msg, coordinatorKey)
	must(t, err)
	return handoffConformanceKit{s, coordinator, coordinatorKey, reviewer, keys[reviewer.Pinned], outsider, outsiderKey, evidence, policy, brief, time.Unix(created+120, 0)}
}

func handoffVectorEncode(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func decisionForHandoff(t *testing.T, k handoffConformanceKit, reviewer handoff.Peer, key []byte, choice string, at int64, reviewHash, briefHash, handoffID string) SignedDecision {
	t.Helper()
	d := Decision{Version: 1, ReviewHash: reviewHash, HandoffID: handoffID, BriefHash: briefHash, Reviewer: reviewer, Choice: choice, At: at}
	sig, err := sign(DecisionDomain, d, key, reviewer.Pinned)
	must(t, err)
	return SignedDecision{Domain: DecisionDomain, Decision: d, Signature: sig}
}

func makeDecisionDeliver(t *testing.T, k handoffConformanceKit, brief handoff.Envelope, decision SignedDecision, mutate func(*handoff.Message)) handoff.Envelope {
	t.Helper()
	raw, err := json.Marshal(decision)
	must(t, err)
	id := "2031425364758697a8b9cadbecfd0e1f"
	msg := handoff.Message{Version: 1, Terms: brief.Message.Terms, EventID: id, Sequence: 2, Previous: brief.Hash(), Kind: "deliver", Content: raw, ResultHash: handoff.Commitment(raw)}
	if mutate != nil {
		mutate(&msg)
	}
	deliver, err := handoff.Sign(msg, k.reviewerKey)
	must(t, err)
	return deliver
}

func handoffConformanceVectors(t *testing.T) handoffConformanceFile {
	t.Helper()
	k := makeHandoffConformanceKit(t)
	created := k.review.Manifest.CreatedAt
	validDecision := decisionForHandoff(t, k, k.reviewer, k.reviewerKey, "approve", created+60, k.review.Hash(), k.brief.Hash(), k.brief.Message.Terms.ID)
	decisionRaw, err := json.Marshal(validDecision)
	must(t, err)
	validDeliver := makeDecisionDeliver(t, k, k.brief, validDecision, nil)

	var briefs, decisions, records []handoffConformanceVector
	addBrief := func(name, expect, desc string, b handoff.Envelope) {
		briefs = append(briefs, handoffConformanceVector{Name: name, Expect: expect, Description: desc, BriefBase64: handoffVectorEncode(t, b)})
	}
	addDecision := func(name, expect, desc string, b handoff.Envelope, d []byte) {
		decisions = append(decisions, handoffConformanceVector{Name: name, Expect: expect, Description: desc,
			BriefBase64: handoffVectorEncode(t, b), DecisionBase64: base64.StdEncoding.EncodeToString(d)})
	}
	addRecord := func(name, expect, desc string, b, d handoff.Envelope) {
		records = append(records, handoffConformanceVector{Name: name, Expect: expect, Description: desc,
			BriefBase64: handoffVectorEncode(t, b), DeliverBase64: handoffVectorEncode(t, d)})
	}

	// The base brief opens both signed commitments and matches the explicit reviewer invitation.
	addBrief("valid-committed-brief", "accept", "Coordinator signature, evidence commitment, private policy packet, roster, recipient, and invitation ID all agree.", k.brief)

	badEnvelopeSig := k.brief
	badEnvelopeSig.Signature = conformanceFlipSignature(badEnvelopeSig.Signature)
	addBrief("tampered-brief-envelope-signature", "reject", "The handoff envelope signature is changed without re-signing.", badEnvelopeSig)

	// Re-signing keeps the handoff internally valid while making its evidence opening disagree with the review commitment.
	changedManifest := k.review
	changedManifest.Manifest.EvidenceHash = handoff.Commitment([]byte("different committed evidence"))
	changedManifest.Signature, err = sign(ManifestDomain, changedManifest.Manifest, k.coordinatorKey, k.coordinator.Pinned)
	must(t, err)
	changedPacket, err := EncodePacket(Packet{Review: changedManifest, Policy: k.policy})
	must(t, err)
	changedMessage := k.brief.Message
	changedMessage.Terms.ID = InvitationID(changedManifest, k.reviewer)
	changedMessage.Terms.Registration.Objective.PolicyHash = handoff.Commitment(changedPacket)
	changedMessage.Policy = changedPacket
	changedBrief, err := handoff.Sign(changedMessage, k.coordinatorKey)
	must(t, err)
	addBrief("evidence-opens-against-different-manifest", "reject", "The envelope's evidence commitment is valid, but the signed DAO manifest commits to different evidence bytes.", changedBrief)

	wrongInvitation := k.brief.Message
	wrongInvitation.Terms.ID = "ffeeddccbbaa99887766554433221100"
	wrongInvitationBrief, err := handoff.Sign(wrongInvitation, k.coordinatorKey)
	must(t, err)
	addBrief("wrong-reviewer-invitation-id", "reject", "All handoff fields and signatures are valid, but the ID is not derived from this review and reviewer.", wrongInvitationBrief)

	wrongReviewer := k.brief.Message
	wrongReviewer.Terms.Provider = k.outsider
	wrongReviewer.Terms.ID = InvitationID(k.review, k.outsider)
	wrongReviewerBrief, err := handoff.Sign(wrongReviewer, k.coordinatorKey)
	must(t, err)
	addBrief("reviewer-not-in-explicit-roster", "reject", "The coordinator signed a valid invitation to a key outside this manifest's roster.", wrongReviewerBrief)

	// SignedDecision decoding/verifying is checked independently of the delivery event chain.
	addDecision("valid-signed-approval", "accept", "Reviewer decision signature and review/invitation bindings are valid.", k.brief, decisionRaw)
	badDecisionSig := validDecision
	badDecisionSig.Signature = conformanceFlipSignature(badDecisionSig.Signature)
	badDecisionRaw, err := json.Marshal(badDecisionSig)
	must(t, err)
	addDecision("tampered-decision-signature", "reject", "The reviewer decision signature is changed without re-signing.", k.brief, badDecisionRaw)
	wrongHashDecision := decisionForHandoff(t, k, k.reviewer, k.reviewerKey, "approve", created+60, handoff.Commitment([]byte("other review")), k.brief.Hash(), k.brief.Message.Terms.ID)
	wrongHashRaw, err := json.Marshal(wrongHashDecision)
	must(t, err)
	addDecision("decision-bound-to-other-review", "reject", "Decision is correctly signed but names a different immutable review hash.", k.brief, wrongHashRaw)
	outsiderDecision := decisionForHandoff(t, k, k.outsider, k.outsiderKey, "approve", created+60, k.review.Hash(), k.brief.Hash(), InvitationID(k.review, k.outsider))
	outsiderRaw, err := json.Marshal(outsiderDecision)
	must(t, err)
	addDecision("decision-from-nonmember-key", "reject", "A valid signature from a key outside the explicit roster is rejected.", k.brief, outsiderRaw)
	badChoice := decisionForHandoff(t, k, k.reviewer, k.reviewerKey, "abstain", created+60, k.review.Hash(), k.brief.Hash(), k.brief.Message.Terms.ID)
	badChoiceRaw, err := json.Marshal(badChoice)
	must(t, err)
	addDecision("unsupported-decision-choice", "reject", "The reviewer signed a choice outside approve/reject.", k.brief, badChoiceRaw)
	atDeadline := decisionForHandoff(t, k, k.reviewer, k.reviewerKey, "approve", k.review.Manifest.Deadline, k.review.Hash(), k.brief.Hash(), k.brief.Message.Terms.ID)
	atDeadlineRaw, err := json.Marshal(atDeadline)
	must(t, err)
	addDecision("decision-at-deadline", "reject", "The signature is valid, but its timestamp is at the exclusive deadline.", k.brief, atDeadlineRaw)

	// Full record-chain verifier validates the actual signed brief + signed deliver event + embedded decision.
	addRecord("valid-brief-and-decision-record", "accept", "The signed deliver follows the exact signed brief and carries its signer's valid decision.", k.brief, validDeliver)
	wrongPrevious := makeDecisionDeliver(t, k, k.brief, validDecision, func(m *handoff.Message) { m.Previous = handoff.Commitment([]byte("not the brief hash")) })
	addRecord("deliver-does-not-follow-brief", "reject", "The deliver envelope is correctly signed but its previous hash is not the brief hash.", k.brief, wrongPrevious)
	wrongBriefDecision := decisionForHandoff(t, k, k.reviewer, k.reviewerKey, "approve", created+60, k.review.Hash(), handoff.Commitment([]byte("different brief")), k.brief.Message.Terms.ID)
	wrongBriefDeliver := makeDecisionDeliver(t, k, k.brief, wrongBriefDecision, nil)
	addRecord("decision-does-not-bind-brief", "reject", "Deliver chain is valid, but the embedded signed decision names a different brief hash.", k.brief, wrongBriefDeliver)

	return handoffConformanceFile{
		Format:      handoffVectorFormat,
		Description: "DAO review handoff vectors use standard-base64 JSON envelopes. A brief case runs Envelope.Verify then FromBrief. A decision case decodes a SignedDecision against the review opened from its brief. A record case runs DecisionFromRecord on exactly the brief and deliver envelopes. accept/reject records the protocol result, not error strings.",
		Briefs:      briefs, Decisions: decisions, Records: records,
	}
}

func TestDAOReviewHandoffConformanceVectors(t *testing.T) {
	file := handoffConformanceVectors(t)
	raw, err := json.MarshalIndent(file, "", "  ")
	must(t, err)
	raw = append(raw, '\n')
	if os.Getenv(conformanceRegenEnv) == "1" {
		must(t, os.MkdirAll(filepath.Dir(handoffVectorPath), 0755))
		must(t, os.WriteFile(handoffVectorPath, raw, 0644))
	}
	checked, err := os.ReadFile(handoffVectorPath)
	if err != nil {
		t.Fatalf("read %s (generate with %s=1): %v", handoffVectorPath, conformanceRegenEnv, err)
	}
	if !bytes.Equal(checked, raw) {
		t.Fatalf("%s drifted from the deterministic generator; regenerate only after an intentional encoding change", handoffVectorPath)
	}
	var loaded handoffConformanceFile
	must(t, handoff.DecodeJSON(checked, &loaded, 256<<10))
	if loaded.Format != handoffVectorFormat {
		t.Fatalf("unexpected format %q", loaded.Format)
	}
	if len(loaded.Briefs) != 5 || len(loaded.Decisions) != 6 || len(loaded.Records) != 3 {
		t.Fatalf("vector coverage changed: briefs=%d decisions=%d records=%d; want 5/6/3", len(loaded.Briefs), len(loaded.Decisions), len(loaded.Records))
	}
	for _, v := range loaded.Briefs {
		t.Run("brief/"+v.Name, func(t *testing.T) {
			e := decodeHandoffVectorEnvelope(t, v.BriefBase64)
			_, err := FromBrief(e)
			assertHandoffVectorExpectation(t, v, err)
		})
	}
	for _, v := range loaded.Decisions {
		t.Run("decision/"+v.Name, func(t *testing.T) {
			brief := decodeHandoffVectorEnvelope(t, v.BriefBase64)
			packet, err := FromBrief(brief)
			must(t, err)
			decisionRaw, err := base64.StdEncoding.DecodeString(v.DecisionBase64)
			must(t, err)
			_, err = DecodeDecision(decisionRaw, packet.Review)
			assertHandoffVectorExpectation(t, v, err)
		})
	}
	for _, v := range loaded.Records {
		t.Run("record/"+v.Name, func(t *testing.T) {
			brief := decodeHandoffVectorEnvelope(t, v.BriefBase64)
			deliver := decodeHandoffVectorEnvelope(t, v.DeliverBase64)
			r := handoff.Record{Events: []handoff.Envelope{brief, deliver}}
			_, err := DecisionFromRecord(r)
			assertHandoffVectorExpectation(t, v, err)
		})
	}
}

func decodeHandoffVectorEnvelope(t *testing.T, encoded string) handoff.Envelope {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	must(t, err)
	var e handoff.Envelope
	must(t, handoff.DecodeJSON(raw, &e, handoff.MaxMessage))
	return e
}

func assertHandoffVectorExpectation(t *testing.T, v handoffConformanceVector, err error) {
	t.Helper()
	switch v.Expect {
	case "accept":
		must(t, err)
	case "reject":
		if err == nil {
			t.Fatal("invalid handoff vector accepted")
		}
	default:
		t.Fatalf("unknown expectation %q", v.Expect)
	}
}
