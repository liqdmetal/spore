package daoreview

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/handoff"
)

// The checked-in vector file is the portable contract for certificate
// verifiers. It is generated from fixed keys and timestamps, so any drift in
// canonical JSON, signing input, or verification rules fails byte-for-byte.
// Regenerate deliberately with SPORE_UPDATE_DAO_REVIEW_VECTORS=1.
const (
	conformanceVectorPath = "testdata/conformance/dao-review-certificate-v1.json"
	conformanceFormat     = "spore/dao-review/conformance/v1"
	conformanceRegenEnv   = "SPORE_UPDATE_DAO_REVIEW_VECTORS"
	confCreated           = int64(1900000000)
	confNow               = confCreated + 120
)

type conformanceFixtureJSON struct {
	ReviewHash              string `json:"review_hash"`
	ManifestCanonicalJSON   string `json:"manifest_canonical_json"`
	ManifestSigningInputHex string `json:"manifest_signing_input_hex"`
}

type conformanceVector struct {
	Name               string `json:"name"`
	Expect             string `json:"expect"`
	Description        string `json:"description"`
	ExpectedReviewHash string `json:"expected_review_hash"`
	Now                int64  `json:"now"`
	Approvals          int    `json:"approvals,omitempty"`
	CertificateBase64  string `json:"certificate_base64"`
}

type conformanceFile struct {
	Format      string                 `json:"format"`
	Description string                 `json:"description"`
	Fixture     conformanceFixtureJSON `json:"fixture"`
	Vectors     []conformanceVector    `json:"vectors"`
}

func conformanceDecision(t *testing.T, s SignedManifest, reviewer handoff.Peer, key []byte, choice string, at int64) SignedDecision {
	t.Helper()
	d := Decision{Version: 1, ReviewHash: s.Hash(), HandoffID: InvitationID(s, reviewer), BriefHash: handoff.Commitment([]byte("conformance brief")), Reviewer: reviewer, Choice: choice, At: at}
	sig, err := sign(DecisionDomain, d, key, reviewer.Pinned)
	must(t, err)
	return SignedDecision{Domain: DecisionDomain, Decision: d, Signature: sig}
}

func conformanceFlipSignature(sig string) string {
	b := []byte(sig)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

// conformanceMutate changes exactly one anchor so each negative vector fails for one reason.
func conformanceMutate(t *testing.T, raw []byte, anchor, replacement string) []byte {
	t.Helper()
	if strings.Count(string(raw), anchor) != 1 {
		t.Fatalf("mutation anchor %q must occur exactly once", anchor)
	}
	return []byte(strings.Replace(string(raw), anchor, replacement, 1))
}

func conformanceVectorsFile(t *testing.T) conformanceFile {
	t.Helper()
	coordinator, coordKey := peer(t, 0x11)
	var reviewers []handoff.Peer
	keys := map[string][]byte{}
	for _, n := range []byte{0x22, 0x33, 0x44} {
		p, k := peer(t, n)
		reviewers = append(reviewers, p)
		keys[p.Pinned] = k
	}
	outsider, outsiderKey := peer(t, 0x55)
	s, err := SignManifest(Manifest{
		Version:      1,
		ID:           "00112233445566778899aabbccddeeff",
		DAO:          "dao:conformance",
		Proposal:     "proposal:1",
		Epoch:        3,
		Coordinator:  coordinator,
		EvidenceHash: handoff.Commitment([]byte("conformance evidence")),
		PolicyHash:   handoff.Commitment([]byte("conformance policy")),
		Reviewers:    reviewers,
		Threshold:    2,
		CreatedAt:    confCreated,
		Deadline:     confCreated + 3600,
		ExpiresAt:    confCreated + 86400,
	}, coordKey)
	must(t, err)

	// Reviewers are sorted by pin inside the signed manifest, so index by it.
	reviewerAt := func(i int) (handoff.Peer, []byte) {
		p := s.Manifest.Reviewers[i]
		return p, keys[p.Pinned]
	}
	decide := func(i int, choice string, at int64) SignedDecision {
		p, k := reviewerAt(i)
		return conformanceDecision(t, s, p, k, choice, at)
	}
	a0 := decide(0, "approve", confCreated+60)
	a1 := decide(1, "approve", confCreated+61)
	a2 := decide(2, "approve", confCreated+63)
	r2 := decide(2, "reject", confCreated+62)

	encodeIndent := func(c Certificate) []byte {
		raw, err := json.MarshalIndent(c, "", "  ")
		must(t, err)
		return append(raw, '\n')
	}
	encodeCompact := func(c Certificate) []byte {
		raw, err := json.Marshal(c)
		must(t, err)
		return raw
	}

	valid, err := NewCertificate(s, []SignedDecision{a0, a1, r2}, time.Unix(confNow, 0))
	must(t, err)
	validRaw := encodeIndent(valid)
	validCompact := encodeCompact(valid)

	var vectors []conformanceVector
	add := func(name, expect, desc, expected string, now int64, approvals int, raw []byte) {
		vectors = append(vectors, conformanceVector{
			Name:               name,
			Expect:             expect,
			Description:        desc,
			ExpectedReviewHash: expected,
			Now:                now,
			Approvals:          approvals,
			CertificateBase64:  base64.StdEncoding.EncodeToString(raw),
		})
	}

	// Accepted certificates.
	add("two-of-three-approvals-accepted", "accept",
		"Two distinct approvals meet the threshold; one rejection is ignored for quorum but not hidden from the roster.",
		s.Hash(), confNow, 2, validRaw)
	add("accepted-after-deadline-before-expiry", "accept",
		"Decisions made before the deadline still form a valid certificate after the deadline and before expiry.",
		s.Hash(), confCreated+3600+600, 2, validRaw)
	three, err := NewCertificate(s, []SignedDecision{a0, a1, a2}, time.Unix(confNow, 0))
	must(t, err)
	add("three-approvals-accepted", "accept",
		"More approvals than the threshold are accepted and listed in canonical pin order.",
		s.Hash(), confNow, 3, encodeIndent(three))

	// Hash, time, and quorum rules.
	add("wrong-expected-review-hash", "reject",
		"The trusted expected review hash differs from the signed manifest hash.",
		handoff.Commitment([]byte("other roster")), confNow, 0, validRaw)
	add("malformed-expected-review-hash", "reject",
		"The expected hash uses uppercase hex, so it is not a canonical sha256 commitment.",
		"sha256:ABCDEF", confNow, 0, validRaw)
	add("certificate-at-expiry", "reject",
		"Verification at the exact expiry instant is rejected.",
		s.Hash(), confCreated+86400, 0, validRaw)
	add("certificate-before-creation", "reject",
		"Verification before the review's creation time is rejected.",
		s.Hash(), confCreated-1, 0, validRaw)
	belowQuorum := Certificate{CertificateDomain, 1, s, []SignedDecision{a0}}
	add("one-approval-below-threshold", "reject",
		"A single approval does not satisfy a two-of-three threshold.",
		s.Hash(), confNow, 0, encodeIndent(belowQuorum))

	// Decision-set rules, with each hand-built certificate isolating one defect.
	add("duplicate-reviewer-approval", "reject",
		"The same reviewer key approves twice, which must not count as two votes.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, a0}}))
	add("rejection-listed-as-approval", "reject",
		"A signed rejection appears in the approvals list.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, r2}}))
	add("noncanonical-approval-order", "reject",
		"Two valid approvals are in reverse pin order instead of canonical order.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a1, a0}}))
	outsiderApproval := conformanceDecision(t, s, outsider, outsiderKey, "approve", confCreated+60)
	add("outsider-approval", "reject",
		"A validly signed approval from a key outside the pinned roster is rejected.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, outsiderApproval}}))
	lateReviewer, lateKey := reviewerAt(1)
	atDeadline := conformanceDecision(t, s, lateReviewer, lateKey, "approve", confCreated+3600)
	add("approval-at-deadline", "reject",
		"A decision timestamped exactly at the deadline is outside the review window.",
		s.Hash(), confCreated+3600+600, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, atDeadline}}))
	futureReviewer, futureKey := reviewerAt(1)
	future := conformanceDecision(t, s, futureReviewer, futureKey, "approve", confNow+1)
	add("future-approval", "reject",
		"A decision timestamped after the verification time is rejected.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, future}}))

	// Signature and review-binding tamper cases.
	tamperedSig := a1
	tamperedSig.Signature = conformanceFlipSignature(tamperedSig.Signature)
	add("tampered-approval-signature", "reject",
		"One byte of an approval signature is changed while the review hash remains correct.",
		s.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, s, []SignedDecision{a0, tamperedSig}}))
	epochTampered := s
	epochTampered.Manifest.Epoch = 4
	add("tampered-manifest-epoch", "reject",
		"The manifest epoch changed without re-signing; the expected hash is the tampered manifest's own hash.",
		epochTampered.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, epochTampered, []SignedDecision{a0, a1}}))
	minorityManifest := s.Manifest
	minorityManifest.Threshold = 1
	minoritySig, err := sign(ManifestDomain, minorityManifest, coordKey, coordinator.Pinned)
	must(t, err)
	minority := SignedManifest{ManifestDomain, minorityManifest, minoritySig}
	add("signed-minority-threshold", "reject",
		"The coordinator correctly signs a minority threshold; verifiers must still enforce a strict majority.",
		minority.Hash(), confNow, 0, encodeIndent(Certificate{CertificateDomain, 1, minority, []SignedDecision{a0}}))
	wrongDomain := valid
	wrongDomain.Domain = "spore/dao-review/certificate/v0"
	add("wrong-certificate-domain", "reject",
		"The certificate domain is not the v1 certificate domain.",
		s.Hash(), confNow, 0, encodeIndent(wrongDomain))

	// Strict JSON decoding cases, using the compact canonical bytes as the base.
	add("unknown-field", "reject",
		"An unknown top-level field is rejected by the strict decoder.",
		s.Hash(), confNow, 0, conformanceMutate(t, validCompact, `"version":1,"review":`, `"version":1,"unexpected":true,"review":`))
	add("duplicate-key", "reject",
		"A duplicate top-level version key is rejected rather than last-value-wins.",
		s.Hash(), confNow, 0, conformanceMutate(t, validCompact, `"version":1,"review":`, `"version":1,"version":1,"review":`))
	add("null-version", "reject",
		"A null version is rejected instead of being treated as absent.",
		s.Hash(), confNow, 0, conformanceMutate(t, validCompact, `"version":1,"review":`, `"version":null,"review":`))
	add("trailing-json-value", "reject",
		"A second JSON value after the certificate is rejected.",
		s.Hash(), confNow, 0, append(append([]byte{}, validCompact...), []byte(" {}")...))

	return conformanceFile{
		Format:      conformanceFormat,
		Description: "Portable DAO review certificate vectors. Canonical bytes are encoding/json output of the Go structs: declared field order, no insignificant whitespace, HTML-safe escaping. Signatures are Ed25519 over domain + NUL + canonical JSON of the signed body. Certificates are verified with an independently trusted review hash and the verification time; expect=accept means every rule passes.",
		Fixture: conformanceFixtureJSON{
			ReviewHash:              s.Hash(),
			ManifestCanonicalJSON:   string(mustJSON(t, s.Manifest)),
			ManifestSigningInputHex: hex.EncodeToString(append([]byte(ManifestDomain+"\x00"), mustJSON(t, s.Manifest)...)),
		},
		Vectors: vectors,
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return raw
}

func TestDAOReviewConformanceVectors(t *testing.T) {
	file := conformanceVectorsFile(t)
	raw, err := json.MarshalIndent(file, "", "  ")
	must(t, err)
	raw = append(raw, '\n')
	if os.Getenv(conformanceRegenEnv) == "1" {
		must(t, os.MkdirAll(filepath.Dir(conformanceVectorPath), 0755))
		must(t, os.WriteFile(conformanceVectorPath, raw, 0644))
	}
	checked, err := os.ReadFile(conformanceVectorPath)
	if err != nil {
		t.Fatalf("read %s (generate with %s=1): %v", conformanceVectorPath, conformanceRegenEnv, err)
	}
	if !bytes.Equal(checked, raw) {
		t.Fatalf("%s drifted from the deterministic generator; regenerate only after an intentional encoding change", conformanceVectorPath)
	}

	var loaded conformanceFile
	must(t, handoff.DecodeJSON(checked, &loaded, 256<<10))
	if loaded.Format != conformanceFormat || len(loaded.Vectors) == 0 {
		t.Fatal("conformance file has wrong format or no vectors")
	}
	for _, v := range loaded.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(v.CertificateBase64)
			must(t, err)
			c, err := DecodeCertificate(raw, v.ExpectedReviewHash, time.Unix(v.Now, 0))
			switch v.Expect {
			case "accept":
				must(t, err)
				if len(c.Approvals) != v.Approvals {
					t.Fatalf("approvals = %d, want %d", len(c.Approvals), v.Approvals)
				}
			case "reject":
				if err == nil {
					t.Fatal("invalid certificate accepted")
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expect)
			}
		})
	}
}
