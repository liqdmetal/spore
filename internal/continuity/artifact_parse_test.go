package continuity

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestContinuityArtifactParsersRejectUnknownAndTrailingJSON(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	observerPriv, pub := observerPair(t)
	notice, err := Observe(v, observerPriv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewQuorumPolicy(v, 1, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := Attest(policy, v, observerPriv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	quorum, err := NewQuorumRelease(policy, []QuorumAttestation{*attestation})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := NewChainAnchor(v, policy)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		value any
		parse func([]byte) error
	}{
		{"vault", v, func(raw []byte) error { _, err := Parse(raw); return err }},
		{"notice", notice, func(raw []byte) error { _, err := ParseNotice(raw); return err }},
		{"quorum", quorum, func(raw []byte) error { _, err := ParseQuorumRelease(raw); return err }},
		{"anchor", anchor, func(raw []byte) error { _, err := ParseChainAnchor(raw); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			trailing := append(append([]byte(nil), raw...), []byte(" {}")...)
			if err := tc.parse(trailing); err == nil {
				t.Fatal("accepted trailing JSON value")
			}
			unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"future":true}`)...)
			if err := tc.parse(unknown); err == nil {
				t.Fatal("accepted unknown field")
			}
		})
	}

	if _, err := ParseNotice([]byte("{")); !errors.Is(err, ErrInvalidNotice) {
		t.Fatalf("malformed notice error = %v", err)
	}
}
