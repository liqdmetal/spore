package continuity

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyPolicyRejectsZeroBindingIdentifiers(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	_, pub := observerPair(t)
	policy, err := NewQuorumPolicy(v, 1, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*QuorumPolicy)
	}{
		{"vault", func(p *QuorumPolicy) { p.VaultID = "0000000000000000000000000000000000000000000000000000000000000000" }},
		{"vault-policy", func(p *QuorumPolicy) {
			p.VaultPolicy = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"owner-signing-key", func(p *QuorumPolicy) {
			p.OwnerSigPub = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forged := *policy
			tc.mutate(&forged)
			forged.PolicyID = quorumPolicyID(forged)
			if err := verifyPolicy(forged); !errors.Is(err, ErrInvalidQuorum) {
				t.Fatalf("accepted zero %s binding: %v", tc.name, err)
			}
			if raw, err := json.Marshal(forged); err != nil {
				t.Fatal(err)
			} else if parsed, err := ParseQuorumPolicy(raw); !errors.Is(err, ErrInvalidQuorum) {
				_ = parsed
				t.Fatalf("parser accepted zero %s binding: %v", tc.name, err)
			}
		})
	}
}
