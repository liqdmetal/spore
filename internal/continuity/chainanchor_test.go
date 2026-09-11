package continuity

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestChainAnchorBindsExactQuorumEpoch(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	_, pub1 := observerPair(t)
	_, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewChainAnchor(v, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.VerifyAgainst(v, policy); err != nil {
		t.Fatal(err)
	}
	if ca.VaultID != v.VaultID || ca.PolicyID != policy.PolicyID || ca.CheckInSeq != policy.CheckInSeq || ca.Deadline != policy.Deadline {
		t.Fatalf("chain anchor = %#v", ca)
	}

	stale := *ca
	stale.CheckInSeq++
	if err := stale.VerifyAgainst(v, policy); !errors.Is(err, ErrInvalidChainAnchor) {
		t.Fatalf("accepted wrong check-in epoch: %v", err)
	}
	stale = *ca
	stale.Deadline++
	if err := stale.VerifyAgainst(v, policy); !errors.Is(err, ErrInvalidChainAnchor) {
		t.Fatalf("accepted wrong deadline: %v", err)
	}
}

func TestChainAnchorDeroWireRoundTrip(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	_, pub1 := observerPair(t)
	_, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewChainAnchor(v, policy)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ca.ToDEROAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if wire.Kind != anchor.KindContinuity || wire.Version != anchor.Version {
		t.Fatalf("wire kind/version = %d/%d", wire.Kind, wire.Version)
	}
	parsed, err := ParseDEROChainAnchor(wire)
	if err != nil {
		t.Fatal(err)
	}
	if *parsed != *ca {
		t.Fatalf("parsed = %#v, want %#v", parsed, ca)
	}
	args := wire.ToArguments()
	wire2, err := anchor.FromArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	parsed2, err := ParseDEROChainAnchor(wire2)
	if err != nil {
		t.Fatal(err)
	}
	if *parsed2 != *ca {
		t.Fatalf("argument round trip = %#v, want %#v", parsed2, ca)
	}
}

func TestChainAnchorRejectsLaterOwnerCheckin(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, _ := testVault(t, now)
	_, pub1 := observerPair(t)
	_, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewChainAnchor(v, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIn(v, owner.Priv, now+5); err != nil {
		t.Fatal(err)
	}
	if err := ca.VerifyAgainst(v, policy); !errors.Is(err, ErrInvalidChainAnchor) {
		t.Fatalf("stale anchor accepted after check-in: %v", err)
	}
}

func TestChainAnchorJSONDoesNotContainPlaintext(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	_, pub1 := observerPair(t)
	_, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewChainAnchor(v, policy)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sealed continuity instructions")) {
		t.Fatal("chain anchor contains plaintext")
	}
}
