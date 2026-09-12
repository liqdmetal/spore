package continuity

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

func testChainAnchor(t *testing.T) (*Vault, *QuorumPolicy, *ChainAnchor) {
	t.Helper()
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
	return v, policy, ca
}

func TestChainAnchorBindsExactQuorumEpoch(t *testing.T) {
	v, policy, ca := testChainAnchor(t)
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
	_, _, ca := testChainAnchor(t)
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

func TestChainAnchorPostsWithinDEROWireLimit(t *testing.T) {
	_, _, ca := testChainAnchor(t)
	wire, err := ca.ToDEROAnchor()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := dero.PackArguments(wire.ToArguments()); err != nil {
		t.Fatal(err)
	} else if len(got) > 111 {
		t.Fatalf("wire payload length = %d, want <= 111", len(got))
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
	_, _, ca := testChainAnchor(t)
	raw, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sealed continuity instructions")) {
		t.Fatal("chain anchor contains plaintext")
	}
}

func TestParseChainAnchorRejectsUnknownAndTrailingJSON(t *testing.T) {
	_, _, ca := testChainAnchor(t)
	raw, err := json.Marshal(ca)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		append(append([]byte(nil), raw...), []byte(" {}")...),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"future":true}`)...),
	} {
		if _, err := ParseChainAnchor(input); err == nil {
			t.Fatalf("accepted malformed anchor: %s", input)
		}
	}
}

func TestChainAnchorRejectsZeroAndWrongType(t *testing.T) {
	ca := ChainAnchor{
		Type: chainAnchorType, Version: chainAnchorVersion,
		VaultID:  "0000000000000000000000000000000000000000000000000000000000000000",
		PolicyID: "1111111111111111111111111111111111111111111111111111111111111111",
		Deadline: 1, CheckInSeq: 0,
	}
	if err := ca.Verify(); !errors.Is(err, ErrInvalidChainAnchor) {
		t.Fatalf("accepted zero vault id: %v", err)
	}
	ca.VaultID = "2222222222222222222222222222222222222222222222222222222222222222"
	ca.Type = "wrong-type"
	if err := ca.Verify(); !errors.Is(err, ErrInvalidChainAnchor) {
		t.Fatalf("accepted wrong type: %v", err)
	}
}
