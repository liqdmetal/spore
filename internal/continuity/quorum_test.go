package continuity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

func observerPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	priv, pub, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestQuorumTwoOfThreeReleaseAndDecrypt(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, recipient := testVault(t, now)
	p1, pub1 := observerPair(t)
	p2, pub2 := observerPair(t)
	_, pub3 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2, pub3})
	if err != nil {
		t.Fatal(err)
	}
	a1, err := Attest(policy, v, p1, now+15)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Attest(policy, v, p2, now+20)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewQuorumRelease(policy, []QuorumAttestation{*a2, *a1})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Verify(); err != nil {
		t.Fatal(err)
	}
	plain, err := ReleaseWithQuorum(v, q, recipient.Priv, now+20)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "sealed continuity instructions" {
		t.Fatalf("release = %q", plain)
	}
	if bytes.Contains(mustJSON(t, q), []byte("sealed continuity instructions")) {
		t.Fatal("quorum bundle contains plaintext")
	}
}

func TestQuorumRejectsEarlyAndInsufficientAttestations(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	p1, pub1 := observerPair(t)
	_, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Attest(policy, v, p1, now+14); !errors.Is(err, ErrNotDue) {
		t.Fatalf("early attest = %v", err)
	}
	a1, err := Attest(policy, v, p1, now+15)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQuorumRelease(policy, []QuorumAttestation{*a1}); !errors.Is(err, ErrQuorumNotMet) {
		t.Fatalf("insufficient quorum = %v", err)
	}
}

func TestQuorumRejectsDuplicateUnapprovedAndStaleEpoch(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, _ := testVault(t, now)
	p1, pub1 := observerPair(t)
	p2, pub2 := observerPair(t)
	unapproved, _ := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	a1, err := Attest(policy, v, p1, now+15)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Attest(policy, v, p2, now+15)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewQuorumRelease(policy, []QuorumAttestation{*a1, *a1}); !errors.Is(err, ErrDuplicateAttester) {
		t.Fatalf("duplicate = %v", err)
	}
	fake, err := Attest(policy, v, unapproved, now+15)
	if !errors.Is(err, ErrAttesterNotApproved) || fake != nil {
		t.Fatalf("unapproved attest = %#v %v", fake, err)
	}
	q, err := NewQuorumRelease(policy, []QuorumAttestation{*a1, *a2})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIn(v, owner.Priv, now+5); err != nil {
		t.Fatal(err)
	}
	if err := VerifyNoticeQuorumForVault(v, q); err == nil {
		t.Fatal("stale quorum accepted after newer check-in")
	}
}

func TestQuorumPolicyAndBundleTamperingFailClosed(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	p1, pub1 := observerPair(t)
	p2, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	a1, _ := Attest(policy, v, p1, now+15)
	a2, _ := Attest(policy, v, p2, now+15)
	q, err := NewQuorumRelease(policy, []QuorumAttestation{*a1, *a2})
	if err != nil {
		t.Fatal(err)
	}
	q.Attestations[0].Notice.ObservedAt++
	if err := q.Verify(); err == nil {
		t.Fatal("tampered quorum verified")
	}
	policy.Attesters[0] = policy.Attesters[1]
	if _, err := NewQuorumRelease(policy, []QuorumAttestation{*a1, *a2}); err == nil {
		t.Fatal("tampered policy accepted")
	}
}

func TestQuorumJSONRoundTrip(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, _ := testVault(t, now)
	p1, pub1 := observerPair(t)
	p2, pub2 := observerPair(t)
	policy, err := NewQuorumPolicy(v, 2, [][]byte{pub1, pub2})
	if err != nil {
		t.Fatal(err)
	}
	a1, _ := Attest(policy, v, p1, now+15)
	a2, _ := Attest(policy, v, p2, now+20)
	q, err := NewQuorumRelease(policy, []QuorumAttestation{*a1, *a2})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseQuorumRelease(mustJSON(t, q))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.QuorumID != q.QuorumID {
		t.Fatal("quorum ID changed through JSON")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
