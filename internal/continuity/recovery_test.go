package continuity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryBundleRoundTripAndCleanRestore(t *testing.T) {
	v, policy, anchor := testChainAnchor(t)
	vaultRaw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	anchorRaw, err := json.Marshal(anchor)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := NewRecoveryBundle(map[string][]byte{
		"continuity-vault.json":  vaultRaw,
		"quorum-policy.json":     policyRaw,
		"continuity-anchor.json": anchorRaw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Verify(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRecoveryBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "restored")
	if err := parsed.Restore(root); err != nil {
		t.Fatal(err)
	}
	restoredVault, err := os.ReadFile(filepath.Join(root, "continuity-vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(restoredVault); err != nil {
		t.Fatalf("restored vault does not verify: %v", err)
	}
	restoredPolicy, err := os.ReadFile(filepath.Join(root, "quorum-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseQuorumPolicy(restoredPolicy); err != nil {
		t.Fatalf("restored policy does not verify: %v", err)
	}
}

func TestRecoveryBundleRejectsPrivateAndUnknownArtifacts(t *testing.T) {
	_, err := NewRecoveryBundle(map[string][]byte{
		"owner.key": []byte("private"),
	})
	if !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("private artifact accepted: %v", err)
	}
	_, err = NewRecoveryBundle(map[string][]byte{
		"unexpected.json": []byte("{}"),
	})
	if !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("unknown artifact accepted: %v", err)
	}
}

func TestRecoveryBundleRejectsTamperingAndUnsafeRestore(t *testing.T) {
	v, _, _ := testChainAnchor(t)
	vaultRaw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := NewRecoveryBundle(map[string][]byte{"continuity-vault.json": vaultRaw})
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts[0].Data = "AAAA"
	if err := bundle.Verify(); !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("tampered bundle accepted: %v", err)
	}
	bundle, err = NewRecoveryBundle(map[string][]byte{"continuity-vault.json": vaultRaw})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "restore")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Restore(root); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Restore(root); !errors.Is(err, ErrRecoveryDestinationExists) {
		t.Fatalf("existing destination accepted: %v", err)
	}
}
