package continuity

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
)

func TestRecoveryBundleRejectsCrossEpochPolicy(t *testing.T) {
	v1, _, _ := testChainAnchor(t)
	v2, policy2, _ := testChainAnchor(t)
	vaultRaw, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := json.Marshal(policy2)
	if err != nil {
		t.Fatal(err)
	}
	if v1.VaultID == v2.VaultID {
		t.Fatal("test vaults unexpectedly share an identifier")
	}
	_, err = NewRecoveryBundle(map[string][]byte{
		"continuity-vault.json": vaultRaw,
		"quorum-policy.json":    policyRaw,
	})
	if !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("cross-epoch policy accepted: %v", err)
	}
}

func TestRecoveryBundleRejectsReceiptWireDigestMismatch(t *testing.T) {
	v, policy, anchor := testChainAnchor(t)
	wire, err := anchor.ToDEROAnchor()
	if err != nil {
		t.Fatal(err)
	}
	packed, err := dero.PackArguments(wire.ToArguments())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewAnchorReceipt(anchor, "synthetic-txid", "dero1syntheticdestination", 16, time.Now().Unix(), DigestAnchorWire(packed))
	if err != nil {
		t.Fatal(err)
	}
	receipt.WireDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRecoveryBundle(map[string][]byte{
		"continuity-vault.json":          vaultRaw,
		"quorum-policy.json":             policyRaw,
		"continuity-anchor.json":         anchorRaw,
		"continuity-anchor-receipt.json": receiptRaw,
	})
	if !errors.Is(err, ErrInvalidRecoveryBundle) {
		t.Fatalf("receipt with forged wire digest accepted: %v", err)
	}
}
