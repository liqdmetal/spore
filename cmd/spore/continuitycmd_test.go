package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func TestContinuityFileRoundTripAndAtomicModes(t *testing.T) {
	dir := t.TempDir()
	owner, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(dir, "instructions.txt")
	if err := os.WriteFile(payloadPath, []byte("do not publish this"), 0600); err != nil {
		t.Fatal(err)
	}
	ownerPath := filepath.Join(dir, "owner.key")
	if err := os.WriteFile(ownerPath, []byte(hex.EncodeToString(owner.Priv)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, "vault.json")
	v, err := continuity.Create(continuity.CreateOptions{
		OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub},
		Payload: []byte("do not publish this"), CreatedAt: time.Now().Unix(),
		Interval: time.Hour, Grace: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeContinuityVault(vaultPath, v); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0200 == 0 {
		t.Fatalf("vault is not owner-writable: mode %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "do not publish this") {
		t.Fatal("vault file contains plaintext")
	}
	parsed, err := continuity.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.VaultID != v.VaultID {
		t.Fatalf("vault id changed: %s != %s", parsed.VaultID, v.VaultID)
	}
}

func TestParseRecipientPubsRejectsMalformedAndAcceptsMultiple(t *testing.T) {
	one := strings.Repeat("ab", 32)
	pubs, err := parseRecipientPubs(one + "," + strings.Repeat("cd", 32))
	if err != nil || len(pubs) != 2 {
		t.Fatalf("valid recipients: %#v %v", pubs, err)
	}
	for _, bad := range []string{"", "ab", "zz" + strings.Repeat("00", 31), one + ",ab"} {
		if _, err := parseRecipientPubs(bad); err == nil {
			t.Fatalf("accepted malformed recipient list %q", bad)
		}
	}
}
