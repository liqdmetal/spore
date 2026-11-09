package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func continuityMsgVault(t *testing.T) (*continuity.Vault, []byte) {
	t.Helper()
	owner, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := continuity.Create(continuity.CreateOptions{
		OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub},
		Payload: []byte("sealed"), CreatedAt: 1000,
		Interval: 60 * time.Second, Grace: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, owner.Priv
}

func continuityMsgBody(t *testing.T, v *continuity.Vault) []byte {
	t.Helper()
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalContinuityCheckInMessage(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestContinuityCheckInMessageRoundTrip(t *testing.T) {
	v, owner := continuityMsgVault(t)
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	body := continuityMsgBody(t, v)
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		t.Fatal(err)
	}
	if head.Type != continuityCheckInType {
		t.Fatalf("type = %q, want %q", head.Type, continuityCheckInType)
	}
	if strings.Contains(string(body), "sealed") || strings.Contains(string(body), "payload_ciphertext") {
		t.Fatal("check-in message carries payload material")
	}
	env, isCheckIn, err := parseContinuityCheckInMessage(body)
	if err != nil || !isCheckIn {
		t.Fatalf("parse = %v, %v", isCheckIn, err)
	}
	if env.VaultID != v.VaultID || len(env.Checkins) != len(v.Checkins) {
		t.Fatalf("envelope mismatch: %+v", env)
	}
	if _, isCheckIn, err := parseContinuityCheckInMessage([]byte("just a message")); isCheckIn || err != nil {
		t.Fatalf("plain text treated as check-ins: %v %v", isCheckIn, err)
	}
	withExtra := strings.Replace(string(body), `{"type"`, `{"extra":1,"type"`, 1)
	if _, isCheckIn, err := parseContinuityCheckInMessage([]byte(withExtra)); !isCheckIn || err == nil {
		t.Fatal("accepted a check-in message with an unknown field")
	}
	if _, isCheckIn, err := parseContinuityCheckInMessage([]byte(`{"type":"` + continuityCheckInType + `"}`)); !isCheckIn || err == nil {
		t.Fatal("accepted a typed message with no chain")
	}
}

func TestAdoptContinuityCheckInMessageAdvancesVaultFile(t *testing.T) {
	v, owner := continuityMsgVault(t)
	vaultPath := filepath.Join(t.TempDir(), "vault.json")
	if err := writeContinuityVault(vaultPath, v); err != nil {
		t.Fatal(err)
	}
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	body := continuityMsgBody(t, v)

	summary, isCheckIn, err := adoptContinuityCheckInMessage(vaultPath, body)
	if err != nil || !isCheckIn {
		t.Fatalf("adopt = %q, %v, %v", summary, isCheckIn, err)
	}
	if !strings.Contains(summary, "adopted: +1") {
		t.Fatalf("summary = %q", summary)
	}
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := continuity.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if last := merged.Checkins[len(merged.Checkins)-1]; last.Seq != 1 || last.Deadline != 1095 {
		t.Fatalf("vault not advanced: %+v", last)
	}
	again, _, err := adoptContinuityCheckInMessage(vaultPath, body)
	if err != nil || !strings.Contains(again, "already current") {
		t.Fatalf("replay = %q, %v", again, err)
	}
}

func TestAdoptContinuityCheckInMessageRefusesBadMessages(t *testing.T) {
	v, owner := continuityMsgVault(t)
	vaultPath := filepath.Join(t.TempDir(), "vault.json")
	if err := writeContinuityVault(vaultPath, v); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	good := continuityMsgBody(t, v)

	other, otherOwner := continuityMsgVault(t)
	if err := continuity.CheckIn(other, otherOwner, 1005); err != nil {
		t.Fatal(err)
	}
	foreign := continuityMsgBody(t, other)

	var broken continuityCheckInMessage
	if err := json.Unmarshal(good, &broken); err != nil {
		t.Fatal(err)
	}
	broken.Checkins[len(broken.Checkins)-1].Deadline++
	tampered, err := json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string][]byte{"foreign": foreign, "tampered": tampered} {
		if _, isCheckIn, err := adoptContinuityCheckInMessage(vaultPath, body); !isCheckIn || err == nil {
			t.Fatalf("%s: adopted (%v %v)", name, isCheckIn, err)
		}
		after, err := os.ReadFile(vaultPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("%s: refusal modified the vault", name)
		}
	}
	if _, isCheckIn, err := adoptContinuityCheckInMessage(vaultPath, []byte("hello")); isCheckIn || err != nil {
		t.Fatalf("plain text reported as check-ins: %v %v", isCheckIn, err)
	}
}
