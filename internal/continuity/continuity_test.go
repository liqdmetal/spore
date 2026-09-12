package continuity

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func testKey(t *testing.T) *sporecrypto.KeyPair {
	t.Helper()
	k, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testVault(t *testing.T, now int64) (*Vault, *sporecrypto.KeyPair, *sporecrypto.KeyPair) {
	t.Helper()
	owner := testKey(t)
	recipient := testKey(t)
	v, err := Create(CreateOptions{
		OwnerPriv:  owner.Priv,
		Recipients: [][]byte{recipient.Pub},
		Payload:    []byte("sealed continuity instructions"),
		CreatedAt:  now,
		Interval:   10 * time.Second,
		Grace:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, owner, recipient
}

func TestCreateVerifyAndReleaseAtDeadline(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, recipient := testVault(t, now)
	if err := v.Verify(); err != nil {
		t.Fatal(err)
	}
	st, err := v.Status(now + 14)
	if err != nil {
		t.Fatal(err)
	}
	if st.Releasable {
		t.Fatal("vault became releasable before deadline")
	}
	if _, err := Release(v, recipient.Priv, now+14); !errors.Is(err, ErrNotDue) {
		t.Fatalf("release before deadline: got %v, want ErrNotDue", err)
	}
	plain, err := Release(v, recipient.Priv, now+15)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "sealed continuity instructions" {
		t.Fatalf("released payload = %q", plain)
	}
}

func TestOnTimeCheckinMovesDeadline(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, recipient := testVault(t, now)
	if err := CheckIn(v, owner.Priv, now+5); err != nil {
		t.Fatal(err)
	}
	if len(v.Checkins) != 2 || v.Checkins[1].Seq != 1 {
		t.Fatalf("check-in chain = %#v", v.Checkins)
	}
	if _, err := Release(v, recipient.Priv, now+19); !errors.Is(err, ErrNotDue) {
		t.Fatalf("release after old deadline: got %v, want ErrNotDue", err)
	}
	if _, err := Release(v, recipient.Priv, now+20); err != nil {
		t.Fatalf("release at moved deadline: %v", err)
	}
}

func TestLateCheckinCannotResurrectVault(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, recipient := testVault(t, now)
	if err := CheckIn(v, owner.Priv, now+15); !errors.Is(err, ErrDeadlinePassed) {
		t.Fatalf("late check-in: got %v, want ErrDeadlinePassed", err)
	}
	if len(v.Checkins) != 1 {
		t.Fatalf("late check-in mutated chain: %#v", v.Checkins)
	}
	if _, err := Release(v, recipient.Priv, now+15); err != nil {
		t.Fatalf("vault should release after missed deadline: %v", err)
	}
}

func TestTamperingAndWrongRecipientFailClosed(t *testing.T) {
	now := int64(1_800_000_000)
	v, _, recipient := testVault(t, now)
	v.Recipients[0].Ciphertext = v.Recipients[0].Ciphertext[:len(v.Recipients[0].Ciphertext)-2] + "00"
	if err := v.Verify(); err == nil {
		t.Fatal("tampered ciphertext verified")
	}

	v, _, recipient = testVault(t, now)
	wrong := testKey(t)
	if _, err := Release(v, wrong.Priv, now+15); !errors.Is(err, ErrRecipientNotFound) {
		t.Fatalf("wrong recipient: got %v, want ErrRecipientNotFound", err)
	}
	_ = recipient
}

func TestCheckinChainTamperingFails(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, _ := testVault(t, now)
	if err := CheckIn(v, owner.Priv, now+5); err != nil {
		t.Fatal(err)
	}
	v.Checkins[1].Prev = "00"
	if err := v.Verify(); err == nil {
		t.Fatal("check-in with broken predecessor verified")
	}
}

func TestVaultJSONDoesNotContainPlaintext(t *testing.T) {
	now := int64(1_800_000_000)
	payload := []byte("never store this continuity secret in clear")
	owner := testKey(t)
	recipient := testKey(t)
	v, err := Create(CreateOptions{
		OwnerPriv:  owner.Priv,
		Recipients: [][]byte{recipient.Pub},
		Payload:    payload,
		CreatedAt:  now,
		Interval:   time.Hour,
		Grace:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, payload) {
		t.Fatal("vault JSON contains plaintext payload")
	}
}

func TestPrivateInputsAreNotMutated(t *testing.T) {
	now := int64(1_800_000_000)
	owner := testKey(t)
	recipient := testKey(t)
	ownerBefore := append([]byte(nil), owner.Priv...)
	if _, err := Create(CreateOptions{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: now, Interval: time.Hour, Grace: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owner.Priv, ownerBefore) {
		t.Fatal("Create mutated caller-owned owner key")
	}
	v, _, _ := testVault(t, now)
	recipientBefore := append([]byte(nil), recipient.Priv...)
	if _, err := Release(v, recipient.Priv, now+15); err == nil {
		t.Fatal("unexpected release with unrelated recipient")
	}
	if !bytes.Equal(recipient.Priv, recipientBefore) {
		t.Fatal("Release mutated caller-owned recipient key")
	}
}

func TestArtifactLimitsFailClosed(t *testing.T) {
	owner := testKey(t)
	recipient := testKey(t)
	tooLarge := make([]byte, MaxPayloadBytes+1)
	if _, err := Create(CreateOptions{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: tooLarge, CreatedAt: 1_800_000_000, Interval: time.Second, Grace: 0}); err == nil {
		t.Fatal("accepted oversized payload")
	}
	v, _, _ := testVault(t, 1_800_000_000)
	v.Recipients = append(v.Recipients, make([]RecipientWrap, MaxRecipients)...)
	if err := v.Verify(); err == nil {
		t.Fatal("accepted oversized recipient set")
	}
	v, _, _ = testVault(t, 1_800_000_000)
	v.Checkins = append(v.Checkins, make([]CheckInRecord, MaxCheckIns)...)
	if err := v.Verify(); err == nil {
		t.Fatal("accepted oversized check-in chain")
	}
}

func TestOverflowAndInvalidPolicyFailClosed(t *testing.T) {
	owner := testKey(t)
	recipient := testKey(t)
	for _, tc := range []CreateOptions{
		{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: 1, Interval: 0, Grace: time.Second},
		{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: 1, Interval: time.Second, Grace: -time.Second},
		{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: 1, Interval: time.Duration(1<<63 - 1), Grace: time.Second},
	} {
		if _, err := Create(tc); err == nil {
			t.Fatal("accepted invalid or overflowing policy")
		}
	}
}

func TestRandomnessSourceIsUsed(t *testing.T) {
	// The production path must not become deterministic merely because tests
	// use fixed timestamps. Two vaults with the same inputs have different IDs
	// and ciphertexts.
	now := time.Now().Unix()
	owner := testKey(t)
	recipient := testKey(t)
	v1, err := Create(CreateOptions{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: now, Interval: time.Hour, Grace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := Create(CreateOptions{OwnerPriv: owner.Priv, Recipients: [][]byte{recipient.Pub}, Payload: []byte("x"), CreatedAt: now, Interval: time.Hour, Grace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(v1.Recipients[0].CiphertextBytes(), v2.Recipients[0].CiphertextBytes()) || v1.VaultID == v2.VaultID {
		t.Fatal("vault creation reused randomness")
	}
	_ = rand.Reader
}
