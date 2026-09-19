package continuity

import (
	"bytes"
	"errors"
	"testing"
	"time"

	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func TestRevocationStateRejectsRecipientRelease(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, recipient := testVault(t, now)
	state, err := NewRevocationState(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Revoke(v, owner.Priv, RevokedRecipient, recipient.Pub, now+1); err != nil {
		t.Fatal(err)
	}
	if err := state.VerifyForVault(v); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := NewRevocationCheckpoint(v, state, owner.Priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseWithRevocations(v, state, checkpoint, recipient.Priv, now+20); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("release error = %v, want ErrKeyRevoked", err)
	}
}

func TestRevocationStateRejectsRollbackAndTamper(t *testing.T) {
	now := int64(1_800_000_000)
	v, owner, recipient := testVault(t, now)
	state, err := NewRevocationState(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Revoke(v, owner.Priv, RevokedRecipient, recipient.Pub, now+1); err != nil {
		t.Fatal(err)
	}
	copyState := *state
	copyState.Records = append([]RevocationRecord(nil), state.Records...)
	copyState.Records[0].Subject = "00" + copyState.Records[0].Subject[2:]
	if err := copyState.VerifyForVault(v); err == nil {
		t.Fatal("tampered revocation record verified")
	}
	checkpoint, err := NewRevocationCheckpoint(v, state, owner.Priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseWithRevocations(v, &RevocationState{Version: state.Version, Type: state.Type, VaultID: state.VaultID, PolicyID: state.PolicyID, OwnerSigPub: state.OwnerSigPub}, checkpoint, recipient.Priv, now+20); err == nil {
		t.Fatal("rollback state allowed release")
	}
}

func TestVaultRotationBindsSuccessorAndRetiresOldVault(t *testing.T) {
	now := int64(1_800_000_000)
	old, oldOwner, recipient := testVault(t, now)
	newOwner, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newRecipient, err := sporecrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newVault, cert, err := RotateVault(old, oldOwner.Priv, CreateOptions{
		OwnerPriv: newOwner.Priv, Recipients: [][]byte{newRecipient.Pub}, Payload: []byte("replacement"),
		CreatedAt: now + 100, Interval: time.Hour, Grace: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRotation(old, newVault, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseWithRotation(old, cert, newVault, recipient.Priv, now+20); !errors.Is(err, ErrVaultRetired) {
		t.Fatalf("retired release error = %v, want ErrVaultRetired", err)
	}
	plain, err := Release(newVault, newRecipient.Priv, now+10_000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, []byte("replacement")) {
		t.Fatalf("successor plaintext = %q", plain)
	}
}
