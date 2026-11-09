package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/continuity"
	sporecrypto "github.com/liqdmetal/spore/internal/crypto"
)

func writeCheckInEnvelope(t *testing.T, v *continuity.Vault) string {
	t.Helper()
	env, err := v.CheckIns()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "checkins.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func watchAdoptVault(t *testing.T) (*continuity.Vault, []byte) {
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

func watchAdoptCopy(t *testing.T, v *continuity.Vault) *continuity.Vault {
	t.Helper()
	raw, err := v.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	copyV, err := continuity.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return copyV
}

func TestAdoptCheckInEnvelopesAdvancesWatcherCopy(t *testing.T) {
	v, owner := watchAdoptVault(t)
	stale := watchAdoptCopy(t, v)
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	first := writeCheckInEnvelope(t, v)

	adopted, err := adoptCheckInEnvelopes(stale, []string{first})
	if err != nil || adopted != 1 {
		t.Fatalf("adopt = %d, %v", adopted, err)
	}
	if last := stale.Checkins[len(stale.Checkins)-1]; last.Seq != 1 || last.Deadline != 1095 {
		t.Fatalf("copy not advanced: %+v", last)
	}
	if adopted, err := adoptCheckInEnvelopes(stale, []string{first}); err != nil || adopted != 0 {
		t.Fatalf("replay = %d, %v", adopted, err)
	}

	// A second check-in and its envelope, delivered after the first, still
	// converges: a watcher may hold several envelopes at once.
	if err := continuity.CheckIn(v, owner, 1010); err != nil {
		t.Fatal(err)
	}
	second := writeCheckInEnvelope(t, v)
	adopted, err = adoptCheckInEnvelopes(stale, []string{first, second})
	if err != nil || adopted != 1 {
		t.Fatalf("second adopt = %d, %v", adopted, err)
	}
	if last := stale.Checkins[len(stale.Checkins)-1]; last.Seq != 2 {
		t.Fatalf("copy at seq %d, want 2", last.Seq)
	}
}

func TestAdoptCheckInEnvelopesRefusesForeignAndTampered(t *testing.T) {
	v, owner := watchAdoptVault(t)
	stale := watchAdoptCopy(t, v)
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	before, err := stale.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	other, otherOwner := watchAdoptVault(t)
	if err := continuity.CheckIn(other, otherOwner, 1005); err != nil {
		t.Fatal(err)
	}
	foreign := writeCheckInEnvelope(t, other)
	if _, err := adoptCheckInEnvelopes(stale, []string{foreign}); err == nil {
		t.Fatal("adopted an envelope for another vault")
	}

	tampered := writeCheckInEnvelope(t, v)
	raw, err := os.ReadFile(tampered)
	if err != nil {
		t.Fatal(err)
	}
	var broken continuity.CheckInEnvelope
	if err := json.Unmarshal(raw, &broken); err != nil {
		t.Fatal(err)
	}
	broken.Checkins[len(broken.Checkins)-1].Deadline++
	raw, err = json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := adoptCheckInEnvelopes(stale, []string{tampered}); err == nil {
		t.Fatal("adopted a tampered envelope")
	}

	after, err := stale.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused envelope modified the watcher copy")
	}
}

func TestWatchStateSupersededOnlyForwardForSameVault(t *testing.T) {
	v, owner := watchAdoptVault(t)
	observer, _, err := continuity.NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	state, err := continuity.NewWatchState(v, observer)
	if err != nil {
		t.Fatal(err)
	}
	if watchStateSuperseded(state, v) {
		t.Fatal("a current checkpoint is not superseded")
	}
	older := watchAdoptCopy(t, v)
	if err := continuity.CheckIn(v, owner, 1005); err != nil {
		t.Fatal(err)
	}
	if !watchStateSuperseded(state, v) {
		t.Fatal("an older epoch of the same vault should be superseded")
	}
	// A vault older than the checkpoint is a rollback, not an adoption: the
	// watcher must keep erroring instead of following it backward.
	newer, err := continuity.NewWatchState(v, observer)
	if err != nil {
		t.Fatal(err)
	}
	if watchStateSuperseded(newer, older) {
		t.Fatal("a rolled-back vault must not re-anchor a newer checkpoint")
	}
	other, otherOwner := watchAdoptVault(t)
	if err := continuity.CheckIn(other, otherOwner, 1005); err != nil {
		t.Fatal(err)
	}
	if watchStateSuperseded(state, other) {
		t.Fatal("a checkpoint from another vault must not be re-anchored")
	}
}
