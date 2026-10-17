package ratchetwire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

var (
	backupTestPass     = []byte("correct horse battery")
	backupTestIdentity = []byte("0123456789abcdef0123456789abcdef")
	backupTestStateKey = bytes.Repeat([]byte{7}, 32)
	backupTestSession  = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
)

func backupTestDevice(t *testing.T, dir string) *DeviceState {
	t.Helper()
	dev, err := LoadOrCreateDevice(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dev
}

// saveSession advances the session in dir by n saves, so its sequence is n.
func saveSession(t *testing.T, dir string, key []byte, state string, n int) {
	t.Helper()
	store, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := store.Save(backupTestSession, []byte(state)); err != nil {
			t.Fatal(err)
		}
	}
}

func loadSession(t *testing.T, dir string, key []byte) string {
	t.Helper()
	store, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Load(backupTestSession)
	if err != nil {
		t.Fatal(err)
	}
	return string(st)
}

func restoreInto(t *testing.T, dir string, key, pass, raw []byte) (*RestoreResult, error) {
	t.Helper()
	opened, err := OpenBackup(pass, raw)
	if err != nil {
		return nil, err
	}
	return opened.Restore(dir, key, AnchorCheck{})
}

func TestBackupRoundTripRestoresDeviceSessionsAndIdentity(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "ratchet-v2", 2)

	raw, gen, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 {
		t.Fatalf("first backup generation = %d, want 1", gen)
	}
	if bytes.Contains(raw, []byte("ratchet-v2")) || bytes.Contains(raw, backupTestIdentity) {
		t.Fatal("backup file leaks plaintext session or identity bytes")
	}

	dst := t.TempDir()
	opened, err := OpenBackup(backupTestPass, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Identity, backupTestIdentity) {
		t.Fatal("identity key did not round-trip")
	}
	res, err := opened.Restore(dst, backupTestStateKey, AnchorCheck{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Device != dev.ID || res.Sessions != 1 || res.Generation != 1 {
		t.Fatalf("restore result = %+v", res)
	}
	if got := loadSession(t, dst, backupTestStateKey); got != "ratchet-v2" {
		t.Fatalf("restored session state = %q", got)
	}
	restored, err := readDeviceFile(dst)
	if err != nil || restored == nil || restored.ID != dev.ID {
		t.Fatalf("restored device identity = %+v, %v", restored, err)
	}
}

func TestBackupRejectsWrongPassphrase(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "s", 1)
	raw, _, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup([]byte("not the passphrase"), raw); err == nil {
		t.Fatal("backup opened with the wrong passphrase")
	}
}

func TestBackupRejectsTamperedHeaderAndCiphertext(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "s", 1)
	raw, _, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}

	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	// Re-stamping the generation must break authentication, because the header
	// is bound as associated data.
	env.Generation = 99
	tamperedHeader, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(backupTestPass, tamperedHeader); err == nil {
		t.Fatal("backup with an altered generation opened")
	}

	env.Generation = 1
	env.Ciphertext[len(env.Ciphertext)/2] ^= 0x01
	tamperedBody, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(backupTestPass, tamperedBody); err == nil {
		t.Fatal("backup with a flipped ciphertext byte opened")
	}
}

func TestRestoreRefusesOlderGenerationThanDeviceHighWater(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "v1", 1)
	old, gen1, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	saveSession(t, src, backupTestStateKey, "v2", 1)
	_, gen2, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	if gen1 != 1 || gen2 != 2 {
		t.Fatalf("generations = %d, %d; want 1, 2", gen1, gen2)
	}

	// The device has already reached generation 2, so replaying generation 1
	// must be refused, and the live session must be left as it is.
	_, err = restoreInto(t, src, backupTestStateKey, backupTestPass, old)
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("expected generation rollback refusal, got %v", err)
	}
	if got := loadSession(t, src, backupTestStateKey); got != "v2" {
		t.Fatalf("refused restore changed the live session to %q", got)
	}
}

func TestRestoreRefusesSessionBehindLocalDurableSequence(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "at-2", 2)
	backup, gen, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 {
		t.Fatalf("generation = %d, want 1", gen)
	}

	// The session moves on without another backup. The generation mark stays
	// at 1, so only the per-session sequence check can catch restoring the
	// older ratchet state.
	saveSession(t, src, backupTestStateKey, "at-3", 1)
	_, err = restoreInto(t, src, backupTestStateKey, backupTestPass, backup)
	if err == nil || !strings.Contains(err.Error(), "roll the ratchet back") {
		t.Fatalf("expected session rollback refusal, got %v", err)
	}
	if got := loadSession(t, src, backupTestStateKey); got != "at-3" {
		t.Fatalf("refused restore changed the live session to %q", got)
	}
}

func TestRestoreRefusesDifferentDevice(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "s", 1)
	raw, _, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreInto(t, t.TempDir(), backupTestStateKey, backupTestPass, raw); err != nil {
		t.Fatalf("restore onto empty storage should succeed: %v", err)
	}

	foreign := t.TempDir()
	backupTestDevice(t, foreign) // a different device owns this state dir
	_, err = restoreInto(t, foreign, backupTestStateKey, backupTestPass, raw)
	if err == nil || !strings.Contains(err.Error(), "belongs to device") {
		t.Fatalf("expected device mismatch refusal, got %v", err)
	}
}

func TestRestoreRejectsWrongStateKey(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	saveSession(t, src, backupTestStateKey, "s", 1)
	raw, _, err := CreateBackup(src, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := bytes.Repeat([]byte{9}, 32)
	if _, err := restoreInto(t, t.TempDir(), wrongKey, backupTestPass, raw); err == nil {
		t.Fatal("restore under a different state key succeeded")
	}
}

func TestBackupRequiresLongPassphraseAndIdentity(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	if _, _, err := CreateBackup(src, backupTestStateKey, []byte("short"), backupTestIdentity, dev); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if _, _, err := CreateBackup(src, backupTestStateKey, backupTestPass, nil, dev); err == nil {
		t.Fatal("backup without an identity key accepted")
	}
}
