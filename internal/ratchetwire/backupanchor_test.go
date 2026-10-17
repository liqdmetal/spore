package ratchetwire

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func anchorTestBackup(t *testing.T, dir string, dev *DeviceState, state string) ([]byte, uint64) {
	t.Helper()
	saveSession(t, dir, backupTestStateKey, state, 1)
	raw, gen, err := CreateBackup(dir, backupTestStateKey, backupTestPass, backupTestIdentity, dev)
	if err != nil {
		t.Fatal(err)
	}
	return raw, gen
}

func TestAnchorRefusesRollbackOnEmptyStorage(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	anchorPath := filepath.Join(t.TempDir(), "anchor.json") // kept outside the state dir

	old, gen1 := anchorTestBackup(t, src, dev, "v1")
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, gen1); err != nil {
		t.Fatal(err)
	}
	newer, gen2 := anchorTestBackup(t, src, dev, "v2")
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, gen2); err != nil {
		t.Fatal(err)
	}

	// Without the anchor, empty storage has nothing to compare with, so the
	// old backup restores. That is the gap the anchor closes.
	if _, err := restoreInto(t, t.TempDir(), backupTestStateKey, backupTestPass, old); err != nil {
		t.Fatalf("expected the unanchored restore to succeed (the gap): %v", err)
	}

	empty := t.TempDir()
	_, err := restoreAnchored(t, empty, old, AnchorCheck{Path: anchorPath})
	if err == nil || !strings.Contains(err.Error(), "external anchor") {
		t.Fatalf("expected anchor rollback refusal, got %v", err)
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatalf("refused anchored restore wrote %d entries", len(entries))
	}

	res, err := restoreAnchored(t, t.TempDir(), newer, AnchorCheck{Path: anchorPath})
	if err != nil {
		t.Fatalf("current backup refused: %v", err)
	}
	if res.Generation != gen2 {
		t.Fatalf("restored generation = %d, want %d", res.Generation, gen2)
	}
}

func TestAnchorMissingRefusedUnlessInit(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	raw, gen := anchorTestBackup(t, src, dev, "v1")
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")

	if _, err := restoreAnchored(t, t.TempDir(), raw, AnchorCheck{Path: anchorPath}); err == nil || !strings.Contains(err.Error(), "no backup anchor") {
		t.Fatalf("missing anchor must be refused, got %v", err)
	}
	if _, err := os.Stat(anchorPath); !os.IsNotExist(err) {
		t.Fatal("refused restore created the anchor")
	}

	if _, err := restoreAnchored(t, t.TempDir(), raw, AnchorCheck{Path: anchorPath, Init: true}); err != nil {
		t.Fatalf("init restore failed: %v", err)
	}
	a, err := ReadBackupAnchor(anchorPath, backupTestStateKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.Device != dev.ID || a.Generation != gen {
		t.Fatalf("init anchor = %+v, want device %s generation %d", a, dev.ID, gen)
	}
}

func TestAnchorTamperAndWrongKeyRejected(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	raw, gen := anchorTestBackup(t, src, dev, "v1")
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, gen+1); err != nil {
		t.Fatal(err)
	}

	// An attacker lowers the generation but keeps the old MAC.
	var rec backupAnchorRecord
	stored, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stored, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Generation = gen
	lowered, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorPath, lowered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBackupAnchor(anchorPath, backupTestStateKey); err == nil {
		t.Fatal("lowered anchor authenticated")
	}
	if _, err := restoreAnchored(t, t.TempDir(), raw, AnchorCheck{Path: anchorPath}); err == nil {
		t.Fatal("restore accepted a tampered anchor")
	}

	// Restore the genuine anchor, then check a different state key.
	if err := os.WriteFile(anchorPath, stored, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBackupAnchor(anchorPath, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("anchor authenticated under the wrong state key")
	}
}

func TestAnchorNeverLowered(t *testing.T) {
	dev := backupTestDevice(t, t.TempDir())
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, 5); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, 4); err == nil {
		t.Fatal("anchor was lowered from 5 to 4")
	}
	after, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused lowering changed the anchor file")
	}
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, dev.ID, 5); err != nil {
		t.Fatalf("re-recording the same generation should be a no-op: %v", err)
	}
}

func TestAnchorRefusesOtherDeviceOnRestore(t *testing.T) {
	src := t.TempDir()
	dev := backupTestDevice(t, src)
	raw, gen := anchorTestBackup(t, src, dev, "v1")
	other := backupTestDevice(t, t.TempDir())
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	if err := WriteBackupAnchor(anchorPath, backupTestStateKey, other.ID, gen); err != nil {
		t.Fatal(err)
	}
	_, err := restoreAnchored(t, t.TempDir(), raw, AnchorCheck{Path: anchorPath})
	if err == nil || !strings.Contains(err.Error(), "is for device") {
		t.Fatalf("expected device mismatch refusal, got %v", err)
	}
}

func restoreAnchored(t *testing.T, dir string, raw []byte, anchor AnchorCheck) (*RestoreResult, error) {
	t.Helper()
	opened, err := OpenBackup(backupTestPass, raw)
	if err != nil {
		t.Fatal(err)
	}
	return opened.Restore(dir, backupTestStateKey, anchor)
}
