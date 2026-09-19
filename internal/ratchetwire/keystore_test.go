package ratchetwire

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStateStoreRoundTripAndTamperReject(t *testing.T) {
	dir := t.TempDir()
	key := filled(8)
	id := [8]byte{1, 2, 3}
	st, err := NewFileStateStore(filepath.Join(dir, "state"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(id, []byte("private session state")); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(id)
	if err != nil || string(got) != "private session state" {
		t.Fatalf("load=%q err=%v", got, err)
	}
	path := st.path(id)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(id); err == nil {
		t.Fatal("tampered state accepted")
	}
}

// TestFileStateStoreRejectsRestoredOlderSnapshotAfterProcessRestart proves
// the exact attack the append-only log exists to stop: an attacker (or a
// failed backup/restore) with filesystem write access swaps the current head
// file for an older, still-validly-authenticated snapshot of the SAME
// session, then the process restarts (so the in-memory sequence map — which
// alone cannot see this — starts empty). Load must still refuse it, because
// the append-only log remembers a higher sequence was already durable.
func TestFileStateStoreRejectsRestoredOlderSnapshotAfterProcessRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := filled(9)
	id := [8]byte{9, 8, 7}

	st1, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.Save(id, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	oldSnapshot, err := os.ReadFile(st1.path(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.Save(id, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if err := st1.Save(id, []byte("v3")); err != nil {
		t.Fatal(err)
	}

	// Attacker/backup-restore: overwrite the head file with the v1 snapshot.
	// The log file is untouched — this is the threat model the log defends
	// against (an attacker who can only replace the mutable head, not edit
	// the append-only log too).
	if err := os.WriteFile(st1.path(id), oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	// Fresh process: new store, empty in-memory sequence map. Without the
	// durable log, this Load would succeed and silently resurrect v1's
	// already-used message keys.
	st2, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Load(id); err == nil {
		t.Fatal("rollback to older snapshot was accepted after simulated process restart")
	}
}

// TestFileStateStoreSaveAfterRestoredOlderSnapshotStillAdvances proves the
// log doesn't just block Load — Save also consults it, so a legitimate new
// Save issued after a rollback attempt still produces a sequence higher than
// anything ever logged, rather than resuming from the swapped-in old head.
func TestFileStateStoreSaveAfterRestoredOlderSnapshotStillAdvances(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	key := filled(11)
	id := [8]byte{5, 5, 5}

	st1, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st1.Save(id, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	oldSnapshot, err := os.ReadFile(st1.path(id))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := st1.Save(id, []byte("advance")); err != nil {
			t.Fatal(err)
		}
	}
	loggedBefore, err := st1.maxLoggedSequence(id)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(st1.path(id), oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	st2, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Save(id, []byte("post-restore")); err != nil {
		t.Fatal(err)
	}
	loggedAfter, err := st2.maxLoggedSequence(id)
	if err != nil {
		t.Fatal(err)
	}
	if loggedAfter <= loggedBefore {
		t.Fatalf("save after restored snapshot did not advance past prior high-water mark: before=%d after=%d", loggedBefore, loggedAfter)
	}
}
