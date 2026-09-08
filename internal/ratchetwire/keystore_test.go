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
