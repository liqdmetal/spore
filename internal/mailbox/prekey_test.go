package mailbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

func testPrekey() ratchet.SPKBundle {
	var b ratchet.SPKBundle
	b.IKPub[0] = 1
	b.SPKPub[0] = 2
	b.SPKSig[0] = 3
	return b
}

func TestOpenLoadsPersistedPrekey(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := testPrekey()
	if err := m.publishPrekey(want); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.currentPrekey()
	if !ok {
		t.Fatal("reopened mailbox has no persisted prekey")
	}
	if got != want {
		t.Fatalf("reopened prekey = %#v, want %#v", got, want)
	}
}

func TestOpenRejectsMalformedPersistedPrekey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prekeyFile), []byte(`{"bundle":{"ik_pub":"bad"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil {
		t.Fatal("Open accepted malformed persisted prekey")
	}
}

func TestPublishPrekeyReplacesAtomicallyAndRestrictively(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.publishPrekey(testPrekey()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, prekeyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not expose POSIX permission bits through os.FileMode;
	// publishPrekey still requests 0600 and enforces it where supported.
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("prekey mode = %o, want 600", got)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(prekeyFile)+5 && entry.Name()[:len(prekeyFile)+5] == prekeyFile+".tmp-" {
			t.Fatalf("temporary prekey file left behind: %s", entry.Name())
		}
	}
}
