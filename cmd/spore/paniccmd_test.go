package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPanicWipesFilesAndDirs(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	spool := filepath.Join(root, "spool")
	mdb := filepath.Join(root, "mail.json")
	for _, d := range []string{state, spool} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{
		filepath.Join(state, "session-0102.state"),
		filepath.Join(state, "session-0102.log"),
		filepath.Join(spool, "send-1.json"),
		filepath.Join(spool, "msg-1.plain"),
		mdb,
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("secret-bytes-aaaaaaaaaaaaaaaa"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	paniccmd([]string{"-state-dir", state, "-spool", spool, "-maildb", mdb, "-confirm"})
	for _, f := range files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("panic left %s behind (stat err=%v)", f, err)
		}
	}
	for _, d := range []string{state, spool} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("panic left dir %s behind", d)
		}
	}
}

func TestPanicRefusesDangerousTargets(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	for _, dangerous := range []string{home, "/", `C:\`, `C:\Windows`, filepath.Dir(home)} {
		if !isDangerousWipeTarget(dangerous) {
			t.Errorf("isDangerousWipeTarget(%q) = false; MUST refuse", dangerous)
		}
	}
	// A normal spore dir under home is safe to wipe.
	if isDangerousWipeTarget(filepath.Join(home, ".spore", "state")) {
		t.Error("refused a legitimate .spore/state target")
	}
}
