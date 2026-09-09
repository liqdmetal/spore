package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpoolSigVerifyAndTamper: a composed entry verifies, but any tamper to
// a payload field invalidates the signature.
func TestSpoolSigVerifyAndTamper(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "identity.hex")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("ab", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := spoolEntry{
		To: "dero1recipient", Identity: keyFile, Pinned: "aabb",
		Bundle: "/keys/b.json", MsgFile: "/tmp/msg.plain",
		StateDir: dir, StateKey: keyFile,
	}
	e.Sig = spoolSig(&e)
	if !spoolVerify(&e) {
		t.Fatal("valid spool failed verification")
	}
	// Tamper: change the recipient.
	e.To = "dero1evil"
	if spoolVerify(&e) {
		t.Fatal("tampered spool passed verification")
	}
	// Tamper: change the key path.
	e2 := spoolEntry{To: "dero1recipient", Identity: keyFile, Pinned: "aabb",
		Bundle: "/keys/b.json", MsgFile: "/tmp/msg.plain", StateDir: dir, StateKey: keyFile}
	e2.Sig = spoolSig(&e2)
	e2.StateKey = "/etc/passwd"
	if spoolVerify(&e2) {
		t.Fatal("key-path tamper passed verification")
	}
	// Missing signature always fails.
	e3 := spoolEntry{To: "x", Identity: keyFile}
	if spoolVerify(&e3) {
		t.Fatal("unsigned spool passed verification")
	}
}

// TestSpoolPathSafe: relative paths inside the spool are fine; escaping via
// .. is refused.
func TestSpoolPathSafe(t *testing.T) {
	// Absolute paths are user-provided key/bundle paths — always allowed.
	if !spoolPathSafe("spool", filepath.Join(t.TempDir(), "x")) {
		t.Fatal("absolute path should be allowed")
	}
	// Relative containment is judged against the CWD. Set up a real spool
	// dir under the CWD so relative msg paths resolve inside it.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	base := filepath.Join("spool-tmp-test")
	if err := os.MkdirAll(filepath.Join(base, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for _, p := range []string{"msg-1.plain", filepath.Join("sub", "msg-2.plain")} {
		if !spoolPathSafe(base, p) {
			t.Errorf("spoolPathSafe(%q) refused a safe relative path", p)
		}
	}
	for _, p := range []string{"..", filepath.Join("..", "x"), filepath.Join("sub", "..", "..", "x"), ""} {
		if spoolPathSafe(base, p) {
			t.Errorf("spoolPathSafe(%q) allowed an escaping relative path", p)
		}
	}
}
