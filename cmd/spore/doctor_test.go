package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDoctorAllGood(t *testing.T) {
	dir := t.TempDir()
	priv := strings.Repeat("11", 32) // 32 bytes of 0x11
	checks := runDoctorChecks(doctorOpts{Priv: priv, Dir: dir, Listen: "127.0.0.1:19191"})
	for _, c := range checks {
		if !c.OK {
			t.Errorf("check %s should pass: %s", c.Name, c.Note)
		}
	}
}

func TestDoctorIdentityChecks(t *testing.T) {
	// Bad hex.
	c := runDoctorChecks(doctorOpts{Priv: "zz"})[0]
	if c.Name != "identity" || c.OK {
		t.Errorf("bad hex should fail identity: %+v", c)
	}
	// Wrong length ("aabb" = 2 bytes).
	c = runDoctorChecks(doctorOpts{Priv: "aabb"})[0]
	if c.OK || !strings.Contains(c.Note, "2 bytes, want 32") {
		t.Errorf("short key should fail identity with length note: %+v", c)
	}
	// Missing key is a soft fail with guidance.
	c = runDoctorChecks(doctorOpts{})[0]
	if c.OK || !strings.Contains(c.Note, "keygen") {
		t.Errorf("missing priv should point at keygen: %+v", c)
	}
}

func TestDoctorDirChecks(t *testing.T) {
	// Nonexistent dir fails with a create hint.
	c := runDoctorChecks(doctorOpts{Dir: filepath.Join(t.TempDir(), "nope")})[1]
	if c.Name != "data-dir" || c.OK {
		t.Errorf("missing dir should fail: %+v", c)
	}
	// A file, not a directory, fails.
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("x"), 0o600)
	c = runDoctorChecks(doctorOpts{Dir: f})[1]
	if c.OK {
		t.Errorf("file-as-dir should fail: %+v", c)
	}
	// Read-only dir fails the write probe. POSIX-only: Windows enforces
	// directory write-protection via FILE_ATTRIBUTE, not the mode bits.
	if runtime.GOOS == "windows" {
		t.Skip("windows does not honor mode-bit read-only dirs")
	}
	ro := t.TempDir()
	os.Chmod(ro, 0o555)
	defer os.Chmod(ro, 0o755)
	c = runDoctorChecks(doctorOpts{Dir: ro})[1]
	if c.OK {
		t.Errorf("read-only dir should fail write probe: %+v", c)
	}
}

func TestDoctorListenChecks(t *testing.T) {
	c := runDoctorChecks(doctorOpts{Listen: "127.0.0.1:19191"})[2]
	if c.Name != "listen" || !c.OK {
		t.Errorf("loopback bind should pass: %+v", c)
	}
	c = runDoctorChecks(doctorOpts{Listen: ":19191"})[2]
	if c.OK || !strings.Contains(c.Note, "NOT loopback") {
		t.Errorf("all-interfaces bind should fail with explanation: %+v", c)
	}
}

// Sanity: the priv hex printed by keygen round-trips through the identity check.
func TestDoctorKeygenCompatible(t *testing.T) {
	raw, _ := hex.DecodeString(strings.Repeat("ab", 32))
	c := runDoctorChecks(doctorOpts{Priv: hex.EncodeToString(raw)})[0]
	if !c.OK || !strings.Contains(c.Note, "publish BOTH") {
		t.Errorf("valid key should pass with publish guidance: %+v", c)
	}
}
