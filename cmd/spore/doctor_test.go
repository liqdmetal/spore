package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestDoctorAllGood(t *testing.T) {
	dir := t.TempDir()
	priv := strings.Repeat("11", 32) // 32 bytes of 0x11
	// Hermetic home + config: the key-files check must grade THIS setup,
	// not whatever the developer's machine happens to have at ~/.spore.
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "identity.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := runDoctorChecks(doctorOpts{
		Priv: priv, Dir: dir, Listen: "127.0.0.1:19191",
		Config: filepath.Join(t.TempDir(), "config.json"), // absent = ok
		Home:   home,
	})
	for _, c := range checks {
		if !c.OK {
			t.Errorf("check %s should pass: %s", c.Name, c.Note)
		}
	}
}

// checkByName finds a check by name, so tests do not depend on slice order.
func checkByName(t *testing.T, checks []doctorCheck, name string) doctorCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in results", name)
	return doctorCheck{}
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
	c := checkByName(t, runDoctorChecks(doctorOpts{Dir: filepath.Join(t.TempDir(), "nope")}), "data-dir")
	if c.OK {
		t.Errorf("missing dir should fail: %+v", c)
	}
	// A file, not a directory, fails.
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, []byte("x"), 0o600)
	c = checkByName(t, runDoctorChecks(doctorOpts{Dir: f}), "data-dir")
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
	c = checkByName(t, runDoctorChecks(doctorOpts{Dir: ro}), "data-dir")
	if c.OK {
		t.Errorf("read-only dir should fail write probe: %+v", c)
	}
}

func TestDoctorListenChecks(t *testing.T) {
	c := checkByName(t, runDoctorChecks(doctorOpts{Listen: "127.0.0.1:19191"}), "listen")
	if !c.OK {
		t.Errorf("loopback bind should pass: %+v", c)
	}
	c = checkByName(t, runDoctorChecks(doctorOpts{Listen: ":19191"}), "listen")
	if c.OK || !strings.Contains(c.Note, "NOT loopback") {
		t.Errorf("all-interfaces bind should fail with explanation: %+v", c)
	}
}

// --- config.json validity (check 4) ---

func TestDoctorConfigCheck(t *testing.T) {
	// No config file: pass with an init pointer (config is optional).
	missing := filepath.Join(t.TempDir(), "config.json")
	c := doctorConfigCheck(missing)
	if !c.OK || !strings.Contains(c.Note, "spore init") {
		t.Errorf("missing config should pass with init hint: %+v", c)
	}
	// Corrupt JSON: fail.
	bad := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(bad, []byte("{not json"), 0600)
	c = doctorConfigCheck(bad)
	if c.OK || !strings.Contains(c.Note, "INVALID") {
		t.Errorf("corrupt config must fail: %+v", c)
	}
	// Unknown field (typo protection): fail.
	os.WriteFile(bad, []byte(`{"identty":"x"}`), 0600)
	c = doctorConfigCheck(bad)
	if c.OK {
		t.Errorf("unknown field must fail strict parse: %+v", c)
	}
	// Valid config whose referenced files are missing: fail.
	lying := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(lying, []byte(`{"identity":"`+filepath.ToSlash(filepath.Join(t.TempDir(), "gone.key"))+`","maildb":"`+filepath.ToSlash(filepath.Join(t.TempDir(), "gone.json"))+`"}`), 0600)
	c = doctorConfigCheck(lying)
	if c.OK || !strings.Contains(c.Note, "missing file") {
		t.Errorf("config referencing missing files must fail: %+v", c)
	}
	// Valid config, all referenced files present: pass.
	home := t.TempDir()
	idFile := filepath.Join(home, "identity.key")
	mailFile := filepath.Join(home, "mail.json")
	os.WriteFile(idFile, []byte("k"), 0600)
	os.WriteFile(mailFile, []byte("{}"), 0600)
	good := filepath.Join(home, "config.json")
	os.WriteFile(good, []byte(`{"identity":"`+filepath.ToSlash(idFile)+`","maildb":"`+filepath.ToSlash(mailFile)+`","state_dir":"`+filepath.ToSlash(home)+`"}`), 0600)
	c = doctorConfigCheck(good)
	if !c.OK {
		t.Errorf("valid config with existing paths should pass: %+v", c)
	}
}

// --- listen port availability (check 5) ---

func TestDoctorListenPortCheck(t *testing.T) {
	// A free port passes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	c := doctorListenPortCheck("127.0.0.1:" + freePort)
	if !c.OK || !strings.Contains(c.Note, "free") {
		t.Errorf("free port should pass: %+v", c)
	}
	// An already-held port passes with a caveat (probably your own daemon).
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	heldPort := strconv.Itoa(ln2.Addr().(*net.TCPAddr).Port)
	c = doctorListenPortCheck("127.0.0.1:" + heldPort)
	if !c.OK || !strings.Contains(c.Note, "in use") {
		t.Errorf("held port should pass with in-use note: %+v", c)
	}
	// A malformed address fails.
	c = doctorListenPortCheck("no-port-here")
	if c.OK {
		t.Errorf("address without a port should fail: %+v", c)
	}
	// No address: skipped, not failed.
	c = doctorListenPortCheck("")
	if !c.OK || !strings.Contains(c.Note, "skipped") {
		t.Errorf("empty listen should be skipped: %+v", c)
	}
}

// --- key file permissions (check 6) ---

func TestDoctorKeyFilesCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission grading is POSIX-only (mode bits not enforced on windows)")
	}
	// No spore home: fail with init hint.
	empty := filepath.Join(t.TempDir(), "no-home")
	c := doctorKeyFilesCheck(empty)
	if c.OK || !strings.Contains(c.Note, "spore init") {
		t.Errorf("missing home should fail with init hint: %+v", c)
	}
	// Home without identity.key: fail.
	home := t.TempDir()
	c = doctorKeyFilesCheck(home)
	if c.OK || !strings.Contains(c.Note, "identity.key") {
		t.Errorf("home without identity.key should fail: %+v", c)
	}
	// Proper home: 0600 keys, 0700 dir — pass.
	good := t.TempDir()
	os.Chmod(good, 0o700)
	for _, name := range []string{"identity.key", "spk.key", "state.key", "store.key", "opk-pool.json", "config.json", "mail.json"} {
		os.WriteFile(filepath.Join(good, name), []byte("x"), 0o600)
	}
	c = doctorKeyFilesCheck(good)
	if !c.OK {
		t.Errorf("tight-permission home should pass: %+v", c)
	}
	// A 0644 secret fails with the offending mode in the note.
	leaky := t.TempDir()
	os.Chmod(leaky, 0o700)
	os.WriteFile(filepath.Join(leaky, "identity.key"), []byte("k"), 0o600)
	os.WriteFile(filepath.Join(leaky, "spk.key"), []byte("k"), 0o644)
	c = doctorKeyFilesCheck(leaky)
	if c.OK || !strings.Contains(c.Note, "spk.key=644") {
		t.Errorf("0644 secret must fail naming the file: %+v", c)
	}
	// A world-scannable home dir fails too.
	open := t.TempDir()
	os.Chmod(open, 0o755)
	os.WriteFile(filepath.Join(open, "identity.key"), []byte("k"), 0o600)
	c = doctorKeyFilesCheck(open)
	if c.OK || !strings.Contains(c.Note, "home dir=755") {
		t.Errorf("0755 home dir must fail: %+v", c)
		os.Chmod(open, 0o700)
	}
}

// Integration: a fully-initialized home (via initcmd's own file layout)
// passes config + key-files checks together.
func TestDoctorHomeLayoutPasses(t *testing.T) {
	home := t.TempDir()
	// Minimal replica of what `spore init` writes.
	for _, name := range []string{"identity.key", "spk.key", "state.key", "store.key", "opk-pool.json"} {
		p := filepath.Join(home, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{Dir: home, Identity: filepath.Join(home, "identity.key"), SPK: filepath.Join(home, "spk.key"),
		OpkPool: filepath.Join(home, "opk-pool.json"), StoreKey: filepath.Join(home, "store.key"),
		StateDir: filepath.Join(home, "state"), StateKey: filepath.Join(home, "state.key")}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(home, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(home, "state"), 0o700)

	checks := runDoctorChecks(doctorOpts{Config: cfgPath, Home: home})
	for _, name := range []string{"config", "key-files"} {
		if c := checkByName(t, checks, name); !c.OK {
			t.Errorf("%s should pass on an init-shaped home: %+v", name, c)
		}
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
