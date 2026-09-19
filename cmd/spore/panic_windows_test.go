package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsDangerousWipeTargetWindowsHome proves the /usr substring bug: a
// legitimate spore home under C:\Users\... must NOT be refused. "users"
// contains "usr", so a naive strings.Contains over a slash-normalised path
// rejects every target in a Windows user profile — which would make `panic
// -home ~/.spore` unusable on the platform most users run.
func TestIsDangerousWipeTargetWindowsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no user home: %v", err)
	}
	safe := []string{
		filepath.Join(home, ".spore"),
		filepath.Join(home, ".spore", "state"),
		filepath.Join(home, ".spore", "mail.json"),
		filepath.Join(home, "spool"),
	}
	for _, p := range safe {
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		if isDangerousWipeTarget(abs) {
			t.Errorf("isDangerousWipeTarget(%q) = true; a spore dir under the user profile must be wipeable", abs)
		}
	}
}

func TestIsDangerousWipeTargetRefusesRealDanger(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no user home: %v", err)
	}
	danger := []string{home, string(filepath.Separator)}
	if vol := filepath.VolumeName(home); vol != "" {
		danger = append(danger, vol+string(filepath.Separator))
	}
	for _, p := range danger {
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		if !isDangerousWipeTarget(abs) {
			t.Errorf("isDangerousWipeTarget(%q) = false; home/root must be refused", abs)
		}
	}
	// A POSIX system dir is still refused regardless of platform.
	if !isDangerousWipeTarget("/etc/passwd-dir") {
		t.Error("/etc must be refused")
	}
	_ = strings.TrimSpace
}

// TestPanicHomeWipesWholeKit is the end-to-end guarantee: panic -home removes
// every artifact init created, including the dedicated store key.
func TestPanicHomeWipesWholeKit(t *testing.T) {
	home := filepath.Join(t.TempDir(), "spore-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// The artifact set `spore init` produces.
	for _, name := range []string{"identity.key", "spk.key", "state.key", "store.key", "opk-pool.json", "batch.json", "mail.json", "config.json"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state", "session-aa.state"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}

	paniccmd([]string{"-home", home, "-confirm"})

	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("panic -home left the kit behind: %v", err)
	}
}
