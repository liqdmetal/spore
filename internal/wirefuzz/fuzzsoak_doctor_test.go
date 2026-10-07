package wirefuzz

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The install is the one part of the soak nothing else watches. A scheduled task
// that stops starting does not fail: the task stays registered and the ledger
// keeps its last row, so a moved checkout or a moved toolchain looks like a
// quiet week until somebody reads a timestamp. scripts/fuzz-soak.sh --doctor is
// the check for that, and it is only worth anything if its idea of "current"
// is the same as the printer's — so this holds the two against each other: the
// doctor must accept exactly the launcher --print-schedule writes, and must
// report a file that is not that.
//
// It runs the real script, so it needs bash (the doctor is bash; the trend
// reader next door is POSIX sh) and a go on PATH, because a healthy install is
// the premise of the accepting case.

// launcherBlock pulls the launcher out of --print-schedule's output: the text
// between the `cat > ...run-soak.cmd <<'CMD'` line and its terminator, with the
// two-space print indent removed.
var launcherBlock = regexp.MustCompile(`(?ms)^  cat > "[^"]*run-soak\.cmd" <<'CMD'\n(.*)\n  CMD$`)

func printedLauncher(t *testing.T, printed string) string {
	t.Helper()
	m := launcherBlock.FindStringSubmatch(printed)
	if m == nil {
		return ""
	}
	lines := strings.Split(m[1], "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "  ")
	}
	return strings.Join(lines, "\n") + "\n"
}

// runSoak invokes the script and reports its combined output and exit status.
func runSoak(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"../../scripts/fuzz-soak.sh"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running the soak: %v (%s)", err, out)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// TestFuzzSoakDoctorMatchesThePrintedLauncher is the acceptance test for the
// check that catches a silent nightly breakage.
func TestFuzzSoakDoctorMatchesThePrintedLauncher(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the doctor is a bash function")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH; a doctor run would fail on the go check, not the launcher")
	}

	dir := t.TempDir()
	// An empty FUZZ_SOAK_TASK means "no task to inspect", so the doctor's task
	// check stays a note and this pins the launcher half on any host.
	env := append(os.Environ(), "FUZZ_SOAK_DIR="+dir, "FUZZ_SOAK_TASK=")

	printed, code := runSoak(t, env, "--print-schedule")
	if code != 0 {
		t.Fatalf("--print-schedule exited %d:\n%s", code, printed)
	}
	launcher := printedLauncher(t, printed)
	if launcher == "" {
		t.Skip("this host prints a cron line, not a launcher file; nothing to hold the doctor against")
	}

	path := filepath.Join(dir, "run-soak.cmd")
	if err := os.WriteFile(path, []byte(launcher), 0o644); err != nil {
		t.Fatalf("writing the launcher: %v", err)
	}

	out, code := runSoak(t, env, "--doctor")
	if code != 0 {
		t.Errorf("doctor rejected the launcher --print-schedule just wrote (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "launcher is current") {
		t.Errorf("doctor did not report the launcher as current:\n%s", out)
	}

	// --doctor is a read-only verdict: it must not start a pass, and a pass is
	// what writes the ledger and the state file.
	for _, name := range []string{"log.tsv", "last.state", "lock"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("--doctor wrote %s; it must run nothing", name)
		}
	}

	t.Run("a launcher that drifted is reported", func(t *testing.T) {
		if err := os.WriteFile(path, []byte(launcher+"rem drifted\n"), 0o644); err != nil {
			t.Fatalf("perturbing the launcher: %v", err)
		}
		out, code := runSoak(t, env, "--doctor")
		if code == 0 {
			t.Errorf("doctor accepted a launcher that is not what --print-schedule prints:\n%s", out)
		}
		if !strings.Contains(out, "stale") {
			t.Errorf("doctor did not call the launcher stale:\n%s", out)
		}
	})

	t.Run("a missing launcher is reported", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatalf("removing the launcher: %v", err)
		}
		out, code := runSoak(t, env, "--doctor")
		if code == 0 {
			t.Errorf("doctor accepted a state directory with no launcher:\n%s", out)
		}
		if !strings.Contains(out, "no launcher") {
			t.Errorf("doctor did not say the launcher is missing:\n%s", out)
		}
	})
}

// TestFuzzSoakDoctorIsCheapAndReadOnly holds the guarantee that makes --doctor
// safe to call from anywhere at any time: it answers without running a pass, so
// it must not create the ledger, the state file, or the lock a pass would leave
// behind.
func TestFuzzSoakDoctorIsCheapAndReadOnly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the doctor is a bash function")
	}

	dir := t.TempDir()
	env := append(os.Environ(), "FUZZ_SOAK_DIR="+dir, "FUZZ_SOAK_TASK=")
	out, code := runSoak(t, env, "--doctor")

	if code != 0 && code != 1 {
		t.Errorf("doctor exited %d, which is not a verdict (0 healthy, 1 problem):\n%s", code, out)
	}
	if !strings.Contains(out, "fuzz-soak: doctor:") {
		t.Errorf("doctor did not print its summary line:\n%s", out)
	}
	for _, name := range []string{"log.tsv", "last.state", "last-report.md", "last-fuzz.log", "lock"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("--doctor created %s; it runs nothing", name)
		}
	}
}
