package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The haul's own tests drive --propose, which is the same step by hand. This
// drives the pass, because --pr is where the hand-off actually happens and the
// step that follows it — restoring the corpus the haul just proposed — only runs
// there. A pass also writes the two artifacts a human reads, the report and the
// ledger row, and neither is a function that can be called on its own.
//
// The pass's two minutes-long steps are stubbed out. What is under test is the
// soak's own orchestration — the ledger row, the report, the haul, the restore —
// and a real deep pass would be minutes of fuzzing that says nothing about any of
// them. fuzz-smoke.sh and fuzz-corpus.sh are replaced by no-ops in the sandbox, and
// a failing `go` is put in front of the real one so the coverage measurement
// answers the way a broken replay does instead of building the module.

// stubCalves stubs the pass's expensive callees and returns a PATH whose first
// entry is a `go` that refuses to run, so the pass never builds anything. The
// harvester stub writes down how it was called, because a no-op that says nothing
// would hide the flags the pass asks it for — the reclaim among them.
func (sb sandbox) stubCalves(t *testing.T) string {
	t.Helper()
	harvester := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/../.fuzz-corpus.argv\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-corpus.sh"), []byte(harvester), 0o755); err != nil {
		t.Fatalf("stubbing fuzz-corpus.sh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-smoke.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("stubbing fuzz-smoke.sh: %v", err)
	}
	bin := filepath.Join(filepath.Dir(sb.repo), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("creating %s: %v", bin, err)
	}
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\necho 'stub go: refusing' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing the go stub: %v", err)
	}
	return bin
}

// pass runs a whole pass with --pr in the sandbox and returns what it printed.
func (sb sandbox) pass(t *testing.T, bin string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "scripts/fuzz-soak.sh", "--time", "1", "--pr")
	cmd.Dir = sb.repo
	cmd.Env = append(os.Environ(),
		"FUZZ_SOAK_DIR="+sb.soakDir(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running a pass: %v (%s)", err, out)
		}
	}
	return string(out), cmd.ProcessState.ExitCode()
}

// TestFuzzSoakPassHandsItsFindingsOverAndTidiesUp is the acceptance test for the
// pass's half of the hand-off: a pass that found something hands it over, restores
// the tree it borrowed, and says so in the report a scheduler's mail carries.
func TestFuzzSoakPassHandsItsFindingsOverAndTidiesUp(t *testing.T) {
	sb := newSandbox(t)
	bin := sb.stubCalves(t)
	dropped := sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")

	out, code := sb.pass(t, bin)
	if code != 0 {
		t.Fatalf("the pass exited %d, want a clean pass:\n%s", code, out)
	}

	// The haul, and then the tree it came from: the corpus is on the branch, and
	// the checkout stops showing it.
	if !strings.Contains(out, "fuzz-soak: haul — pushed "+haulBranch) {
		t.Errorf("the pass did not report the hand-off:\n%s", out)
	}
	if !strings.Contains(out, "restored to HEAD here") {
		t.Errorf("the pass did not say it had restored the tree:\n%s", out)
	}
	// The pass is where the two corpus stores drift apart — a haul takes the corpus
	// out of the tree, and the merge puts it into a commit — so it has to ask the
	// harvester for the reclaim as well as the save.
	argv, err := os.ReadFile(filepath.Join(sb.repo, ".fuzz-corpus.argv"))
	if err != nil {
		t.Fatalf("the pass never ran the harvester: %v", err)
	}
	if !strings.Contains(string(argv), "--save") || !strings.Contains(string(argv), "--reclaim") {
		t.Errorf("the pass asked the harvester for %q, want both --save and --reclaim", strings.TrimSpace(string(argv)))
	}
	// The pass's change was a deletion, so the branch carries the deletion: the
	// commit names the path and the tree does not have the file.
	if files := gitIn(t, sb.repo, "--git-dir="+sb.bare, "show", "--pretty=format:", "--name-only", haulBranch); !strings.Contains(files, dropped) {
		t.Errorf("the haul does not carry the entry the pass dropped (%s):\n%s", dropped, files)
	}
	if sb.branchHas(t, haulBranch, dropped) {
		t.Errorf("the branch still holds %s, which the haul recorded as dropped", dropped)
	}
	status := gitIn(t, sb.repo, "status", "--porcelain")
	if strings.Contains(status, "testdata/fuzz") {
		t.Errorf("the pass left the corpus it handed over in the working tree; status is:\n%s", status)
	}
	if !strings.Contains(status, "ROADMAP.md") {
		t.Errorf("the restore touched an unrelated edit; status is:\n%s", status)
	}

	// The report is the artifact a scheduler mails, so what it says about the pass
	// is the point of the pass. It is printed and written, and the two must agree.
	report, err := os.ReadFile(filepath.Join(sb.soakDir(), "last-report.md"))
	if err != nil {
		t.Fatalf("reading the report: %v", err)
	}
	for _, want := range []string{
		"## Haul",
		"- branch: `" + haulBranch + "`",
		"restored to HEAD here",
		"## Per target",
		"| FuzzFabricRPC2Frame |",
		"- coverage: not measured — other: go test failed",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("the report does not contain %q:\n%s", want, report)
		}
	}
	if strings.Contains(string(report), "n/a covered block(s)") {
		t.Errorf("the report counts a measurement it does not have:\n%s", report)
	}
	if !strings.Contains(out, string(report)) {
		t.Errorf("the report the pass printed is not the report it wrote:\n%s", out)
	}

	// One row per pass, and the reason it could not measure coverage in the last
	// column — a row whose columns have drifted would be read out of place by the
	// trend reader for the whole cohort.
	ledger, err := os.ReadFile(filepath.Join(sb.soakDir(), "log.tsv"))
	if err != nil {
		t.Fatalf("reading the ledger: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(ledger), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a header and one pass row, got %d line(s):\n%s", len(lines), ledger)
	}
	cols := strings.Split(lines[1], "\t")
	if len(cols) != 12 {
		t.Fatalf("the row has %d column(s), want 12:\n%s", len(cols), lines[1])
	}
	if cols[3] != "GREEN" || cols[8] != "n/a" || !strings.HasPrefix(cols[11], "other: go test failed") {
		t.Errorf("the row does not record the pass as it happened: %q", cols)
	}
}
