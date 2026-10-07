package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A pass used to end by dropping its findings in the working tree and leaving
// them there for somebody to notice. scripts/fuzz-soak.sh --propose is the other
// half of that: the corpus directories, and nothing else, on a branch, pushed.
//
// These run it against a real clone with a real (local, bare) remote rather than
// a mock, because what can go wrong here is git-shaped: the wrong paths staged,
// the user's branch switched, a haul that turns out to be a move, a second PR for
// entries already proposed. The remote is a bare repo in a temp directory, so no
// network, no credentials, and no pull request is opened — the GitHub leg
// degrades to a pushed branch by design.

// sandbox is a clone of this repository wired to a bare "origin" of its own.
type sandbox struct {
	repo string // the working clone
	bare string // its remote
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	dir := t.TempDir()
	sb := sandbox{
		repo: filepath.Join(dir, "repo"),
		bare: filepath.Join(dir, "origin.git"),
	}

	gitIn(t, dir, "init", "--bare", "-q", sb.bare)
	gitIn(t, dir, "clone", "-q", filepath.ToSlash(root), sb.repo)
	gitIn(t, sb.repo, "remote", "set-url", "origin", sb.bare)
	gitIn(t, sb.repo, "push", "-q", "origin", "main")

	// The soak under test is the one in the working tree, which is what a
	// developer has. Copying it in also leaves a second, non-corpus edit in the
	// clone — a stand-in for whatever else a real tree holds, which the haul
	// must never sweep up.
	script, err := os.ReadFile(filepath.Join(root, "scripts", "fuzz-soak.sh"))
	if err != nil {
		t.Fatalf("reading the soak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-soak.sh"), script, 0o644); err != nil {
		t.Fatalf("writing the soak into the sandbox: %v", err)
	}
	return sb
}

// propose runs --propose in the sandbox and returns its combined output.
// --propose is read-only, so a non-zero exit is the caller's to assert on.
func (sb sandbox) propose(t *testing.T) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "scripts/fuzz-soak.sh", "--propose")
	cmd.Dir = sb.repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running --propose: %v (%s)", err, out)
		}
	}
	return string(out), cmd.ProcessState.ExitCode()
}

// dropCorpusEntry deletes one tracked corpus entry, which is a real haul: a
// minimization that dropped a seed looks exactly like this.
func (sb sandbox) dropCorpusEntry(t *testing.T, target string) string {
	t.Helper()
	dir := filepath.Join(sb.repo, "internal", "wirefuzz", "testdata", "fuzz", target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s holds no corpus entries to drop", dir)
	}
	victim := filepath.Join(dir, entries[0].Name())
	if err := os.Remove(victim); err != nil {
		t.Fatalf("removing %s: %v", victim, err)
	}
	return victim
}

func (sb sandbox) remoteBranches(t *testing.T) []string {
	t.Helper()
	out := gitIn(t, sb.repo, "--git-dir="+sb.bare, "for-each-ref",
		"--format=%(refname:short)", "refs/heads")
	var branches []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			branches = append(branches, line)
		}
	}
	return branches
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestFuzzSoakHaulHandsTheCorpusOver is the acceptance test: the corpus, and
// only the corpus, on a branch of its own — leaving the working tree exactly as
// it was found.
func TestFuzzSoakHaulHandsTheCorpusOver(t *testing.T) {
	sb := newSandbox(t)
	dropped := sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")

	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("--propose exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "fuzz-soak/") {
		t.Errorf("--propose did not name the branch it pushed:\n%s", out)
	}

	var pushed []string
	for _, b := range sb.remoteBranches(t) {
		if strings.HasPrefix(b, "fuzz-soak/") {
			pushed = append(pushed, b)
		}
	}
	if len(pushed) != 1 {
		t.Fatalf("want exactly one hauled branch on the remote, got %v", sb.remoteBranches(t))
	}
	branch := pushed[0]

	// The commit must carry the corpus and nothing else — not the README, not the
	// test harness, not whatever else the tree happened to be holding.
	files := gitIn(t, sb.repo, "--git-dir="+sb.bare, "show", "--pretty=format:", "--name-only", branch)
	listed := 0
	for _, f := range strings.Split(files, "\n") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		listed++
		if !strings.Contains(f, "testdata/fuzz") {
			t.Errorf("the haul swept up %s, which is not corpus", f)
		}
	}
	if listed == 0 {
		t.Errorf("the haul branch %s carries no commit", branch)
	}
	if !strings.Contains(files, filepath.ToSlash(strings.TrimPrefix(dropped, sb.repo+string(filepath.Separator)))) &&
		!strings.Contains(files, "testdata/fuzz/FuzzFabricRPC2Frame") {
		t.Errorf("the haul does not mention the entry that was dropped:\n%s", files)
	}

	// Its parent is the branch the user was on, so the diff is the corpus alone.
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", "main.."+branch); got != "1" {
		t.Errorf("the haul is %s commits on top of main, want 1", got)
	}

	// A haul is a copy, not a move: the tree keeps its findings, and the checkout
	// stays where it was.
	if got := gitIn(t, sb.repo, "rev-parse", "--abbrev-ref", "HEAD"); got != "main" {
		t.Errorf("the haul left the checkout on %s, want main", got)
	}
	status := gitIn(t, sb.repo, "status", "--porcelain")
	if !strings.Contains(status, "testdata/fuzz") {
		t.Errorf("the haul moved the corpus out of the working tree; status is:\n%s", status)
	}
	if !strings.Contains(status, "scripts/fuzz-soak.sh") {
		t.Errorf("the haul disturbed an unrelated edit; status is:\n%s", status)
	}
	// ...and it does not leave a branch behind in the tree it borrowed.
	if local := gitIn(t, sb.repo, "branch", "--format=%(refname:short)"); local != "main" {
		t.Errorf("the haul left local branches behind: %s", local)
	}
	if wt := gitIn(t, sb.repo, "worktree", "list"); strings.Count(wt, "\n") > 0 {
		t.Errorf("the haul left a worktree behind:\n%s", wt)
	}
}

// TestFuzzSoakHaulProposesADistinctHaulOnce holds the rail that makes an
// unattended pull request worth reading: an unmerged haul is not re-proposed
// every night, and a genuinely different haul still is.
func TestFuzzSoakHaulProposesADistinctHaulOnce(t *testing.T) {
	sb := newSandbox(t)
	sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")

	if out, code := sb.propose(t); code != 0 || !strings.Contains(out, "fuzz-soak/") {
		t.Fatalf("the first haul did not propose (exit %d):\n%s", code, out)
	}
	first := len(sb.remoteBranches(t))

	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("re-proposing exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "already proposed") {
		t.Errorf("the same haul was proposed twice, want it to say it is already proposed:\n%s", out)
	}
	if got := len(sb.remoteBranches(t)); got != first {
		t.Errorf("the same haul pushed another branch (%d -> %d)", first, got)
	}

	// A different haul is a different haul, and must still get through.
	sb.dropCorpusEntry(t, "FuzzFrameParse")
	out, code = sb.propose(t)
	if code != 0 || !strings.Contains(out, "fuzz-soak/") {
		t.Errorf("a changed haul was not proposed (exit %d):\n%s", code, out)
	}
	if got := len(sb.remoteBranches(t)); got != first+1 {
		t.Errorf("a changed haul did not push a branch (%d -> %d)", first, got)
	}
}

// TestFuzzSoakHaulDeclinesWithNothingToHandOver keeps a quiet night quiet.
func TestFuzzSoakHaulDeclinesWithNothingToHandOver(t *testing.T) {
	sb := newSandbox(t)

	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("--propose exited %d with nothing to propose:\n%s", code, out)
	}
	if !strings.Contains(out, "nothing to propose") {
		t.Errorf("--propose did not say there was nothing to propose:\n%s", out)
	}
	for _, b := range sb.remoteBranches(t) {
		if strings.HasPrefix(b, "fuzz-soak/") {
			t.Errorf("a quiet tree still pushed %s", b)
		}
	}
}
