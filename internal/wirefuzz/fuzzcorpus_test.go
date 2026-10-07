package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/fuzz-corpus.sh owns both stores a fuzzer has: the repo's testdata/fuzz,
// which travels with the clone and survives a cache wipe, and Go's copy under
// $GOCACHE/fuzz, which compounds on one machine and dies with the build cache.
// A save copies the cache into the repo; --reclaim closes the other half by
// dropping the cached copies of entries a commit already carries.
//
// What it must never drop is an entry no commit carries, because that is the
// window the cache exists for — and the state the soak leaves behind is exactly
// that: a haul restores the tree, so an entry that has been proposed and not yet
// merged lives in the cache and nowhere else. So the test drives the real script
// against a cache of its own, holding one of each kind, and asks which survived.
//
// The cache is a temporary $GOCACHE, so this never touches the one the box uses
// for real fuzzing.

// runFuzzCorpus runs the harvester in a sandbox with a cache of its own.
func runFuzzCorpus(t *testing.T, repo, cache string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"scripts/fuzz-corpus.sh"}, args...)...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOCACHE="+cache)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running fuzz-corpus.sh %s: %v (%s)", strings.Join(args, " "), err, out)
		}
	}
	return string(out), cmd.ProcessState.ExitCode()
}

// moduleOf reads the module path out of a go.mod, which is the first component of
// the fuzz cache's layout.
func moduleOf(t *testing.T, repo string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}

// firstTrackedEntry is one corpus entry of a target as the commit has it.
func firstTrackedEntry(t *testing.T, repo, target string) string {
	t.Helper()
	dir := "internal/wirefuzz/testdata/fuzz/" + target
	listed := gitIn(t, repo, "ls-tree", "-r", "--name-only", "HEAD", "--", dir)
	if strings.TrimSpace(listed) == "" {
		t.Fatalf("%s carries no corpus entry in HEAD", dir)
	}
	return filepath.Base(strings.Split(listed, "\n")[0])
}

func TestFuzzCorpusReclaimsWhatACommitAlreadyCarries(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the harvester is a bash script")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH; the script asks it where the cache is")
	}

	sb := newSandbox(t)
	// The harvester under test is the one in the working tree, which is what a
	// developer runs.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	script, err := os.ReadFile(filepath.Join(root, "scripts", "fuzz-corpus.sh"))
	if err != nil {
		t.Fatalf("reading the harvester: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-corpus.sh"), script, 0o755); err != nil {
		t.Fatalf("writing the harvester into the sandbox: %v", err)
	}

	const target = "FuzzFrameParse"
	dir := filepath.Join(sb.repo, "internal", "wirefuzz", "testdata", "fuzz", target)

	// A commit carries this one, and the fuzzer found it too: a second copy.
	merged := firstTrackedEntry(t, sb.repo, target)
	// The fuzzer found this one, a pass proposed it, and nobody has merged it —
	// the same bytes in the tree and the cache, and only the cache once the soak
	// restores the tree. Only a commit makes the repo the durable copy.
	proposed := "00000000feedface"
	if err := os.WriteFile(filepath.Join(dir, proposed), []byte("go test fuzz v1\n[]byte(\"proposed\")\n"), 0o644); err != nil {
		t.Fatalf("writing the proposed entry: %v", err)
	}
	// And this one the repo has never seen at all.
	unseen := "000000000badcafe"

	cache := filepath.Join(t.TempDir(), "gocache")
	cdir := filepath.Join(cache, "fuzz", moduleOf(t, sb.repo), "internal", "wirefuzz", target)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatalf("making the cache: %v", err)
	}
	for _, name := range []string{merged, proposed, unseen} {
		if err := os.WriteFile(filepath.Join(cdir, name), []byte("go test fuzz v1\n[]byte(\"cached\")\n"), 0o644); err != nil {
			t.Fatalf("seeding the cache with %s: %v", name, err)
		}
	}

	// What the tree looked like before, so "it changed nothing" is exact: the
	// proposed entry above is untracked on purpose, and stays untracked either way.
	tree := gitIn(t, sb.repo, "status", "--porcelain")

	out, code := runFuzzCorpus(t, sb.repo, cache, "--reclaim")
	if code != 0 {
		t.Fatalf("--reclaim exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "reclaimed 1 cached cop") {
		t.Errorf("--reclaim did not reclaim exactly the merged entry:\n%s", out)
	}

	if _, err := os.Stat(filepath.Join(cdir, merged)); !os.IsNotExist(err) {
		t.Errorf("the cached copy of %s survived, though a commit carries it (stat: %v)", merged, err)
	}
	for _, name := range []string{proposed, unseen} {
		if _, err := os.Stat(filepath.Join(cdir, name)); err != nil {
			t.Errorf("the cached copy of %s was dropped, and no commit carries it: %v", name, err)
		}
	}
	// The repository's copies are not the reclaim's to touch: it drops the cache's.
	if _, err := os.Stat(filepath.Join(dir, merged)); err != nil {
		t.Errorf("the repo's copy of %s is gone: %v", merged, err)
	}
	if after := gitIn(t, sb.repo, "status", "--porcelain"); after != tree {
		t.Errorf("--reclaim changed the working tree:\nbefore:\n%s\nafter:\n%s", tree, after)
	}

	// Nothing left to reclaim: the second run says so and touches nothing.
	out, code = runFuzzCorpus(t, sb.repo, cache, "--reclaim")
	if code != 0 {
		t.Fatalf("the second --reclaim exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "reclaimed 0 cached cop") {
		t.Errorf("a second --reclaim still found something to drop:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(cdir, proposed)); err != nil {
		t.Errorf("the proposed entry was dropped by a second run: %v", err)
	}

	// --status counts the same thing, so an operator can see it coming.
	if err := os.WriteFile(filepath.Join(cdir, merged), []byte("go test fuzz v1\n[]byte(\"cached\")\n"), 0o644); err != nil {
		t.Fatalf("re-seeding the cache: %v", err)
	}
	out, code = runFuzzCorpus(t, sb.repo, cache, "--status")
	if code != 0 {
		t.Fatalf("--status exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "1 cached entr(ies) a commit already carries") {
		t.Errorf("--status did not count what --reclaim would drop:\n%s", out)
	}
	// ...and --status is read-only, whatever it counted.
	if _, err := os.Stat(filepath.Join(cdir, merged)); err != nil {
		t.Errorf("--status dropped a cached entry: %v", err)
	}
}
