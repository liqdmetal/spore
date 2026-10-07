package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A pass used to end by dropping its findings in the working tree and leaving
// them there for somebody to notice. scripts/fuzz-soak.sh --propose is the other
// half of that: the corpus directories, and nothing else, pushed, with a pull
// request for review.
//
// It is one rolling branch rather than one per firing. Review gets a single
// request, and it is updated in place each time the corpus moves on — so a haul
// nobody has merged yet cannot pile up a second request behind it. That makes
// three things worth holding down: the branch name stays the same across hauls,
// each haul is *appended* to it (the branch is never rewritten — nothing anybody
// else put there may be lost, and this repository's protect-all-branches ruleset
// refuses a non-fast-forward push on every branch anyway), and the hand-off
// updates the request it already has instead of opening another.
//
// The pass-through tests run it against a real clone with a real (local, bare)
// remote rather than a mock, because what can go wrong here is git-shaped: the
// wrong paths staged, the user's branch switched, a haul that turns out to be a
// move, a second branch for entries already proposed, a rewrite where an append
// was wanted. The remote is a bare repo in a temp directory, so no network, no
// credentials, and no pull request is opened — the GitHub leg degrades to a
// pushed branch by design. The update-vs-open decision is pinned separately,
// offline, by TestFuzzSoakHaulRollsThePullRequest.

// The one branch every haul lands on. It is a contract, not an implementation
// detail: WIRE_SPEC.md names it, and review is expected to find the haul there.
const haulBranch = "fuzz-soak/corpus"

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
	// developer runs.
	script, err := os.ReadFile(filepath.Join(root, "scripts", "fuzz-soak.sh"))
	if err != nil {
		t.Fatalf("reading the soak: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-soak.sh"), script, 0o644); err != nil {
		t.Fatalf("writing the soak into the sandbox: %v", err)
	}

	// A second, non-corpus edit: the stand-in for whatever else a real tree is
	// holding, which a haul must never sweep up. It is made explicitly rather
	// than left over from the copy above, because once the soak is committed that
	// copy changes nothing — and a fixture that quietly stops existing is a test
	// that quietly stops testing.
	roadmap := filepath.Join(sb.repo, "ROADMAP.md")
	f, err := os.OpenFile(roadmap, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("opening %s: %v", roadmap, err)
	}
	if _, err := f.WriteString("\n<!-- an unrelated edit a haul must never sweep up -->\n"); err != nil {
		f.Close()
		t.Fatalf("appending to %s: %v", roadmap, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing %s: %v", roadmap, err)
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

// dropCorpusEntry deletes one tracked corpus entry and returns its repo-relative
// path (slash-separated, as git reports it). A minimization that dropped a seed
// looks exactly like this.
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
	rel, err := filepath.Rel(sb.repo, victim)
	if err != nil {
		t.Fatalf("rel %s: %v", victim, err)
	}
	return filepath.ToSlash(rel)
}

// pushForeignCommit puts a commit on the rolling branch from somewhere that is
// not the soak — the reviewer who edits the machine branch, or a second host's
// soak — and returns the commit it left there.
func (sb sandbox) pushForeignCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	other := filepath.Join(dir, "reviewer")
	gitIn(t, dir, "clone", "-q", sb.bare, other)
	gitIn(t, other, "config", "user.email", "reviewer@example.com")
	gitIn(t, other, "config", "user.name", "reviewer")
	gitIn(t, other, "fetch", "-q", "origin", "refs/heads/"+haulBranch)
	gitIn(t, other, "checkout", "-q", "-b", haulBranch, "FETCH_HEAD")
	if err := os.WriteFile(filepath.Join(other, "reviewer-note.txt"), []byte("keep me\n"), 0o644); err != nil {
		t.Fatalf("writing the reviewer's file: %v", err)
	}
	gitIn(t, other, "add", "reviewer-note.txt")
	gitIn(t, other, "commit", "-q", "-m", "review: a note about this haul")
	gitIn(t, other, "push", "-q", "origin", haulBranch)
	return gitIn(t, other, "rev-parse", "HEAD")
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

// haulBranches is the hauled branches on the remote — all of them, so a second
// one is a failure rather than something the test cannot see.
func (sb sandbox) haulBranches(t *testing.T) []string {
	t.Helper()
	var hauled []string
	for _, b := range sb.remoteBranches(t) {
		if strings.HasPrefix(b, "fuzz-soak/") {
			hauled = append(hauled, b)
		}
	}
	return hauled
}

// branchHas reports whether a commit's tree carries one path. git cat-file exits
// non-zero for a path that is not there, which is the answer.
func (sb sandbox) branchHas(t *testing.T, branch, path string) bool {
	t.Helper()
	cmd := exec.Command("git", "--git-dir="+sb.bare, "cat-file", "-e", branch+":"+path)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.Run() == nil
}

// isAncestor asks whether a commit contains another, which is what separates a
// fast-forward from a rewrite.
func (sb sandbox) isAncestor(t *testing.T, older, newer string) bool {
	t.Helper()
	cmd := exec.Command("git", "--git-dir="+sb.bare, "merge-base", "--is-ancestor", older, newer)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.Run() == nil
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

// soakFunc pulls one shell function out of the soak, so a test can call it
// without running the script it lives in.
func soakFunc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../scripts/fuzz-soak.sh")
	if err != nil {
		t.Fatalf("reading the soak: %v", err)
	}
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(name) + `\(\) \{.*?^\}$`)
	m := re.FindString(string(raw))
	if m == "" {
		t.Fatalf("could not find %s() in the soak", name)
	}
	return m
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestFuzzSoakHaulBodyIsNotExecuted guards a bug the first real firing shipped.
// The pull request body is an unquoted heredoc, so every backtick in it is a
// command substitution: unescaped, it ran `go test`, pasted that output over the
// prose, and left the base commit blank. The escape is a single backslash, which
// no diff makes visible, so this calls the real function and reads what it
// produces.
func TestFuzzSoakHaulBodyIsNotExecuted(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}

	dir := t.TempDir()
	state := filepath.Join(dir, "last.state")
	err := os.WriteFile(state, []byte("timestamp=2026-01-02T03:04:05Z\ncorpus=98\ncoverage=1212\n"), 0o644)
	if err != nil {
		t.Fatalf("writing state: %v", err)
	}

	probe := "STATE=" + shellQuote(filepath.ToSlash(state)) + "\n" +
		soakFunc(t, "state_get") + "\n" +
		soakFunc(t, "haul_fact") + "\n" +
		soakFunc(t, "haul_body") + "\n" +
		"haul_body abc1234 main\n"
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(probe), 0o644); err != nil {
		t.Fatalf("writing the probe: %v", err)
	}

	// Run it somewhere that is not a Go module: a substituted `go test` fails
	// there, and says so into the body, which is how the bug announced itself.
	cmd := exec.Command("bash", filepath.ToSlash(script))
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, out)
	}
	body := string(out)

	if !strings.Contains(body, "`abc1234` on `main`") {
		t.Errorf("the body does not quote the base it was handed:\n%s", body)
	}
	for _, want := range []string{"2026-01-02T03:04:05Z", "98 file(s)", "1212 covered block(s)"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body is missing %q:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"setup failed", "no test files", "[no test files]"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the body contains %q, so a backtick in it was executed:\n%s", unwanted, body)
		}
	}
}

// TestFuzzSoakHaulRollsThePullRequest holds the decision the rolling model turns
// on, offline. With an open request already on the branch, the hand-off has to
// update that request; only when there is none may it open one. curl is a shell
// function here, so what the API would have been asked is a file the test reads
// back — no network, no credential, and the payloads are inspected as sent.
func TestFuzzSoakHaulRollsThePullRequest(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}

	// The functions the hand-off is made of, and nothing else: the point is to
	// call the real one, not a paraphrase of it.
	functions := []string{
		"github_token", "github_slug", "json_string", "state_get", "haul_fact",
		"haul_title", "haul_body", "haul_api", "haul_api_body", "haul_api_status",
		"pr_url", "propose_pull_request",
	}

	// run calls propose_pull_request with the API answering `listing` to the
	// lookup, `postCode` to the first creation and `retryCode` to any second one,
	// and returns the probe's output and the calls curl was given.
	run := func(t *testing.T, listing, postCode, retryCode string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		log := filepath.Join(dir, "curl.log")

		var b strings.Builder
		b.WriteString("set -euo pipefail\n")
		b.WriteString("owner=liqdmetal\nrepo=spore\n")
		b.WriteString("GITHUB_TOKEN=fake-token\nexport GITHUB_TOKEN\n")
		b.WriteString("POST_CODE=" + postCode + "\n")
		b.WriteString("RETRY_CODE=" + retryCode + "\n")
		b.WriteString("POSTS=" + shellQuote(filepath.ToSlash(filepath.Join(dir, "posts"))) + "\n")
		b.WriteString("STATE=" + shellQuote(filepath.ToSlash(filepath.Join(dir, "no.state"))) + "\n")
		for _, name := range functions {
			b.WriteString(soakFunc(t, name) + "\n")
		}
		// A curl that records the call and answers the API shapes the hand-off
		// reads: the lookup listing, an update, and a creation, each with the
		// status the real API answers.
		b.WriteString("curl() {\n")
		b.WriteString("  printf '%s\\n---\\n' \"$*\" >> " + shellQuote(filepath.ToSlash(log)) + "\n")
		b.WriteString("  case \"$*\" in\n")
		b.WriteString("    *'-X PATCH'*)\n")
		b.WriteString("      printf '%s' '{\n  \"number\": 7,\n  \"html_url\": \"https://github.com/liqdmetal/spore/pull/7\"\n}'\n")
		b.WriteString("      printf '\\n%s' 200 ;;\n")
		b.WriteString("    *'-X POST'*)\n")
		b.WriteString("      n=$(($(cat \"$POSTS\" 2>/dev/null || echo 0) + 1)); printf '%s' \"$n\" > \"$POSTS\"\n")
		b.WriteString("      printf '%s' '{\n  \"number\": 8,\n  \"html_url\": \"https://github.com/liqdmetal/spore/pull/8\"\n}'\n")
		b.WriteString("      if [ \"$n\" -le 1 ]; then printf '\\n%s' \"$POST_CODE\"; else printf '\\n%s' \"$RETRY_CODE\"; fi ;;\n")
		b.WriteString("    *'state=open'*)\n")
		b.WriteString("      printf '%s' " + shellQuote(listing) + " ; printf '\\n%s' 200 ;;\n")
		b.WriteString("    *)\n")
		b.WriteString("      printf '%s' '{}' ; printf '\\n%s' 404 ;;\n")
		b.WriteString("  esac\n")
		b.WriteString("}\n")
		b.WriteString("propose_pull_request abc1234 main " + haulBranch + " https://github.com/liqdmetal/spore.git\n")
		b.WriteString("printf 'status=%s\\nnote=%s\\nurl=%s\\n' \"$HAUL_STATUS\" \"$HAUL_NOTE\" \"$HAUL_URL\"\n")

		script := filepath.Join(dir, "probe.sh")
		if err := os.WriteFile(script, []byte(b.String()), 0o644); err != nil {
			t.Fatalf("writing the probe: %v", err)
		}
		cmd := exec.Command("bash", filepath.ToSlash(script))
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running the probe: %v\n%s", err, out)
		}
		calls, err := os.ReadFile(log)
		if err != nil {
			t.Fatalf("reading the curl log: %v", err)
		}
		return string(out), string(calls)
	}

	// A pull request is already open on the rolling branch.
	t.Run("an open request is updated, not duplicated", func(t *testing.T) {
		listing := "[\n  {\n    \"number\": 7,\n    \"html_url\": \"https://github.com/liqdmetal/spore/pull/7\"\n  }\n]"
		out, calls := run(t, listing, "201", "201")

		for _, want := range []string{
			"status=proposed",
			"note=pushed " + haulBranch + " and updated pull request #7",
			"url=https://github.com/liqdmetal/spore/pull/7",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the hand-off did not report %q:\n%s", want, out)
			}
		}
		for _, want := range []string{
			"-X GET",
			"/repos/liqdmetal/spore/pulls?head=liqdmetal:" + haulBranch + "&state=open",
			"Authorization: Bearer fake-token",
			"-X PATCH",
			"/repos/liqdmetal/spore/pulls/7",
		} {
			if !strings.Contains(calls, want) {
				t.Errorf("curl was never given %q:\n%s", want, calls)
			}
		}
		// Creating beside it would be the pileup the rolling branch exists to
		// prevent; a head is not updatable, so an update must not send one.
		if strings.Contains(calls, "-X POST") {
			t.Errorf("the hand-off opened a second pull request:\n%s", calls)
		}
		if strings.Contains(calls, `"head":`) {
			t.Errorf("the update sent a head, which the API cannot change:\n%s", calls)
		}
		if !strings.Contains(calls, `"title":"test(fuzz): the soak corpus haul"`) {
			t.Errorf("the update did not carry the rolling title:\n%s", calls)
		}
	})

	// Nothing open for this branch — the first haul, or the last request merged.
	t.Run("no open request is opened once", func(t *testing.T) {
		out, calls := run(t, "[\n\n]", "201", "201")

		for _, want := range []string{
			"status=proposed",
			"note=pushed " + haulBranch + " and opened a pull request",
			"url=https://github.com/liqdmetal/spore/pull/8",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the hand-off did not report %q:\n%s", want, out)
			}
		}
		for _, want := range []string{
			"-X POST",
			"/repos/liqdmetal/spore/pulls",
			`"head":"` + haulBranch + `"`,
			`"base":"main"`,
			`"title":"test(fuzz): the soak corpus haul"`,
		} {
			if !strings.Contains(calls, want) {
				t.Errorf("curl was never given %q:\n%s", want, calls)
			}
		}
		if strings.Contains(calls, "-X PATCH") {
			t.Errorf("the hand-off updated a request that does not exist:\n%s", calls)
		}
	})

	// A lookup that answers something that is not a list leaves the code unable
	// to know whether a request exists, so it tries to open one rather than
	// silently dropping the haul.
	t.Run("an unusable lookup still tries to open one", func(t *testing.T) {
		out, calls := run(t, "{}", "201", "201")
		if !strings.Contains(out, "status=proposed") {
			t.Errorf("an unusable lookup failed the haul:\n%s", out)
		}
		if !strings.Contains(calls, "-X POST") {
			t.Errorf("an unusable lookup opened nothing:\n%s", calls)
		}
	})

	// A creation the API refuses once is retried once: a request for a branch that
	// was pushed seconds ago is refused while the API still sees the ref as it was.
	t.Run("a creation refused once is retried", func(t *testing.T) {
		out, calls := run(t, "[\n\n]", "400", "201")
		if !strings.Contains(out, "opened a pull request") {
			t.Errorf("a refused creation was not retried:\n%s", out)
		}
		if got := strings.Count(calls, "-X POST"); got != 2 {
			t.Errorf("want the creation attempted twice, got %d:\n%s", got, calls)
		}
	})

	// An API that refuses twice must not turn a pushed branch into a failed haul:
	// the compare URL is still a hand-off, and the pass goes on.
	t.Run("a refused creation still hands the branch over", func(t *testing.T) {
		out, _ := run(t, "[\n\n]", "422", "422")
		for _, want := range []string{
			"status=proposed",
			"answered 422",
			"url=https://github.com/liqdmetal/spore/compare/main..." + haulBranch + "?expand=1",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("a refused creation did not report %q:\n%s", want, out)
			}
		}
	})
}

// TestFuzzSoakHaulHandsTheCorpusOver is the acceptance test: the corpus, and
// only the corpus, on the rolling branch — leaving the working tree exactly as
// it was found.
func TestFuzzSoakHaulHandsTheCorpusOver(t *testing.T) {
	sb := newSandbox(t)
	dropped := sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")

	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("--propose exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, haulBranch) {
		t.Errorf("--propose did not name the branch it pushed:\n%s", out)
	}

	hauled := sb.haulBranches(t)
	if len(hauled) != 1 {
		t.Fatalf("want exactly one hauled branch (%s) on the remote, got %v", haulBranch, sb.remoteBranches(t))
	}
	if hauled[0] != haulBranch {
		t.Fatalf("the haul landed on %s, want the rolling branch %s", hauled[0], haulBranch)
	}

	// The commit must carry the corpus and nothing else — not the README, not the
	// test harness, not whatever else the tree happened to be holding.
	files := gitIn(t, sb.repo, "--git-dir="+sb.bare, "show", "--pretty=format:", "--name-only", haulBranch)
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
		t.Errorf("the haul branch %s carries no commit", haulBranch)
	}
	if !strings.Contains(files, dropped) {
		t.Errorf("the haul does not mention the entry that was dropped (%s):\n%s", dropped, files)
	}
	if !strings.Contains(gitIn(t, sb.repo, "--git-dir="+sb.bare, "log", "-1", "--format=%s", haulBranch),
		"test(fuzz): the soak corpus haul") {
		t.Errorf("the haul's commit is not titled as the rolling haul")
	}

	// Its parent is the branch the user was on, so the diff is the corpus alone.
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", "main.."+haulBranch); got != "1" {
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
	if !strings.Contains(status, "ROADMAP.md") {
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

// TestFuzzSoakHaulRollsOneBranchForward holds the rail that makes an unattended
// pull request worth reading: an unmerged haul is not handed over every night,
// and a genuinely different haul is — on the same branch, rewritten, so review
// keeps one request instead of a queue of them.
func TestFuzzSoakHaulRollsOneBranchForward(t *testing.T) {
	sb := newSandbox(t)
	firstDrop := sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")

	out, code := sb.propose(t)
	if code != 0 || !strings.Contains(out, haulBranch) {
		t.Fatalf("the first haul did not propose (exit %d):\n%s", code, out)
	}
	if got := sb.haulBranches(t); len(got) != 1 || got[0] != haulBranch {
		t.Fatalf("want exactly one hauled branch %s, got %v", haulBranch, sb.remoteBranches(t))
	}
	first := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch)
	if sb.branchHas(t, haulBranch, firstDrop) {
		t.Errorf("the haul still carries %s, which the tree no longer holds", firstDrop)
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", "main.."+haulBranch); got != "1" {
		t.Errorf("want one commit on a fresh rolling branch, got %s", got)
	}

	// The same entries are not handed over twice: a quiet night stays quiet.
	out, code = sb.propose(t)
	if code != 0 {
		t.Errorf("re-proposing exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "already proposed") {
		t.Errorf("the same entries were handed over twice, want it to say they are already proposed:\n%s", out)
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch); got != first {
		t.Errorf("an unchanged haul rewrote the branch (%s -> %s)", first, got)
	}

	// A changed haul appends to that branch rather than adding another, and rather
	// than rewriting it: one rolling request, and a history nobody can lose.
	secondDrop := sb.dropCorpusEntry(t, "FuzzFrameParse")
	out, code = sb.propose(t)
	if code != 0 || !strings.Contains(out, haulBranch) {
		t.Fatalf("a changed haul was not proposed (exit %d):\n%s", code, out)
	}
	if got := sb.haulBranches(t); len(got) != 1 || got[0] != haulBranch {
		t.Errorf("a changed haul did not reuse the rolling branch: %v", sb.remoteBranches(t))
	}
	second := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch)
	if second == first {
		t.Errorf("the branch still points at the first haul, so the change was not handed over")
	}
	if !sb.isAncestor(t, first, second) {
		t.Errorf("the haul was pushed over the branch (%s is not an ancestor of %s); appends only, never a rewrite", first, second)
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", "main.."+haulBranch); got != "2" {
		t.Errorf("want one commit per haul on the branch, got %s", got)
	}
	// ...and it carries the corpus as it stands now, not as it stood last night.
	if sb.branchHas(t, haulBranch, secondDrop) {
		t.Errorf("the branch still carries %s, which the tree no longer holds", secondDrop)
	}
}

// TestFuzzSoakHaulBuildsOnWhatIsThere holds the shape the rolling branch must
// never break. The branch is machine-owned, and appending is what makes that
// safe: a commit somebody else put there — a reviewer editing the machine branch,
// a second host's soak — stays exactly where it is, and the haul is added on top
// of it rather than over it.
func TestFuzzSoakHaulBuildsOnWhatIsThere(t *testing.T) {
	sb := newSandbox(t)
	sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")
	if out, code := sb.propose(t); code != 0 || !strings.Contains(out, haulBranch) {
		t.Fatalf("the first haul did not propose (exit %d):\n%s", code, out)
	}

	foreign := sb.pushForeignCommit(t)

	// A changed corpus, so the haul is not skipped as already proposed.
	secondDrop := sb.dropCorpusEntry(t, "FuzzFrameParse")
	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("the haul failed against a branch somebody else had moved (exit %d):\n%s", code, out)
	}
	tip := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch)
	if !sb.isAncestor(t, foreign, tip) {
		t.Errorf("the haul does not sit on top of what was there (%s -> %s)", foreign, tip)
	}
	if !sb.branchHas(t, haulBranch, "reviewer-note.txt") {
		t.Errorf("the reviewer's file is gone from the branch")
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", foreign+".."+haulBranch); got != "1" {
		t.Errorf("want the haul as one commit on top of what was there, got %s", got)
	}
	// ...and it still carries the corpus as it stands now.
	if sb.branchHas(t, haulBranch, secondDrop) {
		t.Errorf("the branch still carries %s, which the tree no longer holds", secondDrop)
	}
	if local := gitIn(t, sb.repo, "branch", "--format=%(refname:short)"); local != "main" {
		t.Errorf("the haul left local branches behind: %s", local)
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
	if got := sb.haulBranches(t); len(got) != 0 {
		t.Errorf("a quiet tree still pushed %v", got)
	}
}
