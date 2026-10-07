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

// soakDir is where the sandbox's --propose keeps its state. It is the sandbox's
// own, never the ambient one: a soak pass measures coverage by running this
// package's tests, so a test that inherited the pass's state directory would read
// state that is not its own — and find the pass's live lock there, which is a
// refusal, not a haul.
func (sb sandbox) soakDir() string {
	return filepath.Join(filepath.Dir(sb.repo), "haul-soak")
}

// propose runs --propose in the sandbox and returns its combined output.
// --propose is read-only, so a non-zero exit is the caller's to assert on.
func (sb sandbox) propose(t *testing.T) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "scripts/fuzz-soak.sh", "--propose")
	cmd.Dir = sb.repo
	cmd.Env = append(os.Environ(), "FUZZ_SOAK_DIR="+sb.soakDir())
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
		soakFunc(t, "coverage_phrase") + "\n" +
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

// TestFuzzSoakHaulBodyCarriesTheReasonCoverageIsMissing keeps the pull request
// honest about a pass that measured nothing: the body is the one place a reviewer
// reads the haul without the report, so "n/a covered block(s)" there — or worse,
// a reproducer named for what was really a failing test — would be the same lie in
// a new place.
func TestFuzzSoakHaulBodyCarriesTheReasonCoverageIsMissing(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}

	dir := t.TempDir()
	state := filepath.Join(dir, "last.state")
	note := "test-failure: TestFuzzSoakHaulHandsTheCorpusOver fails, which is not a corpus entry"
	err := os.WriteFile(state, []byte("timestamp=2026-01-02T03:04:05Z\ncorpus=98\ncoverage=n/a\ncoverage_note="+note+"\n"), 0o644)
	if err != nil {
		t.Fatalf("writing state: %v", err)
	}

	probe := "STATE=" + shellQuote(filepath.ToSlash(state)) + "\n" +
		soakFunc(t, "state_get") + "\n" +
		soakFunc(t, "coverage_phrase") + "\n" +
		soakFunc(t, "haul_fact") + "\n" +
		soakFunc(t, "haul_body") + "\n" +
		"haul_body abc1234 main\n"
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(probe), 0o644); err != nil {
		t.Fatalf("writing the probe: %v", err)
	}
	cmd := exec.Command("bash", filepath.ToSlash(script))
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, out)
	}
	body := string(out)

	if !strings.Contains(body, "not measured — "+note) {
		t.Errorf("the body does not say why coverage is missing:\n%s", body)
	}
	if strings.Contains(body, "n/a covered block(s)") {
		t.Errorf("the body still counts a measurement it does not have:\n%s", body)
	}
	if strings.Contains(body, "reproducer") {
		t.Errorf("the body blames a reproducer for a failing test:\n%s", body)
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
// only the corpus, on the rolling branch — and then out of git status, because a
// finding that has a pull request does not need to keep sitting in the checkout.
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

	// The checkout stays where it was, but the corpus does not: once it is on the
	// branch the tree is restored to HEAD, so the pass stops leaving the checkout
	// dirtier every night. Nothing is lost by that — the commit checked above
	// carries exactly what the tree carried — and the restore is the corpus's own
	// pathspec, so nothing else the tree holds is touched.
	if got := gitIn(t, sb.repo, "rev-parse", "--abbrev-ref", "HEAD"); got != "main" {
		t.Errorf("the haul left the checkout on %s, want main", got)
	}
	status := gitIn(t, sb.repo, "status", "--porcelain")
	if strings.Contains(status, "testdata/fuzz") {
		t.Errorf("the hauled corpus is still sitting in the working tree; status is:\n%s", status)
	}
	if !strings.Contains(status, "ROADMAP.md") {
		t.Errorf("the restore touched an unrelated edit; status is:\n%s", status)
	}
	// An empty status for those paths is also the byte-for-byte proof: git reports
	// a difference for content, mode and deletion alike. The entry is back where
	// HEAD has it, which is why the restore cannot lose one.
	if _, err := os.Stat(filepath.Join(sb.repo, filepath.FromSlash(dropped))); err != nil {
		t.Errorf("the entry the haul carried away is not back (%s): %v", dropped, err)
	}
	// The branch and the restored tree disagree here on purpose — the haul recorded
	// that the pass minimized this seed away, and HEAD still has it — and that is
	// what the fingerprint rail is for: if the next pass minimizes the same seed
	// again, the tree is dirty in exactly the way it already proposed and the haul
	// is skipped rather than re-committed.
	if sb.branchHas(t, haulBranch, dropped) {
		t.Errorf("the branch still carries %s, which the haul recorded as minimized away", dropped)
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

	// The same entries are not handed over twice. The first haul restored the tree,
	// so a second --propose has nothing in front of it to hand over and leaves the
	// branch exactly where it is: a quiet night stays quiet either way, and the
	// rail is the branch tip, not the wording.
	out, code = sb.propose(t)
	if code != 0 {
		t.Errorf("re-proposing exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "nothing to propose") {
		t.Errorf("a restored tree was handed over again, want it to say there is nothing to propose:\n%s", out)
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

// TestFuzzSoakHaulDeclinesWhileAPassIsInFlight pins the interaction a pass walks
// into by measuring coverage: the measurement runs this package's tests, which run
// --propose, while the pass itself holds the lock. The corpus is still being
// minimized at that moment, so the haul that would be proposed is not the corpus
// that is about to exist.
func TestFuzzSoakHaulDeclinesWhileAPassIsInFlight(t *testing.T) {
	sb := newSandbox(t)
	sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")
	if err := os.MkdirAll(filepath.Join(sb.soakDir(), "lock"), 0o755); err != nil {
		t.Fatalf("taking the lock: %v", err)
	}

	out, code := sb.propose(t)
	if code != 2 {
		t.Errorf("--propose exited %d with a pass in flight, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, "holds") {
		t.Errorf("--propose did not explain that a pass is running:\n%s", out)
	}
	if got := sb.haulBranches(t); len(got) != 0 {
		t.Errorf("a pass in flight still handed the corpus over: %v", got)
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

// TestFuzzSoakHaulRestoresTheFindingItProposed is the case the restore exists
// for: the fuzzer writes a new entry under testdata/fuzz, the pass hauls it, and
// it stops sitting in git status — its home is the branch now. The order is the
// point, and this checks it the only way that matters: the branch is asked for the
// finding first, and only then is the tree allowed not to have it.
func TestFuzzSoakHaulRestoresTheFindingItProposed(t *testing.T) {
	sb := newSandbox(t)
	finding := "internal/wirefuzz/testdata/fuzz/FuzzFrameParse/00000000feedface"
	full := filepath.Join(sb.repo, filepath.FromSlash(finding))
	if err := os.WriteFile(full, []byte("go test fuzz v1\n[]byte(\"a finding\")\n"), 0o644); err != nil {
		t.Fatalf("writing the finding: %v", err)
	}
	if status := gitIn(t, sb.repo, "status", "--porcelain"); !strings.Contains(status, finding) {
		t.Fatalf("the fixture is not a new finding; status is:\n%s", status)
	}

	out, code := sb.propose(t)
	if code != 0 || !strings.Contains(out, haulBranch) {
		t.Fatalf("the haul did not propose (exit %d):\n%s", code, out)
	}
	if !sb.branchHas(t, haulBranch, finding) {
		t.Fatalf("the branch does not carry %s, so the restore below would have lost it", finding)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Errorf("the finding is still sitting in the working tree after it was handed over (stat: %v)", err)
	}
	if status := gitIn(t, sb.repo, "status", "--porcelain"); strings.Contains(status, "testdata/fuzz") {
		t.Errorf("the corpus is still in git status after the haul:\n%s", status)
	}
	if status := gitIn(t, sb.repo, "status", "--porcelain"); !strings.Contains(status, "ROADMAP.md") {
		t.Errorf("the restore touched an edit that was not corpus; status is:\n%s", status)
	}
	if !strings.Contains(out, "restored to HEAD") {
		t.Errorf("--propose did not say the tree had been tidied:\n%s", out)
	}
}

// TestFuzzSoakReportNamesEveryTargetThePassFound holds the report's per-target
// table to what the pass found rather than to what the tree happens to hold. That
// matters because a successful haul restores the corpus: asking the disk alone
// would drop a row for the pass that found it, and drop a whole new target — the
// interesting case — entirely. It is called on the real function.
func TestFuzzSoakReportNamesEveryTargetThePassFound(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; corpus_targets is a bash function")
	}

	dir := t.TempDir()
	for _, d := range []string{
		"internal/one/testdata/fuzz/FuzzOnDisk",
		"internal/two/testdata/fuzz/FuzzBoth",
	} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatalf("creating %s: %v", d, err)
		}
	}
	// The pass's snapshot: a target the tree still has, and one it no longer does
	// — restored away, or a directory the haul carried off whole.
	names := filepath.Join(dir, "corpus-names.txt")
	if err := os.WriteFile(names, []byte("FuzzBoth/a\nFuzzBoth/b\nFuzzGone/c\n"), 0o644); err != nil {
		t.Fatalf("writing the snapshot: %v", err)
	}

	probe := "NAMES=" + shellQuote(filepath.ToSlash(names)) + "\n" +
		soakFunc(t, "corpus_targets") + "\ncorpus_targets\n"
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(probe), 0o644); err != nil {
		t.Fatalf("writing the probe: %v", err)
	}
	cmd := exec.Command("bash", filepath.ToSlash(script))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, out)
	}

	const want = "FuzzBoth,FuzzGone,FuzzOnDisk"
	if got := strings.Join(strings.Fields(string(out)), ","); got != want {
		t.Errorf("the report would tabulate %s, want %s (the tree's targets and the pass's, with no repeats)", got, want)
	}
}

// TestFuzzSoakPassStartsFromWhatTheBoxKnew holds the pass's "before" snapshot to
// the durable corpus rather than to the checkout. A successful haul restores the
// tree, so the entries it handed over are absent from the tree and present only in
// the last pass's snapshot — and in the fuzz cache, which the pass's harvest copies
// back. Taking the union is what stops the next pass reporting those entries as
// found again, night after night, for as long as the request stayed open. It is
// called on the real function, over a real tree.
func TestFuzzSoakPassStartsFromWhatTheBoxKnew(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; corpus_known_before is a bash function")
	}

	dir := t.TempDir()
	entry := filepath.Join(dir, "internal", "one", "testdata", "fuzz", "FuzzA", "aaaa")
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatalf("creating the corpus: %v", err)
	}
	if err := os.WriteFile(entry, []byte("go test fuzz v1\n[]byte(\"x\")\n"), 0o644); err != nil {
		t.Fatalf("writing the entry: %v", err)
	}
	// The last pass's snapshot: one entry the tree kept, one the haul carried away,
	// and one repeated — the union must count it once.
	prev := filepath.Join(dir, "prev.txt")
	if err := os.WriteFile(prev, []byte("FuzzA/aaaa\nFuzzA/bbbb\nFuzzGone/cccc\n"), 0o644); err != nil {
		t.Fatalf("writing the snapshot: %v", err)
	}

	probe := soakFunc(t, "corpus_names") + "\n" + soakFunc(t, "corpus_known_before") + "\n" +
		"corpus_known_before " + shellQuote(filepath.ToSlash(prev)) + "\n"
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(probe), 0o644); err != nil {
		t.Fatalf("writing the probe: %v", err)
	}
	cmd := exec.Command("bash", filepath.ToSlash(script))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, out)
	}

	const want = "FuzzA/aaaa*FuzzA/bbbb*FuzzGone/cccc"
	if got := strings.Join(strings.Fields(string(out)), "*"); got != want {
		t.Errorf("the pass would start from %s, want %s (what the tree holds unioned with what the last pass left)", got, want)
	}
}

// TestFuzzSoakHaulDoesNotReCommitWhatItAlreadyMinimized pins the interaction the
// restore creates and the recorded fingerprint absorbs. A minimize-drop is
// proposed once; the restore then puts the seed back where HEAD has it, so the
// next pass minimizes the very same seed again and the tree is dirty in exactly
// the way it was last night. Without the fingerprint that would be a fresh commit
// every night, on a branch this repository's ruleset forbids rewriting.
func TestFuzzSoakHaulDoesNotReCommitWhatItAlreadyMinimized(t *testing.T) {
	sb := newSandbox(t)
	sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")
	if out, code := sb.propose(t); code != 0 || !strings.Contains(out, haulBranch) {
		t.Fatalf("the first haul did not propose (exit %d):\n%s", code, out)
	}
	tip := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch)

	// The restore brought that seed back, so minimizing it away looks new again —
	// and it is the same entry, because the directory is back to its HEAD listing.
	sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")
	out, code := sb.propose(t)
	if code != 0 {
		t.Errorf("re-proposing a minimized seed exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "already proposed") {
		t.Errorf("a seed this branch already recorded as minimized was proposed again:\n%s", out)
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-parse", haulBranch); got != tip {
		t.Errorf("the branch moved for a haul it already had (%s -> %s)", tip, got)
	}
	if got := gitIn(t, sb.repo, "--git-dir="+sb.bare, "rev-list", "--count", "main.."+haulBranch); got != "1" {
		t.Errorf("want one commit on the branch, got %s", got)
	}
}

// TestFuzzSoakHaulKeepsTheCorpusWhenTheHandOverFails is what makes the restore
// safe to have at all. The tree is only tidied once the branch really has the
// corpus, so a remote that cannot be pushed to must leave the findings exactly
// where they were: restoring there would be a soak deleting the only copy of what
// it had just found, and reporting that as a hand-off.
func TestFuzzSoakHaulKeepsTheCorpusWhenTheHandOverFails(t *testing.T) {
	sb := newSandbox(t)
	dropped := sb.dropCorpusEntry(t, "FuzzFabricRPC2Frame")
	finding := "internal/wirefuzz/testdata/fuzz/FuzzFrameParse/00000000deadbeef"
	full := filepath.Join(sb.repo, filepath.FromSlash(finding))
	if err := os.WriteFile(full, []byte("go test fuzz v1\n[]byte(\"a finding\")\n"), 0o644); err != nil {
		t.Fatalf("writing the finding: %v", err)
	}
	gitIn(t, sb.repo, "remote", "set-url", "origin", filepath.Join(filepath.Dir(sb.repo), "gone.git"))

	out, code := sb.propose(t)
	if code == 0 {
		t.Errorf("--propose exited 0 with nowhere to push:\n%s", out)
	}
	if !strings.Contains(out, "could not push") {
		t.Errorf("the failed hand-off was not explained:\n%s", out)
	}
	if _, err := os.Stat(full); err != nil {
		t.Errorf("a failed hand-off removed the finding it could not hand over: %v", err)
	}
	if status := gitIn(t, sb.repo, "status", "--porcelain"); !strings.Contains(status, dropped) {
		t.Errorf("a failed hand-off restored %s, so the minimization the pass recorded is gone:\n%s", dropped, status)
	}
	if got := sb.haulBranches(t); len(got) != 0 {
		t.Errorf("a failed hand-off still left %v on the remote", got)
	}
}
