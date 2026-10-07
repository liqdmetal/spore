package wirefuzz

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// scripts/fuzz-smoke.sh runs these targets — the CI fuzz matrix and the
// ClusterFuzzLite pipelines were deleted with the repository's workflows, so it
// is the only runner now. scripts/fuzz-corpus.sh preserves what they discover,
// by harvesting Go's fuzz cache into testdata/fuzz/<Target>/.
//
// Both scripts keep a hand-written TARGETS list, and both must match the Fuzz
// functions the two packages actually declare. This keeps every one of the four
// ways they can drift — a target added, renamed, or removed in the code, or an
// entry left pointing at a target that no longer exists — failing here at unit
// speed, rather than silently shrinking what the pre-push gate fuzzes or what
// the corpus harvests.
func TestFuzzSmokeListsEveryTarget(t *testing.T) {
	inCode := declaredTargets(t)

	scripts := []string{
		"../../scripts/fuzz-smoke.sh",
		"../../scripts/fuzz-corpus.sh",
	}
	for _, script := range scripts {
		listed := targetsListedIn(t, script)

		var problems []string
		for target, pkg := range inCode {
			listedPkg, ok := listed[target]
			if !ok {
				problems = append(problems, target+" ("+pkg+") has no entry in "+script)
				continue
			}
			if listedPkg != pkg {
				problems = append(problems, target+" is listed as "+listedPkg+" but declared in "+pkg)
			}
		}
		for target, pkg := range listed {
			if _, ok := inCode[target]; !ok {
				problems = append(problems, target+" is listed in "+script+" as "+pkg+" but no such target exists")
			}
		}

		if len(problems) > 0 {
			sort.Strings(problems)
			for _, p := range problems {
				t.Errorf("fuzz target list out of sync: %s", p)
			}
			t.Fatalf("%d target(s) drifted in %s", len(problems), script)
		}
	}
}

// declaredTargets finds the Fuzz functions the two packages declare, mapped to
// the package path the scripts use for them.
func declaredTargets(t *testing.T) map[string]string {
	t.Helper()
	funcRe := regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]+)\(f \*testing\.F\)`)

	out := map[string]string{}
	for _, dir := range []string{".", "../ratchetwire"} {
		abs, err := filepath.Abs(dir)
		if err != nil {
			t.Fatalf("abs %s: %v", dir, err)
		}
		pkg := "./internal/" + filepath.Base(abs)
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			for _, m := range funcRe.FindAllStringSubmatch(string(b), -1) {
				out[m[1]] = pkg
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("found no Fuzz functions — did the harness layout change?")
	}
	return out
}

// targetsListedIn parses a script's TARGETS entries, which are written as
// "./internal/<pkg>:<Target>".
func targetsListedIn(t *testing.T, script string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("%s unreadable: %v", script, err)
	}
	entryRe := regexp.MustCompile(`(\./internal/[a-z]+):(Fuzz[A-Za-z0-9_]+)`)
	out := map[string]string{}
	for _, m := range entryRe.FindAllStringSubmatch(string(raw), -1) {
		out[m[2]] = m[1]
	}
	if len(out) == 0 {
		t.Fatalf("parsed no targets out of %s — did the TARGETS list change format?", script)
	}
	return out
}

// TestFuzzSoakDelegatesToTheSharedTargets guards the soak against growing a
// third, private target list. scripts/fuzz-soak.sh drives the runner and the
// harvester rather than calling `go test -fuzz` itself, and that is what keeps
// one list authoritative; a list typed into it would be invisible to every
// other check here.
func TestFuzzSoakDelegatesToTheSharedTargets(t *testing.T) {
	const script = "../../scripts/fuzz-soak.sh"
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("%s unreadable: %v (the scheduled soak drives the runner and the harvester)", script, err)
	}
	body := string(raw)
	for _, want := range []string{"scripts/fuzz-smoke.sh", "scripts/fuzz-corpus.sh"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s no longer calls %s — the soak must drive the shared scripts, not fuzz on its own", script, want)
		}
	}
	if m := regexp.MustCompile(`\./internal/[a-z]+:Fuzz[A-Za-z0-9_]+`).FindString(body); m != "" {
		t.Errorf("%s carries its own target list (%q); the list belongs to fuzz-smoke.sh and fuzz-corpus.sh alone", script, m)
	}
}

// TestFuzzCorpusEntriesAreContentAddressed guards the property the corpus store
// is built on: Go names a saved entry after the sha256 of its bytes, which is
// what makes a save additive and exact, and what lets scripts/fuzz-corpus.sh
// tell "already saved" from "new" by name alone.
//
// It is also the one check that would catch the way this corpus could die
// silently: a line-ending rewrite. The entries are ASCII text, so a checkout
// that rewrote LF to CRLF would keep every file present and every test passing
// on the machine that made the mess, while breaking the hash — and Go's parser —
// everywhere else. A name that no longer prefixes the digest is that damage.
func TestFuzzCorpusEntriesAreContentAddressed(t *testing.T) {
	for _, dir := range []string{".", "../ratchetwire"} {
		fuzzDir := filepath.Join(dir, "testdata", "fuzz")
		targets, err := os.ReadDir(fuzzDir)
		if err != nil {
			t.Fatalf("read %s: %v", fuzzDir, err)
		}

		checked := 0
		for _, target := range targets {
			// Only the per-target corpus directories hold hash-named entries;
			// seedcorpus/ is a hand-named fixture and is not ours to police.
			if !target.IsDir() || !strings.HasPrefix(target.Name(), "Fuzz") {
				continue
			}
			entries, err := os.ReadDir(filepath.Join(fuzzDir, target.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", filepath.Join(fuzzDir, target.Name()), err)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(fuzzDir, target.Name(), entry.Name())
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read %s: %v", path, err)
				}
				sum := fmt.Sprintf("%x", sha256.Sum256(raw))
				name := entry.Name()
				if len(name) < 16 || !strings.HasPrefix(sum, name) {
					t.Errorf("%s is not named after its own contents: want a prefix of %s, name is %q — was the file rewritten?", path, sum[:16], name)
				}
				checked++
			}
		}
		if checked == 0 {
			t.Errorf("no corpus entries under %s — did the store move?", fuzzDir)
		}
	}
}
