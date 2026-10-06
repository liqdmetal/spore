package wirefuzz

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
