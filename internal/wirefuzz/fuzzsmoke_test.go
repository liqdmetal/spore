package wirefuzz

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// scripts/fuzz-smoke.sh is now the only runner for these targets: the CI fuzz
// matrix and the ClusterFuzzLite pipelines were deleted with the repository's
// workflows, and its TARGETS array is a hand-kept list. This keeps the list and
// the code from drifting — a target added, renamed, or removed in either
// package (or an entry left pointing at a target that no longer exists) fails
// here, at unit speed, instead of silently shrinking what the pre-push gate
// fuzzes.
func TestFuzzSmokeListsEveryTarget(t *testing.T) {
	const script = "../../scripts/fuzz-smoke.sh"
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("%s unreadable: %v (the fuzz-smoke gate lists its targets there)", script, err)
	}

	// "./internal/wirefuzz:FuzzFrameParse" — package and target, as the script
	// writes them.
	entryRe := regexp.MustCompile(`(\./internal/[a-z]+):(Fuzz[A-Za-z0-9_]+)`)
	listed := map[string]string{} // target -> package
	for _, m := range entryRe.FindAllStringSubmatch(string(raw), -1) {
		listed[m[2]] = m[1]
	}
	if len(listed) == 0 {
		t.Fatalf("parsed no targets out of %s — did the TARGETS list change format?", script)
	}

	// The packages the gate is responsible for, and the Fuzz functions each
	// one declares.
	funcRe := regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]+)\(f \*testing\.F\)`)
	inCode := map[string]string{} // target -> package
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
				inCode[m[1]] = pkg
			}
		}
	}

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
			t.Errorf("fuzz-smoke target list out of sync: %s", p)
		}
		t.Fatalf("%d target(s) drifted between the code and %s", len(problems), script)
	}
}
