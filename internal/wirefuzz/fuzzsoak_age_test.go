package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFuzzSoakPendingAgesAcrossPasses(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}
	sb := newSandbox(t)
	bin := filepath.Join(filepath.Dir(sb.repo), "bin")
	cache := filepath.Join(filepath.Dir(sb.repo), "gocache")
	cacheTarget := filepath.Join(cache, "fuzz", "github.com", "liqdmetal", "spore", "internal", "wirefuzz", "FuzzFrameParse")
	if err := os.MkdirAll(cacheTarget, 0o755); err != nil {
		t.Fatalf("creating Go fuzz cache: %v", err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("creating command shims: %v", err)
	}

	fresh, historyless := "2222222222222222", "1111111111111111"
	freshPath := "internal/wirefuzz/testdata/fuzz/FuzzFrameParse/" + fresh
	historylessPath := "internal/wirefuzz/testdata/fuzz/FuzzFrameParse/" + historyless
	if err := os.WriteFile(filepath.Join(cacheTarget, historyless), []byte("old cached seed\n"), 0o644); err != nil {
		t.Fatalf("writing history-less cache entry: %v", err)
	}

	goShim := "#!/bin/sh\nif [ \"$1 $2\" = 'env GOCACHE' ]; then printf '%s\\n' \"$TEST_GOCACHE\"; else echo 'stub go: refusing' >&2; exit 1; fi\n"
	fuzzShim := "#!/bin/sh\nset -eu\nseed=\"$TEST_GOCACHE/fuzz/github.com/liqdmetal/spore/internal/wirefuzz/FuzzFrameParse/" + fresh + "\"\nif [ ! -f \"$seed\" ]; then printf 'new fuzz seed\\n' > \"$seed\"; fi\n"
	harvestShim := "#!/bin/sh\nset -eu\nsrc=\"$TEST_GOCACHE/fuzz/github.com/liqdmetal/spore/internal/wirefuzz/FuzzFrameParse\"\ndest=internal/wirefuzz/testdata/fuzz/FuzzFrameParse\nmkdir -p \"$dest\"\nfor seed in \"$src\"/*; do [ -f \"$seed\" ] && cp \"$seed\" \"$dest/\"; done\n"
	dateShim := "#!/bin/sh\ncase \"$*\" in '-u +%Y-%m-%dT%H:%M:%SZ') echo 2026-10-07T00:00:00Z ;; '+%s') echo \"$TEST_NOW\" ;; *) exit 2 ;; esac\n"
	for name, body := range map[string]string{
		"go":   goShim,
		"date": dateShim,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatalf("writing %s shim: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-smoke.sh"), []byte(fuzzShim), 0o755); err != nil {
		t.Fatalf("stubbing fuzz runner: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sb.repo, "scripts", "fuzz-corpus.sh"), []byte(harvestShim), 0o755); err != nil {
		t.Fatalf("stubbing harvester: %v", err)
	}
	runPass := func(now string) string {
		t.Helper()
		cmd := exec.Command("bash", "scripts/fuzz-soak.sh", "--time", "1")
		cmd.Dir = sb.repo
		cmd.Env = append(os.Environ(),
			"FUZZ_SOAK_DIR="+filepath.Join(filepath.Dir(sb.repo), "age-soak"),
			"TEST_GOCACHE="+filepath.ToSlash(cache),
			"TEST_NOW="+now,
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("running sandbox soak: %v\n%s", err, out)
		}
		return string(out)
	}
	readArtifacts := func() (string, string) {
		t.Helper()
		state := filepath.Join(filepath.Dir(sb.repo), "age-soak")
		manifest, err := os.ReadFile(filepath.Join(state, "pending-first-seen.tsv"))
		if err != nil {
			t.Fatalf("reading first-seen manifest: %v", err)
		}
		report, err := os.ReadFile(filepath.Join(state, "last-report.md"))
		if err != nil {
			t.Fatalf("reading pass report: %v", err)
		}
		return string(manifest), string(report)
	}

	firstOutput := runPass("1000")
	manifest, report := readArtifacts()
	wantFirst := historylessPath + "\t?\n" + freshPath + "\t1000\n"
	if manifest != wantFirst {
		t.Fatalf("first-pass manifest = %q, want %q", manifest, wantFirst)
	}
	for _, want := range []string{
		"- unmerged entries: 2",
		"- oldest known age: 0s (" + freshPath + ")",
		"- age unknown: 1",
	} {
		if !strings.Contains(report, want) || !strings.Contains(firstOutput, want) {
			t.Errorf("first pass is missing %q from report/output:\n%s", want, firstOutput)
		}
	}

	retainedOutput := runPass("1065")
	manifest, report = readArtifacts()
	if manifest != wantFirst || !strings.Contains(report, "- oldest known age: 1m5s ("+freshPath+")") {
		t.Fatalf("second-pass age was not retained:\nmanifest: %s\nreport: %s", manifest, report)
	}
	if !strings.Contains(retainedOutput, "- unmerged entries: 2") || !strings.Contains(retainedOutput, "- age unknown: 1") {
		t.Fatalf("second pass reported an unexpected pending set:\n%s", retainedOutput)
	}

	gitIn(t, sb.repo, "add", filepath.ToSlash(freshPath))
	gitIn(t, sb.repo, "commit", "-q", "-m", "corpus: merge fresh finding")
	secondOutput := runPass("1100")
	manifest, report = readArtifacts()
	if manifest != historylessPath+"\t?\n" {
		t.Fatalf("post-merge manifest = %q, want only the history-less pending entry", manifest)
	}
	for _, want := range []string{
		"- unmerged entries: 1",
		"- oldest known age: none",
		"- age unknown: 1",
	} {
		if !strings.Contains(report, want) || !strings.Contains(secondOutput, want) {
			t.Errorf("post-merge pass is missing %q from report/output:\n%s", want, secondOutput)
		}
	}
}
