package wirefuzz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A pass that cannot measure coverage has to say why, because the two reasons
// mean opposite things: a reproducer sitting in the corpus is the corpus working
// as intended, and a failing test in the package is the measurement itself
// broken. With only "n/a" in the ledger cell the two are indistinguishable, and
// the trend reader resolved them the wrong way round — it blamed a corpus
// reproducer for what was really a test of the soak's own harness, which is
// exactly how one pass here ended up recorded with no coverage and a misleading
// explanation.
//
// The fixtures are the shapes go test really prints — copied out of runs of it
// rather than invented — and the soak's coverage_note is called on them for real,
// not paraphrased.

func TestFuzzSoakCoverageNoteNamesTheRealReason(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the classifier is a bash function")
	}

	tests := []struct {
		name    string
		log     string
		want    []string
		wantNot []string
	}{
		{
			name: "a corpus entry that fails on its own is a reproducer",
			log: "--- FAIL: FuzzThing (0.00s)\n" +
				"    --- FAIL: FuzzThing/0a1b2c3d4e5f6071 (0.00s)\n" +
				"        fuzz_test.go:9: boom\n" +
				"FAIL\ncoverage: [no statements]\nFAIL\tcovprobe\t0.198s\nFAIL\n",
			want:    []string{"reproducer:", "FuzzThing/0a1b2c3d4e5f6071 fails on its own"},
			wantNot: []string{"test-failure:"},
		},
		{
			name: "a seed that fails on its own is a reproducer too",
			log: "--- FAIL: FuzzThing (0.00s)\n" +
				"    --- FAIL: FuzzThing/seed#0 (0.00s)\n" +
				"        fuzz_test.go:9: boom\n" +
				"FAIL\nFAIL\tcovprobe\t0.170s\nFAIL\n",
			want:    []string{"reproducer:", "FuzzThing/seed#0 fails on its own"},
			wantNot: []string{"test-failure:"},
		},
		{
			name: "a failing test in the package is not a reproducer",
			log: "--- FAIL: TestBroken (0.00s)\n" +
				"    extra_test.go:5: nope\n" +
				"FAIL\ncoverage: [no statements]\nFAIL\tcovprobe\t0.701s\nFAIL\n",
			want:    []string{"test-failure:", "TestBroken fails", "which is not a corpus entry"},
			wantNot: []string{"reproducer:"},
		},
		{
			name: "both at once keeps the failing test as the reason",
			log: "--- FAIL: TestBroken (0.00s)\n" +
				"    extra_test.go:5: nope\n" +
				"--- FAIL: FuzzThing (0.00s)\n" +
				"    --- FAIL: FuzzThing/seed#0 (0.00s)\n" +
				"FAIL\nFAIL\tcovprobe\t0.7s\nFAIL\n",
			want:    []string{"test-failure:", "TestBroken fails", "the replay also failed on FuzzThing/seed#0"},
			wantNot: []string{"reproducer:"},
		},
		{
			name: "a package that did not build was never replayed",
			log: "# covprobe\n" +
				"cover: C:\\tmp\\broken.go:3:14: expected ')', found '{'\n" +
				"FAIL\tcovprobe [build failed]\nFAIL\n",
			want:    []string{"build-error:", "did not build"},
			wantNot: []string{"test-failure:", "reproducer:"},
		},
		{
			name: "a replay that did not finish is its own reason",
			log: "panic: test timed out after 10m0s\n" +
				"\trunning tests:\n\t\tTestSlow (10m0s)\n" +
				"FAIL\tcovprobe\t600.3s\n",
			want:    []string{"timeout:", "did not finish"},
			wantNot: []string{"test-failure:", "reproducer:"},
		},
		{
			name:    "a failure it cannot place is quoted rather than guessed at",
			log:     "no Go files in C:\\tmp\\whatever\n",
			want:    []string{"other:", "go test failed", "no Go files in"},
			wantNot: []string{"test-failure:", "reproducer:"},
		},
	}

	dir := t.TempDir()
	var probe strings.Builder
	probe.WriteString("set -u\n")
	for _, name := range []string{"coverage_names", "coverage_note"} {
		probe.WriteString(soakFunc(t, name) + "\n")
	}
	for i, tc := range tests {
		log := filepath.Join(dir, "case"+string(rune('0'+i))+".log")
		if err := os.WriteFile(log, []byte(tc.log), 0o644); err != nil {
			t.Fatalf("writing %s: %v", log, err)
		}
		probe.WriteString("printf 'case" + string(rune('0'+i)) + "\\t%s\\n' \"$(coverage_note " + shellQuote(filepath.ToSlash(log)) + ")\"\n")
	}
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte(probe.String()), 0o644); err != nil {
		t.Fatalf("writing the probe: %v", err)
	}
	out, err := exec.Command("bash", filepath.ToSlash(script)).CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, out)
	}

	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if key, note, ok := strings.Cut(line, "\t"); ok {
			got[key] = note
		}
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			note, ok := got["case"+string(rune('0'+i))]
			if !ok {
				t.Fatalf("the probe produced no note for this case:\n%s", out)
			}
			for _, want := range tc.want {
				if !strings.Contains(note, want) {
					t.Errorf("the note does not say %q: %s", want, note)
				}
			}
			for _, not := range tc.wantNot {
				if strings.Contains(note, not) {
					t.Errorf("the note says %q, which it should not: %s", not, note)
				}
			}
			if strings.ContainsAny(note, "\t\n") {
				t.Errorf("the note carries a tab or newline, which the ledger cell cannot hold: %q", note)
			}
		})
	}
}

// TestFuzzSoakMeasureCoverageSaysWhyItFailed runs the real measurement, in a
// throwaway module, against a package whose replay fails — first with an ordinary
// failing test, then with a corpus entry that fails on its own. It is the case
// that used to be reported as a corpus reproducer, end to end: measure_coverage
// captures the output, the classifier reads it, and the pass's value-and-reason
// line comes back with the two halves separable.
//
// It is a real go test, so it needs go, and it is the only test here that does.
func TestFuzzSoakMeasureCoverageSaysWhyItFailed(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available; the soak is a bash script")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH; the measurement is a go test")
	}

	const fuzzTest = "package wirefuzz\n\nimport \"testing\"\n\n" +
		"func FuzzThing(f *testing.F) {\n" +
		"\tf.Add([]byte(\"ok\"))\n" +
		"\tf.Fuzz(func(t *testing.T, b []byte) {\n" +
		"\t\tif len(b) > 0 && b[0] == 'x' {\n" +
		"\t\t\tt.Fatal(\"boom\")\n" +
		"\t\t}\n" +
		"\t})\n" +
		"}\n"

	tests := []struct {
		name    string
		files   map[string]string
		dirs    []string
		want    []string
		wantNot []string
	}{
		{
			name: "a failing test in the package is named as the reason",
			files: map[string]string{
				"internal/wirefuzz/broken_test.go": "package wirefuzz\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { t.Fatal(\"nope\") }\n",
			},
			// The pass only measures where a corpus lives, so the directory has to
			// be there even though this package's trouble is a test.
			dirs: []string{"internal/wirefuzz/testdata/fuzz/FuzzThing"},
			// The value line is pinned whole, newline included: a tab lost on the
			// way out glues the reason onto the value, and a looser "contains
			// value=n/a" would still pass while the reader saw a nonsense count.
			want: []string{
				"value=n/a\n",
				"note=test-failure: TestBroken fails, which is not a corpus entry\n",
			},
			wantNot: []string{"reproducer:", "no-corpus:"},
		},
		{
			name: "a corpus entry that fails on its own is a reproducer",
			files: map[string]string{
				"internal/wirefuzz/fuzz_test.go": fuzzTest,
				// go's own on-disk encoding for a corpus entry, which is what makes
				// this a failing replay rather than a corpus it cannot parse.
				"internal/wirefuzz/testdata/fuzz/FuzzThing/0a1b2c3d4e5f6071": "go test fuzz v1\n[]byte(\"xx\")\n",
			},
			want: []string{
				"value=n/a\n",
				"note=reproducer: FuzzThing/0a1b2c3d4e5f6071 fails on its own, so the replay it would be measured against cannot finish\n",
			},
			wantNot: []string{"test-failure:", "no-corpus:"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{"go.mod": "module covprobe\n\ngo 1.27\n"}
			for path, body := range tc.files {
				files[path] = body
			}
			for path, body := range files {
				full := filepath.Join(dir, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatalf("creating %s: %v", filepath.Dir(full), err)
				}
				if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
					t.Fatalf("writing %s: %v", full, err)
				}
			}
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o755); err != nil {
					t.Fatalf("creating %s: %v", d, err)
				}
			}

			var probe strings.Builder
			probe.WriteString("set -u\n")
			probe.WriteString("COVER_TMP=" + shellQuote(filepath.ToSlash(filepath.Join(dir, "cover.out"))) + "\n")
			probe.WriteString("COVERLOG=" + shellQuote(filepath.ToSlash(filepath.Join(dir, "last-coverage.log"))) + "\n")
			for _, name := range []string{"corpus_packages", "coverage_names", "coverage_note", "measure_coverage"} {
				probe.WriteString(soakFunc(t, name) + "\n")
			}
			// The pass splits this same line; the split is here so a missing tab —
			// which would put the whole line in the value and leave the reason
			// silently empty — cannot pass unnoticed.
			probe.WriteString("out=\"$(measure_coverage)\"\n")
			probe.WriteString("printf 'value=%s\\n' \"${out%%$'\\t'*}\"\n")
			probe.WriteString("printf 'note=%s\\n' \"${out#*$'\\t'}\"\n")

			script := filepath.Join(dir, "probe.sh")
			if err := os.WriteFile(script, []byte(probe.String()), 0o644); err != nil {
				t.Fatalf("writing the probe: %v", err)
			}
			cmd := exec.Command("bash", filepath.ToSlash(script))
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("running the probe: %v\n%s", err, out)
			}
			text := string(out)
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Errorf("the measurement does not report %q:\n%s", want, text)
				}
			}
			for _, not := range tc.wantNot {
				if strings.Contains(text, not) {
					t.Errorf("the measurement reports %q, which it should not:\n%s", not, text)
				}
			}
		})
	}
}
