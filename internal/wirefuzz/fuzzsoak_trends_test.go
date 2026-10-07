package wirefuzz

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// soakLedgerHeader is the ledger scripts/fuzz-soak.sh writes and
// scripts/fuzz-soak-trends.sh reads.
// TestFuzzSoakLedgerHeaderIsWhatTheReaderExpects holds the writer to it, because
// the reader addresses columns by position: a column added on one side and not the
// other is read out of the wrong place, silently, for a whole cohort of rows.
const soakLedgerHeader = "timestamp\tmode\tfuzz_seconds\tstatus\tcorpus_before\tcorpus_after\tfound\tminimized\tcoverage\tcoverage_delta\tduration_s\tcoverage_note\n"

// The reader addresses the ledger by position, so the writer's header and the
// reader's columns have to be the same list in the same order. That is a fact
// about two files, and only this test can hold it: a column added on one side
// and not the other reads the wrong value out of every row, silently.
func TestFuzzSoakLedgerHeaderIsWhatTheReaderExpects(t *testing.T) {
	script, err := os.ReadFile("../../scripts/fuzz-soak.sh")
	if err != nil {
		t.Fatalf("reading the soak script: %v", err)
	}

	header := regexp.MustCompile(`(?m)^\s*printf '([^']*)' > "\$LEDGER"\s*$`).FindSubmatch(script)
	if header == nil {
		t.Fatal("no line writes the ledger header; the reader's columns would drift from the writer's")
	}
	// printf interprets \t and \n, while the constant holds the real bytes.
	got := strings.NewReplacer(`\t`, "\t", `\n`, "\n").Replace(string(header[1]))
	if got != soakLedgerHeader {
		t.Errorf("the header the soak writes is\n%q\nand the reader expects\n%q", got, soakLedgerHeader)
	}

	// A row has to supply exactly as many values as the header names columns: a
	// missing one renders the literal text %s into the ledger, an extra one lands
	// the reason in the wrong cell.
	row := regexp.MustCompile(`(?s)printf '((?:%s\\t)+%s\\n)' \\\n`).FindSubmatch(script)
	if row == nil {
		t.Fatal("no line writes a ledger row; the ledger's shape is unpinned")
	}
	verbs := strings.Count(string(row[1]), "%s")
	if want := strings.Count(soakLedgerHeader, "\t") + 1; verbs != want {
		t.Errorf("the row format writes %d values but the header names %d columns", verbs, want)
	}
}

// A single soak pass reports its own delta, which leaves the question that
// matters after a few weeks unasked: is the fuzzer still finding anything? A
// corpus that has not moved looks the same whether coverage is saturated or the
// harness is quietly broken — and an unattended pass acts on that verdict, so
// scripts/fuzz-soak-trends.sh is pinned here against synthetic ledgers.
// Producing the real input would take days of fuzzing, and a ledger is just
// rows: this is cheaper and states the cases explicitly.
func TestFuzzSoakTrendsFlags(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available; the trend reader is a POSIX shell script")
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available; the trend reader is awk over the ledger")
	}

	const script = "../../scripts/fuzz-soak-trends.sh"
	header := soakLedgerHeader
	// A row as the soak writes it now: the last column is why a coverage cell says
	// n/a, and is empty when there was a count to put there.
	pass := func(ts, status, coverage, note string) string {
		return strings.Join([]string{ts, "deep", "60", status, "80", "84", "5", "1", coverage, "+0", "600", note}, "\t") + "\n"
	}
	// A row from before that column existed: eleven fields, and the reader has to
	// say it does not know rather than assume.
	oldPass := func(ts, status, coverage string) string {
		return strings.Join([]string{ts, "deep", "60", status, "80", "84", "5", "1", coverage, "+0", "600"}, "\t") + "\n"
	}
	row := func(ts, status, coverage string) string { return pass(ts, status, coverage, "") }

	tests := []struct {
		name     string
		ledger   string
		absent   bool
		env      []string
		args     []string
		wantExit int
		want     []string
		wantNot  []string
	}{
		{
			name: "coverage still setting new bests is clean",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "GREEN", "120") +
				row("2026-10-03T03:30:00Z", "GREEN", "140"),
			wantExit: 0,
			want:     []string{"best coverage 140"},
			wantNot:  []string{"STALLED", "FAILING", "FELL", "UNMEASURED"},
		},
		{
			name: "a plateau of passes with no new best is stalled",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "GREEN", "200") +
				row("2026-10-03T03:30:00Z", "GREEN", "200") +
				row("2026-10-04T03:30:00Z", "GREEN", "200") +
				row("2026-10-05T03:30:00Z", "GREEN", "200") +
				row("2026-10-06T03:30:00Z", "GREEN", "200") +
				row("2026-10-07T03:30:00Z", "GREEN", "200"),
			wantExit: 1,
			want:     []string{"STALLED", "best 200 at 2026-10-02T03:30:00Z"},
		},
		{
			name: "a pass that did not end GREEN is flagged, and named",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "CRASH", "100"),
			wantExit: 1,
			want:     []string{"FAILING", "CRASH", "2026-10-02T03:30:00Z"},
			wantNot:  []string{"STALLED"},
		},
		{
			name: "coverage going backwards is its own flag",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "200") +
				row("2026-10-02T03:30:00Z", "GREEN", "190"),
			wantExit: 1,
			want:     []string{"FELL", "200 -> 190"},
			wantNot:  []string{"STALLED"},
		},
		{
			name: "unmeasured coverage is called out instead of faking a stall",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "CRASH", "n/a"),
			wantExit: 1,
			want:     []string{"UNMEASURED", "FAILING"},
			wantNot:  []string{"STALLED", "FELL"},
		},
		{
			name: "a reproducer is quoted as the reason, and is not a broken harness",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "1211") +
				pass("2026-10-02T03:30:00Z", "GREEN", "n/a",
					"reproducer: FuzzFrameParse/seed#2 fails on its own, so the replay it would be measured against cannot finish"),
			wantExit: 0,
			want:     []string{"UNMEASURED", "reproducer: FuzzFrameParse/seed#2 fails on its own"},
			wantNot:  []string{"FAILING", "FELL", "STALLED", "not because of a reproducer"},
		},
		{
			name: "a failing test is quoted, and is not blamed on the corpus",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "1211") +
				pass("2026-10-02T03:30:00Z", "GREEN", "n/a",
					"test-failure: TestFuzzSoakHaulHandsTheCorpusOver fails, which is not a corpus entry"),
			wantExit: 1,
			want:     []string{"UNMEASURED", "not because of a reproducer", "test-failure: TestFuzzSoakHaulHandsTheCorpusOver"},
			wantNot:  []string{"STALLED", "a reproducer in the corpus fails the replay"},
		},
		{
			name: "a row from before the reason was recorded says so",
			ledger: header +
				oldPass("2026-10-01T03:30:00Z", "GREEN", "1211") +
				oldPass("2026-10-02T03:30:00Z", "GREEN", "n/a"),
			wantExit: 0,
			want:     []string{"UNMEASURED", "did not record why"},
			wantNot:  []string{"a reproducer in the corpus fails the replay", "not because of a reproducer"},
		},
		{
			name: "the stall threshold is a knob",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "GREEN", "100") +
				row("2026-10-03T03:30:00Z", "GREEN", "100"),
			env:      []string{"FUZZ_STALL_PASSES=2"},
			wantExit: 1,
			want:     []string{"STALLED", "3 pass(es)"},
		},
		{
			name: "flags-only keeps the table out of a caller's output",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "GREEN", "200") +
				row("2026-10-03T03:30:00Z", "GREEN", "200") +
				row("2026-10-04T03:30:00Z", "GREEN", "200") +
				row("2026-10-05T03:30:00Z", "GREEN", "200") +
				row("2026-10-06T03:30:00Z", "GREEN", "200") +
				row("2026-10-07T03:30:00Z", "GREEN", "200"),
			args:     []string{"--flags-only"},
			wantExit: 1,
			want:     []string{"STALLED"},
			wantNot:  []string{"timestamp", "minimized"},
		},
		{
			name: "flags-only says nothing at all when clean",
			ledger: header +
				row("2026-10-01T03:30:00Z", "GREEN", "100") +
				row("2026-10-02T03:30:00Z", "GREEN", "120"),
			args:     []string{"--flags-only"},
			wantExit: 0,
			wantNot:  []string{"STALLED", "FAILING", "FELL", "timestamp"},
		},
		{
			name:     "a ledger the soak never wrote is refused",
			ledger:   "nope\tdeep\n",
			wantExit: 2,
			want:     []string{"not a fuzz-soak ledger"},
		},
		{
			name:     "a header with no passes is refused",
			ledger:   header,
			wantExit: 2,
			want:     []string{"no passes recorded"},
		},
		{
			name:     "a missing ledger is refused",
			absent:   true,
			wantExit: 2,
			want:     []string{"no soak ledger found"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ledger := filepath.Join(dir, "log.tsv")
			if !tc.absent {
				if err := os.WriteFile(ledger, []byte(tc.ledger), 0o644); err != nil {
					t.Fatalf("writing the ledger: %v", err)
				}
			}

			cmd := exec.Command("sh", append([]string{script}, tc.args...)...)
			cmd.Env = append(os.Environ(), "FUZZ_SOAK_LEDGER="+ledger, "FUZZ_SOAK_DIR="+dir)
			cmd.Env = append(cmd.Env, tc.env...)
			out, err := cmd.CombinedOutput()

			code := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("running %s: %v (%s)", script, err, out)
				}
				code = ee.ExitCode()
			}
			if code != tc.wantExit {
				t.Errorf("exit %d, want %d; output:\n%s", code, tc.wantExit, out)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(out), want) {
					t.Errorf("output does not mention %q:\n%s", want, out)
				}
			}
			for _, not := range tc.wantNot {
				if strings.Contains(string(out), not) {
					t.Errorf("output should not mention %q:\n%s", not, out)
				}
			}
		})
	}
}
