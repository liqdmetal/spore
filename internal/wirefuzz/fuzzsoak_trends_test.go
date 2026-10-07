package wirefuzz

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

	const (
		script = "../../scripts/fuzz-soak-trends.sh"
		header = "timestamp\tmode\tfuzz_seconds\tstatus\tcorpus_before\tcorpus_after\tfound\tminimized\tcoverage\tcoverage_delta\tduration_s\n"
	)
	row := func(ts, status, coverage string) string {
		return strings.Join([]string{ts, "deep", "60", status, "80", "84", "5", "1", coverage, "+0", "600"}, "\t") + "\n"
	}

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
