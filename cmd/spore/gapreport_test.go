package main

import (
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// TestGapReportLinesSilentWhenNothingMissing: a clean conversation must produce
// no output at all, so a normal run is never noise.
func TestGapReportLinesSilentWhenNothingMissing(t *testing.T) {
	if lines := gapReportLines(ratchetwire.GapReport{}); lines != nil {
		t.Fatalf("clean report produced lines: %#v", lines)
	}
}

// TestGapReportLinesDistinguishesPendingFromLost is the operator-facing
// contract: "still recoverable" and "confirmed lost" must never be conflated.
func TestGapReportLinesDistinguishesPendingFromLost(t *testing.T) {
	deadline := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	r := ratchetwire.GapReport{
		Pending: []ratchetwire.MessageGap{
			{N: 3, Deadline: deadline},
			{N: 4, Deadline: deadline},
		},
		Lost:      []ratchetwire.MessageGap{{N: 1, Deadline: deadline}},
		LostTotal: 5,
	}
	lines := gapReportLines(r)
	if len(lines) == 0 {
		t.Fatal("gaps produced no lines")
	}
	head := lines[0]
	if !strings.Contains(head, "2 message(s) still recoverable") {
		t.Errorf("pending count missing from %q", head)
	}
	if !strings.Contains(head, "5 confirmed lost") {
		t.Errorf("cumulative lost count missing from %q", head)
	}
	// Every pending gap gets its own line, and n is named explicitly.
	if len(lines) != 1+2 {
		t.Fatalf("line count = %d, want 1 header + 2 pending", len(lines))
	}
	for i, want := range []string{"n=3", "n=4"} {
		if !strings.Contains(lines[i+1], want) {
			t.Errorf("pending line %d missing %q: %q", i, want, lines[i+1])
		}
	}
}

// TestGapReportLinesReportsTruncation: a capped view must say so, because
// otherwise the report implies it is showing every loss.
func TestGapReportLinesReportsTruncation(t *testing.T) {
	r := ratchetwire.GapReport{
		Lost:          []ratchetwire.MessageGap{{N: 1}},
		LostTotal:     999,
		LostTruncated: true,
	}
	lines := gapReportLines(r)
	if len(lines) == 0 {
		t.Fatal("truncated report produced no lines")
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "showing the first 1 of 999") {
		t.Fatalf("truncation not disclosed: %q", last)
	}
}

// TestGapDeadlineNamesTheUnboundedCase: a deadline-less gap is bounded by the
// hard caps, not by time, and printing a year-zero timestamp would be a lie.
func TestGapDeadlineNamesTheUnboundedCase(t *testing.T) {
	if got := gapDeadline(time.Time{}); !strings.Contains(got, "none") {
		t.Fatalf("zero deadline rendered as %q", got)
	}
	d := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	if got := gapDeadline(d); !strings.Contains(got, "2030-06-01") {
		t.Fatalf("deadline rendered as %q", got)
	}
}

// TestGapReportLinesLostOnlyStillReports checks the case where nothing is
// pending but messages were lost: silence here would hide permanent data loss.
func TestGapReportLinesLostOnlyStillReports(t *testing.T) {
	r := ratchetwire.GapReport{LostTotal: 1, Lost: []ratchetwire.MessageGap{{N: 7}}}
	lines := gapReportLines(r)
	if len(lines) == 0 {
		t.Fatal("a lost-only report was silent")
	}
	if !strings.Contains(lines[0], "0 message(s) still recoverable") ||
		!strings.Contains(lines[0], "1 confirmed lost") {
		t.Fatalf("unexpected header: %q", lines[0])
	}
}
