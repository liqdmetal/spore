package main

import (
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// gapReportLines renders a loss picture as operator-facing lines.
//
// It returns nil when there is nothing missing, so the caller can treat a nil
// result as "no news". Formatting lives here rather than inline in the receive
// loop so the wording is testable — an operator has to be able to tell
// "recoverable" from "gone" at a glance, and that distinction is exactly what
// this reports.
func gapReportLines(r ratchetwire.GapReport) []string {
	if r.Empty() {
		return nil
	}
	out := []string{
		fmt.Sprintf("e2 gaps: %d message(s) still recoverable, %d confirmed lost",
			len(r.Pending), r.LostTotal),
	}
	for _, g := range r.Pending {
		out = append(out, fmt.Sprintf("  missing n=%d chain=%x…%x deadline=%s",
			g.N, g.RatchetKey[:2], g.RatchetKey[len(g.RatchetKey)-2:], gapDeadline(g.Deadline)))
	}
	if r.LostTruncated {
		out = append(out, fmt.Sprintf("  (showing the first %d of %d lost)", len(r.Lost), r.LostTotal))
	}
	return out
}

// gapDeadline renders a gap's deadline, making the never-expiring case explicit
// instead of printing a year-zero timestamp.
func gapDeadline(d time.Time) string {
	if d.IsZero() {
		return "none (bounded by caps)"
	}
	return d.Format(time.RFC3339)
}
