package continuity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The stale-reaper watchdog: a dead background reaper on the node holding the
// vault-recipient bodies is a CONTINUITY failure with no other signal. Expired
// bodies stop composting, the hold grows unboundedly, and — the quiet part —
// a node whose reaper loop died is often a node wedged more generally. The
// reaper's own heartbeat cannot report its death (a dead loop prints
// nothing), so the watch loop — the thing already scheduled to look at this
// node — carries the check.
//
// Both daemons print identical heartbeat lines (the Rust port kept them
// operator-identical on purpose):
//
//	spore serve: reaper status: 14 passes, 3 bodies composted total, last pass removed 2 at 10:48:49 (cadence 2s)
//	spore-peer serve: reaper status: 14 passes, no pass completed yet (cadence 10m0s)
//
// The watchdog reads that log, takes the LAST reaper status line, and
// compares its pass counter with the value remembered from the previous
// watch. Equal count => the reaper completed no pass between watches =>
// alert. Higher count => record it and stay quiet. This is the
// "counter stuck vs counter advanced" split from the reap-ticker flake,
// pointed at production.
//
// Like the rest of the continuity surface, this does one explicit pass and
// never schedules itself; the cron entry or systemd timer that runs
// `continuity watch` runs the watchdog next to it — the loop is the
// scheduler's, and the docs say so on purpose.

// ReapStatus is the last "reaper status" heartbeat parsed from a log.
type ReapStatus struct {
	Passes  uint64
	Removed uint64
	Cadence string
	// Source is which daemon prefix the line carried ("spore" or
	// "spore-peer") — cross-checked by the caller so a watchdog pointed at
	// the wrong log fails loudly instead of comparing nothing.
	Source string
}

// ParseReapStatusLine recognizes one reaper status heartbeat from either
// daemon and extracts the pass counter. It never guesses: only lines that
// parse cleanly count. The "no pass completed yet" form is accepted too — a
// reaper that has NEVER completed a pass is exactly as dead as one whose
// counter froze (and a hold that should have bodies under a never-run reaper
// is precisely the case worth waking someone for).
func ParseReapStatusLine(line string) (ReapStatus, bool) {
	var source, rest string
	switch {
	case strings.HasPrefix(line, "spore-peer serve: reaper status: "):
		source, rest = "spore-peer", strings.TrimPrefix(line, "spore-peer serve: reaper status: ")
	case strings.HasPrefix(line, "spore serve: reaper status: "):
		source, rest = "spore", strings.TrimPrefix(line, "spore serve: reaper status: ")
	default:
		return ReapStatus{}, false
	}
	st := ReapStatus{Source: source}
	if _, err := fmt.Sscanf(rest, "%d passes", &st.Passes); err != nil {
		return ReapStatus{}, false
	}
	if i := strings.Index(rest, ", "); i >= 0 {
		// Advisory: the "no pass completed yet" variant carries no total.
		_, _ = fmt.Sscanf(rest[i+len(", "):], "%d bodies composted total", &st.Removed)
	}
	if i := strings.LastIndex(rest, "(cadence "); i >= 0 && strings.HasSuffix(rest, ")") {
		st.Cadence = rest[i+len("(cadence ") : len(rest)-1]
	}
	return st, true
}

// LastReapStatus scans a log file and returns the newest parseable reaper
// status line, or nil when the log carries none. Scanning the whole file
// (not tailing) is deliberate: logs rotate, and a one-shot watch reading it
// once per invocation is the cheap case.
func LastReapStatus(path string) (*ReapStatus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var last *ReapStatus
	for _, line := range strings.Split(string(raw), "\n") {
		if st, ok := ParseReapStatusLine(strings.TrimRight(line, "\r")); ok {
			s := st
			last = &s
		}
	}
	return last, nil
}

// ReapMemory is the durable side of the comparison: the pass counter as seen
// by the previous watch, plus the alert latch.
type ReapMemory struct {
	Passes      uint64 `json:"passes"`
	Removed     uint64 `json:"removed"`
	ObservedAt  int64  `json:"observed_at_unix"`
	Frozen      int    `json:"frozen_observations,omitempty"` // consecutive equal-count observations
	Alerted     bool   `json:"alerted"`
	AlertPasses uint64 `json:"alert_passes,omitempty"`
	Source      string `json:"source,omitempty"`
}

// LoadReapMemory reads the memory file; a missing file is a fresh watch (no
// baseline yet). A CORRUPT file is an error: silently treating unreadable
// memory as fresh would turn "the state directory broke" into "the watchdog
// silently re-baselined", which is the exact failure this exists to prevent.
func LoadReapMemory(path string) (*ReapMemory, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m ReapMemory
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("reaper watchdog state %s: %w", path, err)
	}
	return &m, nil
}

// WatchdogOutcome is what one watchdog pass decided and why.
type WatchdogOutcome int

const (
	// WatchdogBaseline: fresh watch, no prior memory — recorded, not judged.
	WatchdogBaseline WatchdogOutcome = iota
	// WatchdogOK: the pass counter advanced; the reaper is alive.
	WatchdogOK
	// WatchdogWithinGrace: frozen, but inside the tolerated observation count.
	WatchdogWithinGrace
	// WatchdogFrozenAlert: frozen past grace — an alert must be raised.
	WatchdogFrozenAlert
	// WatchdogAlreadyQueued: still frozen at the alerted count; do not re-alert.
	WatchdogAlreadyQueued
	// WatchdogRebaselined: the counter went backwards (log rotation or
	// daemon restart with a fresh log) — re-baseline instead of crying wolf.
	WatchdogRebaselined
	// WatchdogNoHeartbeat: the log carries no parseable heartbeat. The
	// reaper is UNVERIFIABLE, which for a continuity hold is treated like
	// dead: silence is not health. The caller alerts (and re-alerts each
	// watch until a heartbeat appears — the wanted nag for a down daemon).
	WatchdogNoHeartbeat
)

// WatchdogResult carries the outcome and the updated memory to persist.
type WatchdogResult struct {
	Outcome WatchdogOutcome
	Memory  ReapMemory
	// Status is the observed heartbeat (nil with WatchdogNoHeartbeat).
	Status *ReapStatus
	// Detail is a human sentence for the alert subject/body.
	Detail string
}

// CheckReaper performs one watchdog pass. grace tolerates that many
// equal-count observations before alerting (0 = alert on the first freeze);
// it is counted in observations rather than seconds because the watch
// cadence is the operator's scheduling choice, not this package's.
//
// The returned memory is always the state to persist (the caller writes it
// atomically through its own private-file helpers); now is injected so tests
// pin timestamps.
func CheckReaper(status *ReapStatus, mem *ReapMemory, grace int, now int64) WatchdogResult {
	// Unverifiable: no heartbeat at all. Treated like dead (see
	// WatchdogNoHeartbeat); memory is left untouched so the baseline
	// survives a down-daemon window and comparison resumes when the
	// daemon returns.
	if status == nil {
		return WatchdogResult{Outcome: WatchdogNoHeartbeat, Memory: derefOrZero(mem),
			Detail: "no reaper status heartbeat in the daemon log; the node may be down or freshly started"}
	}

	switch {
	case mem == nil:
		// Fresh watch: record the baseline, do not compare — the first
		// observation can never show a freeze (nothing to be equal to).
		return WatchdogResult{Outcome: WatchdogBaseline,
			Memory: ReapMemory{Passes: status.Passes, Removed: status.Removed, ObservedAt: now, Source: status.Source},
			Status: status}

	case status.Passes > mem.Passes:
		// Alive: the counter advanced. Clear the latch so a reaper that
		// was wedged and recovered re-arms the watchdog.
		return WatchdogResult{Outcome: WatchdogOK,
			Memory: ReapMemory{Passes: status.Passes, Removed: status.Removed, ObservedAt: now, Source: status.Source},
			Status: status}

	case status.Passes < mem.Passes:
		// Counter went backwards: log rotation truncated the visible
		// history or the daemon restarted with a fresh log. Re-baseline —
		// comparing against the old count would cry wolf forever — and
		// clear the latch, since the next comparison judges the new log.
		return WatchdogResult{Outcome: WatchdogRebaselined,
			Memory: ReapMemory{Passes: status.Passes, Removed: status.Removed, ObservedAt: now, Source: status.Source},
			Status: status}

	default: // status.Passes == mem.Passes
		// Frozen: the heartbeat prints on every pass even when idle, so
		// equality across watches means no pass completed in between.
		if mem.Alerted && mem.AlertPasses == status.Passes {
			return WatchdogResult{Outcome: WatchdogAlreadyQueued, Memory: *mem, Status: status,
				Detail: fmt.Sprintf("pass counter still frozen at %d; alert already queued", status.Passes)}
		}
		next := *mem
		next.Frozen++
		next.ObservedAt = now
		if next.Frozen <= grace {
			return WatchdogResult{Outcome: WatchdogWithinGrace, Memory: next, Status: status,
				Detail: fmt.Sprintf("frozen passes=%d (%d/%d within grace)", status.Passes, next.Frozen, grace)}
		}
		return WatchdogResult{Outcome: WatchdogFrozenAlert, Memory: next, Status: status,
			Detail: fmt.Sprintf("pass counter frozen at %d across watches (last pass removed %d, cadence %s)",
				status.Passes, status.Removed, status.Cadence)}
	}
}

// ApplyAlertLatch marks a memory as alerted for the given frozen count; the
// caller persists it after queueing the alert so repeated watches do not
// re-queue while the counter stays put (the outbox dedupes by TxID anyway,
// but the latch makes recovery visible: the counter advancing clears it).
func ApplyAlertLatch(m ReapMemory, passes uint64) ReapMemory {
	m.Alerted = true
	m.AlertPasses = passes
	return m
}

func derefOrZero(m *ReapMemory) ReapMemory {
	if m == nil {
		return ReapMemory{}
	}
	return *m
}
