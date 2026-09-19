package ratchetwire

import (
	"sort"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// MessageGap is one undelivered message, located in a specific session.
//
// The split between Pending and Lost is the point of this type:
//
//   - Pending: the ciphertext has not arrived, but the message key is still
//     buffered, so it will decrypt if the body turns up before its deadline.
//     This is the retry set — a late arrival is a recovery, not an error.
//   - Lost: the key was swept past the deadline and is gone. By forward
//     secrecy it cannot be re-derived, so this is permanent. Report it; do
//     not retry it.
//
// Both inherit the SAME burn deadline as the body, so "key swept" and "body
// unfetchable" are the same instant — the classification is not a heuristic.
type MessageGap struct {
	SessionID  [8]byte
	RatchetKey [32]byte
	N          uint32
	Deadline   time.Time
}

// Pending reports whether this gap can still be recovered.
func (g MessageGap) Pending(now time.Time) bool {
	return g.Deadline.IsZero() || g.Deadline.After(now)
}

// GapReport is the whole loss picture for an endpoint at one instant.
type GapReport struct {
	// Pending gaps can still be filled in if their ciphertext arrives.
	Pending []MessageGap
	// Lost gaps are unrecoverable. LostTotal is cumulative for the process,
	// because a swept gap is deleted and cannot be enumerated again.
	Lost      []MessageGap
	LostTotal uint64
	// LostTruncated reports that Lost is a capped view and LostTotal is
	// larger — a report must never imply it is showing everything.
	LostTruncated bool
}

// Empty reports whether nothing is missing.
func (r GapReport) Empty() bool { return len(r.Pending) == 0 && len(r.Lost) == 0 && r.LostTotal == 0 }

// toGaps converts ratchet-level records for one session.
func toGaps(id [8]byte, recs []ratchet.LossRecord) []MessageGap {
	out := make([]MessageGap, 0, len(recs))
	for _, r := range recs {
		out = append(out, MessageGap{
			SessionID:  id,
			RatchetKey: r.RatchetKey,
			N:          r.N,
			Deadline:   r.Deadline,
		})
	}
	return out
}

func sortGaps(gaps []MessageGap) {
	sort.Slice(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.SessionID != b.SessionID {
			return string(a.SessionID[:]) < string(b.SessionID[:])
		}
		if a.RatchetKey != b.RatchetKey {
			return string(a.RatchetKey[:]) < string(b.RatchetKey[:])
		}
		return a.N < b.N
	})
}

// Outstanding returns every recoverable gap across all sessions: messages
// whose ciphertext has not arrived but whose key is still held.
func (t *SessionTable) Outstanding() []MessageGap {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []MessageGap
	for id, s := range t.sessions {
		out = append(out, toGaps(id, s.Outstanding())...)
	}
	sortGaps(out)
	return out
}

// SweepGaps drops expired skipped keys and returns them as confirmed losses.
// Sweep is the count-only wrapper.
func (t *SessionTable) SweepGaps(now time.Time) []MessageGap {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []MessageGap
	for id, s := range t.sessions {
		out = append(out, toGaps(id, s.SweepSkippedDetailed(now))...)
	}
	sortGaps(out)
	return out
}

// maxRecordedLosses bounds the per-endpoint ledger of confirmed losses. The
// cumulative counter stays exact; only the enumerated detail is capped, and
// Truncated reports when that has happened so a report never implies it is
// showing everything.
const maxRecordedLosses = 256

// noteLost records confirmed losses in the endpoint ledger.
func (e *DurableEndpoint) noteLost(gaps []MessageGap) {
	if len(gaps) == 0 {
		return
	}
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	e.lostTotal += uint64(len(gaps))
	for _, g := range gaps {
		if len(e.lostGaps) >= maxRecordedLosses {
			e.lostTrunc = true
			break
		}
		e.lostGaps = append(e.lostGaps, g)
	}
}

// Gaps reports what this endpoint is currently missing.
//
// LostTotal is cumulative for the lifetime of the process: a swept gap is
// deleted from the session and cannot be enumerated a second time, so the
// counter — not Lost — is the authoritative "how many messages never arrived".
func (e *DurableEndpoint) Gaps() GapReport {
	e.lossMu.Lock()
	r := GapReport{
		Lost:          append([]MessageGap(nil), e.lostGaps...),
		LostTotal:     e.lostTotal,
		LostTruncated: e.lostTrunc,
	}
	e.lossMu.Unlock()
	r.Pending = e.Sessions.Outstanding()
	return r
}

// LostCount is the cumulative confirmed-loss count.
func (e *DurableEndpoint) LostCount() uint64 {
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	return e.lostTotal
}
