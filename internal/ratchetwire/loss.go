package ratchetwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
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
	// Lost gaps are unrecoverable. LostTotal is the known cumulative count;
	// after the persistent identity cap is reached it is a lower bound.
	Lost      []MessageGap
	LostTotal uint64
	// LostTruncated reports that Lost is a capped view and/or the persisted
	// total has saturated. A report must never imply it shows everything.
	LostTruncated bool
	// ExpiredUnclassified counts persisted keys whose deadline has passed but
	// which have not yet been swept by a receiver process.
	ExpiredUnclassified int
	// LossPersistenceError is non-empty if confirmed loss could not be saved.
	LossPersistenceError string
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

const gapLedgerFile = "message-gaps.enc"
const maxGapLedgerBytes = 256 << 10

var gapLedgerID = [8]byte{'g', 'a', 'p', 's', 'v', '1', 0, 1}

type persistedGapLedger struct {
	Version       int          `json:"version"`
	Lost          []MessageGap `json:"lost"`
	LostTotal     uint64       `json:"lost_total"`
	LostTruncated bool         `json:"lost_truncated"`
}

func gapIdentity(g MessageGap) string {
	return fmt.Sprintf("%x:%x:%d", g.SessionID, g.RatchetKey, g.N)
}

func (e *DurableEndpoint) gapLedgerPath() string {
	return filepath.Join(e.StateDir(), gapLedgerFile)
}

func (e *DurableEndpoint) loadGapLedger() error {
	if e.StateDir() == "" {
		return errors.New("ratchetwire: empty gap ledger directory")
	}
	raw, err := bounds.ReadBound(e.gapLedgerPath(), maxGapLedgerBytes)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	ledger, err := decodeGapLedger(e.states.protector, raw)
	if err != nil {
		return err
	}
	e.lostGaps = append([]MessageGap(nil), ledger.Lost...)
	e.lostTotal = ledger.LostTotal
	e.lostTrunc = ledger.LostTruncated
	return nil
}

func decodeGapLedger(protector *StateProtector, raw []byte) (persistedGapLedger, error) {
	var ledger persistedGapLedger
	plain, err := protector.Open(gapLedgerID, raw)
	if err != nil {
		return ledger, fmt.Errorf("ratchetwire: decrypt gap ledger: %w", err)
	}
	defer clear(plain)
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ledger); err != nil {
		return ledger, fmt.Errorf("ratchetwire: decode gap ledger: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return ledger, errors.New("ratchetwire: trailing gap ledger data")
	}
	if ledger.Version != 1 || len(ledger.Lost) > maxRecordedLosses || ledger.LostTotal < uint64(len(ledger.Lost)) || ledger.LostTotal > maxRecordedLosses || (!ledger.LostTruncated && ledger.LostTotal != uint64(len(ledger.Lost))) {
		return ledger, errors.New("ratchetwire: invalid gap ledger shape")
	}
	seen := make(map[string]bool, len(ledger.Lost))
	for _, gap := range ledger.Lost {
		id := gapIdentity(gap)
		if seen[id] {
			return ledger, errors.New("ratchetwire: duplicate gap ledger identity")
		}
		seen[id] = true
	}
	return ledger, nil
}

// persistGapLedgerLocked atomically writes authenticated, encrypted metadata.
// The caller holds lossMu. The ledger contains gap identities, not skipped
// message keys or plaintext.
func (e *DurableEndpoint) persistGapLedgerLocked() error {
	ledger := persistedGapLedger{Version: 1, Lost: append([]MessageGap(nil), e.lostGaps...), LostTotal: e.lostTotal, LostTruncated: e.lostTrunc}
	if ledger.LostTotal > maxRecordedLosses {
		ledger.LostTotal = maxRecordedLosses
		ledger.LostTruncated = true
	}
	plain, err := json.Marshal(ledger)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain)+64 > maxGapLedgerBytes {
		return errors.New("ratchetwire: gap ledger exceeds size limit")
	}
	raw, err := e.states.protector.Seal(gapLedgerID, plain)
	if err != nil {
		return err
	}
	return privateAtomic(e.gapLedgerPath(), raw)
}

// ReadOnlyGaps reads authenticated ratchet sessions and the encrypted loss
// ledger without creating files/directories, sweeping keys, or rewriting state.
func ReadOnlyGaps(stateDir string, key []byte, now time.Time) (GapReport, error) {
	var report GapReport
	if stateDir == "" {
		return report, errors.New("ratchetwire: empty gap report directory")
	}
	if now.IsZero() {
		now = time.Now()
	}
	protector, err := NewStateProtector(key)
	if err != nil {
		return report, err
	}
	if info, err := os.Stat(stateDir); err != nil {
		return report, err
	} else if !info.IsDir() {
		return report, fmt.Errorf("ratchetwire: gap report path is not a directory")
	}
	states := &FileStateStore{dir: stateDir, protector: protector, sequence: make(map[[8]byte]uint64)}
	ids, err := states.IDs()
	if err != nil {
		return report, err
	}
	for _, id := range ids {
		state, err := states.Load(id)
		if err != nil {
			return report, fmt.Errorf("ratchetwire: read session %x for gap report: %w", id, err)
		}
		session, err := ratchet.ImportState(state)
		clear(state)
		if err != nil {
			return report, fmt.Errorf("ratchetwire: decode session %x for gap report: %w", id, err)
		}
		for _, gap := range session.Outstanding() {
			converted := MessageGap{SessionID: id, RatchetKey: gap.RatchetKey, N: gap.N, Deadline: gap.Deadline}
			if converted.Pending(now) {
				report.Pending = append(report.Pending, converted)
			} else {
				report.ExpiredUnclassified++
			}
		}
		session.Erase()
	}
	sortGaps(report.Pending)
	path := filepath.Join(stateDir, gapLedgerFile)
	raw, err := bounds.ReadBound(path, maxGapLedgerBytes)
	if os.IsNotExist(err) {
		return report, nil
	}
	if err != nil {
		return report, err
	}
	ledger, err := decodeGapLedger(protector, raw)
	if err != nil {
		return report, err
	}
	report.Lost = append([]MessageGap(nil), ledger.Lost...)
	report.LostTotal = ledger.LostTotal
	report.LostTruncated = ledger.LostTruncated
	return report, nil
}

// noteLost records confirmed losses in the endpoint ledger.
func (e *DurableEndpoint) noteLost(gaps []MessageGap) {
	if len(gaps) == 0 {
		return
	}
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	known := make(map[string]bool, len(e.lostGaps))
	for _, g := range e.lostGaps {
		known[gapIdentity(g)] = true
	}
	for _, g := range gaps {
		identity := gapIdentity(g)
		if known[identity] {
			continue
		}
		known[identity] = true
		if e.lostTotal < maxRecordedLosses {
			e.lostTotal++
		}
		if len(e.lostGaps) < maxRecordedLosses {
			e.lostGaps = append(e.lostGaps, g)
		} else {
			e.lostTrunc = true
		}
	}
}

func (e *DurableEndpoint) persistGapLedgerIfNeeded() error {
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	return e.persistGapLedgerLocked()
}

func (e *DurableEndpoint) hasLossPersistenceError() bool {
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	return e.lossPersistenceErr != ""
}

func (e *DurableEndpoint) setLossPersistenceError(err error) {
	e.lossMu.Lock()
	defer e.lossMu.Unlock()
	if err == nil {
		e.lossPersistenceErr = ""
		return
	}
	e.lossPersistenceErr = err.Error()
}

// Gaps reports what this endpoint is currently missing.
//
// LostTotal is cumulative for the lifetime of the process: a swept gap is
// deleted from the session and cannot be enumerated a second time, so the
// counter — not Lost — is the authoritative "how many messages never arrived".
func (e *DurableEndpoint) Gaps() GapReport {
	e.lossMu.Lock()
	r := GapReport{
		Lost:                 append([]MessageGap(nil), e.lostGaps...),
		LostTotal:            e.lostTotal,
		LostTruncated:        e.lostTrunc,
		LossPersistenceError: e.lossPersistenceErr,
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
