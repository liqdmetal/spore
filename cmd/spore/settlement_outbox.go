package main

// The durable settlement-notice outbox.
//
// The settlement commands (escrow claim/refund, dex swap/wrap/unwrap) are
// money-first: the contract call moves the money, THEN the in-thread notice
// rides the ratcheted session (SendNext + pointer post). When that notice
// fails — a body-store outage, a refused pointer post — the money has already
// moved and the counterparty has no in-thread record of it. That is the exact
// failure window the settlement E2E failure-injection tests pin. This outbox
// closes it: the notice is durably queued and re-announced by the NEXT
// settlement command run over the same state-dir.
//
// Retry semantics, deliberately:
//
//   - The flush runs at the START of a settlement command, on the SAME
//     endpoint instance the command's own notice will use, so the caller's
//     in-memory ratchet state and the persisted state stay one and the same.
//     Queued notices keep their ratchet position: per session, the receiver's
//     history-order ingest sees exactly the order the sender produced.
//   - A queued claim entry replays the SAME preimage-bearing body byte for
//     byte. The claim itself only succeeds once and the HTLC is settled by
//     then, so re-revealing the preimage is harmless — the secret is spent.
//   - The queue is deduped by kind+txid: the settlement tx is the identity,
//     so a double enqueue can never double-send.
//   - Queueing/flush failures are loud (stderr) but NEVER fatal: the money
//     already moved, and a hard exit here would hide a successful settlement
//     behind a storage error. A failed enqueue prints "NOTICE LOST" so the
//     loss is at least visible.
//
// The queue file defaults to <state-dir>/settlement-outbox.json (next to the
// ratchet state it depends on) and is written through the same atomic
// private-file helper the continuity state uses. A missing file is an empty
// queue; a CORRUPT file is an error — silently treating unreadable state as
// empty would drop settlement notices without a trace.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// settlementOutboxEntry is one failed settlement notice awaiting delivery.
type settlementOutboxEntry struct {
	// ID is a random hex id assigned at enqueue (ordering tiebreak).
	ID string `json:"id"`
	// Kind is the settlement operation ("escrow claim", "dex wrap", ...).
	Kind string `json:"kind"`
	// TxID is the on-chain settlement tx the notice reports — the dedupe key.
	TxID string `json:"txid"`
	// To is the counterparty address the pointer is posted to.
	To string `json:"to"`
	// SessionHex is the ratchet session the notice rides.
	SessionHex string `json:"session_hex"`
	// Body is the exact marshaled envelope bytes to announce.
	Body []byte `json:"body"`
	// Attempts counts failed flush attempts so far.
	Attempts int `json:"attempts,omitempty"`
	// LastErr is the most recent announce error, for operator diagnosis.
	LastErr string `json:"last_error,omitempty"`
	// QueuedAt is when the entry was first queued (unix seconds).
	QueuedAt int64 `json:"queued_at_unix"`
}

// noticeOutboxFlag registers the shared -notice-outbox flag on a settlement
// flag set.
func noticeOutboxFlag(fs *flag.FlagSet) {
	fs.String("notice-outbox", "",
		"durable settlement-notice outbox JSON (failed in-thread notices queue here and retry on the next settlement command run; default <state-dir>/settlement-outbox.json)")
}

// noticeOutboxPath returns the -notice-outbox flag value, or the default
// location next to the ratchet state.
func noticeOutboxPath(fs *flag.FlagSet) string {
	if f := fs.Lookup("notice-outbox"); f != nil {
		if v := f.Value.String(); v != "" {
			return v
		}
	}
	return filepath.Join(flagValueOr(fs, "state-dir", "."), "settlement-outbox.json")
}

// loadSettlementOutbox reads the queue. A missing file is an empty queue; a
// corrupt file is an error — silently treating unreadable state as empty
// would drop settlement notices without a trace.
func loadSettlementOutbox(path string) ([]settlementOutboxEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []settlementOutboxEntry
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("settlement notice outbox %s: %w", path, err)
	}
	return out, nil
}

// settlementOutboxPublish is the final step of persisting a queue generation:
// write the bytes to a temp file in the destination directory, fsync, and
// atomically replace the destination. It is a package variable ONLY so the
// crash tests can park a child process at the exact instant between "the new
// generation is durably written" and "the rename makes it live" — and kill
// it there. Production always uses writeAtomicPrivate; nothing else may
// replace this.
var settlementOutboxPublish = writeAtomicPrivate

// saveSettlementOutbox atomically rewrites the queue file; an empty queue
// removes the file, so a fully delivered queue leaves no clutter.
func saveSettlementOutbox(path string, entries []settlementOutboxEntry) error {
	if len(entries) == 0 {
		if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return nil
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return settlementOutboxPublish(path, append(raw, '\n'))
}

// newSettlementEntryID is a random hex id for queue ordering.
func newSettlementEntryID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// enqueueSettlementNotice durably queues one failed notice, deduped by
// kind+txid (the settlement tx is the identity; the same settlement must
// never queue twice). The returned error is for the caller to report —
// queue failures are loud but never fatal.
func enqueueSettlementNotice(path, kind, txid, to, sessionHex string, body []byte) error {
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		return fmt.Errorf("read notice outbox: %w", err)
	}
	for _, e := range entries {
		if e.TxID == txid && e.Kind == kind {
			return nil // already queued; nothing to do
		}
	}
	entries = append(entries, settlementOutboxEntry{
		ID:         newSettlementEntryID(),
		Kind:       kind,
		TxID:       txid,
		To:         to,
		SessionHex: sessionHex,
		Body:       body,
		QueuedAt:   time.Now().Unix(),
	})
	return saveSettlementOutbox(path, entries)
}

// flushSettlementOutbox re-announces every queued notice in queue order,
// each on ITS OWN (to, session) through the SHARED endpoint base carries —
// same sessions table, same carrier, so flushed sends advance the caller's
// in-memory ratchet state exactly like its own sends do — and removes the
// entries that delivered. Per-entry failures are printed and stay queued
// with updated bookkeeping. Returns the number delivered.
func flushSettlementOutbox(path string, entries []settlementOutboxEntry, base *escrowNotice) (int, error) {
	delivered := 0
	remaining := make([]settlementOutboxEntry, 0, len(entries))
	for _, e := range entries {
		var aerr error
		per := *base // shallow copy: shares endpoint + carrier, overrides to/session
		if session, perr := parseSessionID(e.SessionHex); perr != nil {
			aerr = perr
		} else {
			per.to, per.session = e.To, session
			aerr = escrowAnnounce(&per, e.Body)
		}
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "notice retry: settlement %s tx %s still undelivered: %v\n",
				e.Kind, shortTx(e.TxID), aerr)
			e.Attempts++
			e.LastErr = aerr.Error()
			remaining = append(remaining, e)
			continue
		}
		delivered++
		fmt.Printf("notice retry: delivered queued %s tx %s\n", e.Kind, shortTx(e.TxID))
	}
	// Persist only when something changed: an untouched stuck queue is not
	// rewritten (no churn), but any delivery or bookkeeping update is.
	dirty := len(remaining) != len(entries)
	if !dirty {
		for i := range entries {
			if entries[i].Attempts != remaining[i].Attempts || entries[i].LastErr != remaining[i].LastErr {
				dirty = true
				break
			}
		}
	}
	if !dirty {
		return delivered, nil
	}
	if err := saveSettlementOutbox(path, remaining); err != nil {
		return delivered, fmt.Errorf("persist notice outbox: %w", err)
	}
	return delivered, nil
}

// flushPendingSettlementNotices is the flag-wired entry point each settlement
// command calls right after prepareEscrowNotice (so the endpoint and its
// sessions are restored) and BEFORE its own contract call (so queued notices
// keep their ratchet position). Failures are printed, never fatal: the
// settlement the operator asked for must still proceed.
func flushPendingSettlementNotices(fs *flag.FlagSet, notice *escrowNotice) {
	path := noticeOutboxPath(fs)
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notice retry: outbox %s unreadable (%v); queued notices NOT flushed this run\n", path, err)
		return
	}
	if len(entries) == 0 {
		return
	}
	n, err := flushSettlementOutbox(path, entries, notice)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notice retry: %v\n", err)
	}
	if n > 0 {
		fmt.Printf("notice retry: %d queued settlement notice(s) delivered\n", n)
	}
}

// flushPendingSettlementNoticesForEndpoint is the RECEIVER-side flush:
// `msg recv-e2` calls it at startup and on its poll cadence so queued notices
// retry at receive cadence, not only when the sender's next settlement
// command runs — a counterparty who never settles again must still learn of
// the money that already moved. It loads the outbox from the same flag
// surface (default <state-dir>/settlement-outbox.json; the recv-e2 flag set
// need not carry -notice-outbox), announces each entry through the receiver's
// restored durable endpoint, and skips entries whose session this endpoint
// does not own (a state-dir may host sessions the receiver never opened).
//
// Money-first, as everywhere else: failures are printed, never fatal, and
// never block the receive loop for longer than one synchronous announce.
//
// Concurrency note: the sender's settlement commands and this receiver flush
// can run concurrently over the same outbox file (a settlement announced at
// the same moment recv-e2's tick fires). writeAtomicPrivate keeps each save
// whole (no torn reads), but the file is not locked — a lost update could
// requeue an entry one side just delivered, and the duplicate announce is
// harmless (re-ratcheting a duplicate is noise, not corruption) because the
// queue dedupes only by kind+txid within a single file generation. The next
// flush attempt converges on the surviving queue.
func flushPendingSettlementNoticesForEndpoint(fs *flag.FlagSet, ep *ratchetwire.DurableEndpoint, carrier ratchetwire.ChainCarrier) {
	path := noticeOutboxPath(fs)
	entries, err := loadSettlementOutbox(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "notice retry: outbox %s unreadable (%v); queued notices NOT flushed this run\n", path, err)
		return
	}
	if len(entries) == 0 {
		return
	}
	delivered := 0
	dirty := false
	remaining := make([]settlementOutboxEntry, 0, len(entries))
	for _, e := range entries {
		session, perr := parseSessionID(e.SessionHex)
		if perr == nil && ep.Sessions.Get(session) == nil {
			perr = fmt.Errorf("session %s not known to this endpoint", shortTx(e.SessionHex))
		}
		if perr != nil {
			fmt.Fprintf(os.Stderr, "notice retry: settlement %s tx %s skipped (not this endpoint's session): %v\n",
				e.Kind, shortTx(e.TxID), perr)
			continue // leave untouched: NOT retried by this endpoint, NOT persisted
		}
		per := escrowNotice{endpoint: ep, carrier: carrier, to: e.To, session: session}
		aerr := escrowAnnounce(&per, e.Body)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "notice retry: settlement %s tx %s still undelivered: %v\n",
				e.Kind, shortTx(e.TxID), aerr)
			e.Attempts++
			remaining = append(remaining, e)
			dirty = true
			continue
		}
		delivered++
		fmt.Printf("notice retry: delivered queued %s tx %s\n", e.Kind, shortTx(e.TxID))
		dirty = true
	}
	if dirty {
		if err := saveSettlementOutbox(path, remaining); err != nil {
			fmt.Fprintf(os.Stderr, "persist notice outbox: %v\n", err)
		}
	}
	if delivered > 0 {
		fmt.Printf("notice retry: %d queued settlement notice(s) delivered by the receiver\n", delivered)
	}
}

// reportSettlementNoticeWithQueue is reportSettlementNotice plus the durable
// retry: on announce failure the notice body is queued for the next
// settlement command run over the same state-dir. Queueing failure is loud
// (NOTICE LOST) but never fatal — the money already moved.
func reportSettlementNoticeWithQueue(operation, txid, to, sessionHex, outboxPath string, announceErr error, body []byte) {
	if announceErr == nil {
		return
	}
	reportSettlementNotice(operation, txid, announceErr)
	if outboxPath == "" {
		return
	}
	if err := enqueueSettlementNotice(outboxPath, operation, txid, to, sessionHex, body); err != nil {
		fmt.Fprintf(os.Stderr, "%s: settlement tx %s NOTICE LOST: the in-thread notice failed AND queueing for retry failed: %v\n",
			operation, shortTx(txid), err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: settlement tx %s notice queued for retry on the next settlement command run (%s)\n",
		operation, shortTx(txid), outboxPath)
}
