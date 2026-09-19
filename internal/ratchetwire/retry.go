package ratchetwire

import (
	"fmt"
	"sort"
	"time"
)

// Retry queue: recovering a body we already know the address of.
//
// Two failures look similar and are not:
//
//	BODY FETCH FAILED   we saw the chain pointer (route/CID/deadline) but the
//	                    content-addressed body was not retrievable — the
//	                    mailbox was briefly down, the sender had not pushed
//	                    the body yet, or the network blipped. The CID is
//	                    KNOWN, so this is genuinely retryable.
//
//	CHAIN POINTER MISSING   a ratchet gap: no pointer ever arrived, so the CID
//	                    is unknown and nothing local can recover it. Only the
//	                    sender can re-post (see the loss ledger in loss.go).
//
// This queue handles the first case only. It is deliberately not a substitute
// for the second: retrying cannot invent an address we never learned.
//
// Backoff is deterministic (no jitter) so behaviour is reproducible in tests
// and an operator can reason about load. Retrying stops at the pointer's burn
// deadline: past that the store is entitled to have reaped the body, and the
// message is a confirmed loss.

const (
	// retryBaseDelay is the wait before the first retry.
	retryBaseDelay = 5 * time.Second
	// retryMaxDelay caps the backoff so a long-lived queue still polls.
	retryMaxDelay = 5 * time.Minute
	// DefaultRetryQueueCap bounds memory. When full, Add refuses new entries
	// rather than silently evicting one — the caller reports the refusal.
	DefaultRetryQueueCap = 512
)

// PendingFetch is one body this endpoint has the address for but not the bytes.
type PendingFetch struct {
	// Pointer is the chain pointer that named this body: Route, CID, deadline.
	Pointer Pointer
	// Sender and TxID are for reporting; they are not used to fetch.
	Sender string
	TxID   string
	// FirstSeen is when the pointer was first observed.
	FirstSeen time.Time
	// Attempts counts failed fetches so far.
	Attempts int
	// NextAttempt is when this entry becomes due again.
	NextAttempt time.Time
	// LastErr is the most recent fetch error, for operator diagnosis.
	LastErr string
}

// Deadline reports the pointer's burn deadline as a time.
func (p PendingFetch) Deadline() time.Time {
	return time.Unix(int64(p.Pointer.BurnDeadline), 0)
}

// RetryDelay returns the backoff after n failed attempts: base doubling to a
// cap. A non-positive n is treated as zero attempts.
func RetryDelay(attempts int) time.Duration {
	if attempts <= 0 {
		return retryBaseDelay
	}
	d := retryBaseDelay
	for i := 0; i < attempts; i++ {
		if d >= retryMaxDelay {
			return retryMaxDelay
		}
		d *= 2
	}
	if d > retryMaxDelay {
		return retryMaxDelay
	}
	return d
}

// RetryQueue holds bodies awaiting re-fetch, keyed by CID so the same body is
// never queued twice.
type RetryQueue struct {
	items map[[32]byte]*PendingFetch
	cap   int
}

// NewRetryQueue builds a queue bounded to capacity entries. A non-positive
// capacity uses DefaultRetryQueueCap.
func NewRetryQueue(capacity int) *RetryQueue {
	if capacity <= 0 {
		capacity = DefaultRetryQueueCap
	}
	return &RetryQueue{items: map[[32]byte]*PendingFetch{}, cap: capacity}
}

// Len is the number of bodies awaiting retry.
func (q *RetryQueue) Len() int { return len(q.items) }

// Cap is the configured bound.
func (q *RetryQueue) Cap() int { return q.cap }

// Add queues a body for retry. Re-adding a known CID refreshes nothing — the
// existing entry keeps its attempt count and schedule, because the point of the
// backoff is to stop a persistently-failing body from being hammered.
//
// Returns false when the queue is full; the caller must surface that rather
// than assume the body will be retried.
func (q *RetryQueue) Add(p Pointer, sender, txID string, now time.Time) bool {
	if p.CID == ([32]byte{}) {
		return false
	}
	if _, ok := q.items[p.CID]; ok {
		return true
	}
	if len(q.items) >= q.cap {
		return false
	}
	q.items[p.CID] = &PendingFetch{
		Pointer:     p,
		Sender:      sender,
		TxID:        txID,
		FirstSeen:   now,
		NextAttempt: now.Add(RetryDelay(0)),
	}
	return true
}

// Due returns the entries whose next attempt has arrived, oldest first, with a
// stable order so two runs against the same state retry the same way.
func (q *RetryQueue) Due(now time.Time) []PendingFetch {
	var out []PendingFetch
	for _, it := range q.items {
		if !it.NextAttempt.After(now) {
			out = append(out, *it)
		}
	}
	sortFetches(out)
	return out
}

// Record notes a failed attempt at cid and schedules the next one. A cid that
// is not queued is ignored.
func (q *RetryQueue) Record(cid [32]byte, now time.Time, err error) {
	it, ok := q.items[cid]
	if !ok {
		return
	}
	it.Attempts++
	it.NextAttempt = now.Add(RetryDelay(it.Attempts))
	if err != nil {
		it.LastErr = err.Error()
	}
}

// Resolve removes a body that was fetched successfully (or otherwise settled).
// Returns whether it had been queued.
func (q *RetryQueue) Resolve(cid [32]byte) bool {
	if _, ok := q.items[cid]; !ok {
		return false
	}
	delete(q.items, cid)
	return true
}

// Expired removes and returns entries whose pointer deadline has passed. Past
// that instant the store is entitled to have reaped the body and the ratchet
// key may also have been swept, so these are confirmed losses — report them,
// do not retry them.
func (q *RetryQueue) Expired(now time.Time) []PendingFetch {
	var out []PendingFetch
	for cid, it := range q.items {
		if it.Pointer.Expired(now) {
			out = append(out, *it)
			delete(q.items, cid)
		}
	}
	sortFetches(out)
	return out
}

// Snapshot returns every queued entry in a stable order (for status/reporting).
func (q *RetryQueue) Snapshot() []PendingFetch {
	out := make([]PendingFetch, 0, len(q.items))
	for _, it := range q.items {
		out = append(out, *it)
	}
	sortFetches(out)
	return out
}

// sortFetches orders by first-seen then CID, so the oldest trouble surfaces
// first and repeated reads agree.
func sortFetches(fs []PendingFetch) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if !a.FirstSeen.Equal(b.FirstSeen) {
			return a.FirstSeen.Before(b.FirstSeen)
		}
		return string(a.Pointer.CID[:]) < string(b.Pointer.CID[:])
	})
}

// String renders one entry for operator output.
func (p PendingFetch) String() string {
	return fmt.Sprintf("cid=%x… attempts=%d next=%s last_err=%q",
		p.Pointer.CID[:4], p.Attempts, p.NextAttempt.Format(time.RFC3339), p.LastErr)
}

// NoteFetchFailure records a failed body fetch for later retry, combining the
// enqueue and the attempt record so callers cannot do one without the other.
//
// Returns false only when the queue is full — the caller must surface that
// rather than assume the body will be retried.
func (q *RetryQueue) NoteFetchFailure(p Pointer, sender, txID string, now time.Time, err error) bool {
	if q == nil {
		return false
	}
	if !q.Add(p, sender, txID, now) {
		return false
	}
	q.Record(p.CID, now, err)
	return true
}
