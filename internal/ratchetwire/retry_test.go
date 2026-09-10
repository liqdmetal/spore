package ratchetwire

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

// togglableStore lets a test make a body temporarily unfetchable, which is the
// realistic failure the retry queue exists for (mailbox briefly down, or the
// sender has not pushed the body yet).
type togglableStore struct {
	*adversarialBodyStore
	unavailable map[[32]byte]bool
}

func newTogglableStore() *togglableStore {
	return &togglableStore{
		adversarialBodyStore: newAdversarialBodyStore(),
		unavailable:          map[[32]byte]bool{},
	}
}

func (s *togglableStore) Get(cid [32]byte) ([]byte, error) {
	if s.unavailable[cid] {
		return nil, errors.New("store: temporarily unavailable")
	}
	return s.adversarialBodyStore.Get(cid)
}

func (s *togglableStore) setUnavailable(cid [32]byte, v bool) {
	if v {
		s.unavailable[cid] = true
		return
	}
	delete(s.unavailable, cid)
}

// ---- backoff ----

// TestRetryDelayDoublesAndCaps pins the schedule and, critically, that a huge
// attempt count cannot overflow into a negative or zero delay (which would
// turn the backoff into a hot loop).
func TestRetryDelayDoublesAndCaps(t *testing.T) {
	if got := RetryDelay(0); got != retryBaseDelay {
		t.Fatalf("RetryDelay(0) = %v, want %v", got, retryBaseDelay)
	}
	if got := RetryDelay(-5); got != retryBaseDelay {
		t.Fatalf("RetryDelay(negative) = %v, want %v", got, retryBaseDelay)
	}
	if got := RetryDelay(1); got != 2*retryBaseDelay {
		t.Fatalf("RetryDelay(1) = %v, want %v", got, 2*retryBaseDelay)
	}
	if got := RetryDelay(3); got != 8*retryBaseDelay {
		t.Fatalf("RetryDelay(3) = %v, want %v", got, 8*retryBaseDelay)
	}
	if got := RetryDelay(100); got != retryMaxDelay {
		t.Fatalf("RetryDelay(100) = %v, want the cap %v", got, retryMaxDelay)
	}
	// Overflow guard: must stay positive and capped.
	for _, n := range []int{1 << 10, 1 << 20, 1 << 30} {
		got := RetryDelay(n)
		if got <= 0 || got > retryMaxDelay {
			t.Fatalf("RetryDelay(%d) = %v — out of range", n, got)
		}
	}
}

// ---- queue mechanics ----

func newTestPointer(n byte, deadline time.Time) Pointer {
	var cid [32]byte
	for i := range cid {
		cid[i] = n
	}
	var route [32]byte
	for i := range route {
		route[i] = n ^ 0xff
	}
	return Pointer{Route: route, CID: cid, BurnDeadline: uint64(deadline.Unix())}
}

func TestRetryQueueAddDedupesByCID(t *testing.T) {
	q := NewRetryQueue(4)
	now := time.Now()
	p := newTestPointer(1, now.Add(time.Hour))

	if !q.Add(p, "alice", "tx1", now) {
		t.Fatal("first add refused")
	}
	// Same CID again keeps the original entry and its schedule.
	later := now.Add(time.Minute)
	if !q.Add(p, "alice", "tx1", later) {
		t.Fatal("duplicate add refused")
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after a duplicate add", q.Len())
	}
	if got := q.Snapshot()[0].FirstSeen; !got.Equal(now) {
		t.Fatalf("duplicate add reset FirstSeen to %v, want %v", got, now)
	}
}

// TestRetryQueueRefusesWhenFull: the queue must refuse rather than silently
// evict, because an evicted body would never be retried and the caller would
// never know.
func TestRetryQueueRefusesWhenFull(t *testing.T) {
	q := NewRetryQueue(2)
	now := time.Now()
	deadline := now.Add(time.Hour)

	if !q.Add(newTestPointer(1, deadline), "a", "t1", now) {
		t.Fatal("add 1 refused")
	}
	if !q.Add(newTestPointer(2, deadline), "a", "t2", now) {
		t.Fatal("add 2 refused")
	}
	if q.Add(newTestPointer(3, deadline), "a", "t3", now) {
		t.Fatal("add 3 accepted past the cap")
	}
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (nothing evicted)", q.Len())
	}
	// Re-adding a known CID is still fine at capacity.
	if !q.Add(newTestPointer(1, deadline), "a", "t1", now) {
		t.Fatal("re-adding a known CID was refused at capacity")
	}
}

func TestRetryQueueRejectsZeroCID(t *testing.T) {
	q := NewRetryQueue(4)
	if q.Add(Pointer{}, "a", "t", time.Now()) {
		t.Fatal("accepted a zero CID")
	}
	if q.Len() != 0 {
		t.Fatalf("Len = %d after a zero-CID add", q.Len())
	}
}

// TestRetryQueueDueRespectsBackoff: a freshly queued body is not due until the
// first backoff elapses, and the order is stable.
func TestRetryQueueDueRespectsBackoff(t *testing.T) {
	q := NewRetryQueue(4)
	now := time.Now()
	deadline := now.Add(time.Hour)
	q.Add(newTestPointer(1, deadline), "a", "t1", now)
	q.Add(newTestPointer(2, deadline), "a", "t2", now.Add(time.Second))

	if due := q.Due(now); len(due) != 0 {
		t.Fatalf("Due(now) = %d entries, want 0 (backoff not elapsed)", len(due))
	}
	at := now.Add(retryBaseDelay)
	due := q.Due(at)
	if len(due) != 1 || due[0].Pointer.CID[0] != 1 {
		t.Fatalf("Due(base delay) = %#v, want only the first entry", due)
	}
	// Both become due once the later one's delay has also elapsed.
	due = q.Due(at.Add(time.Second))
	if len(due) != 2 {
		t.Fatalf("Due = %d entries, want 2", len(due))
	}
	// Stable ordering across calls.
	again := q.Due(at.Add(time.Second))
	if len(again) != 2 || again[0].Pointer.CID[0] != 1 || again[1].Pointer.CID[0] != 2 {
		t.Fatalf("Due order unstable: %#v", again)
	}
}

func TestRetryQueueRecordReschedulesAndCounts(t *testing.T) {
	q := NewRetryQueue(4)
	now := time.Now()
	p := newTestPointer(1, now.Add(time.Hour))
	q.Add(p, "a", "t1", now)

	at := now.Add(retryBaseDelay)
	q.Record(p.CID, at, errors.New("boom"))
	it := q.Snapshot()[0]
	if it.Attempts != 1 {
		t.Fatalf("Attempts = %d, want 1", it.Attempts)
	}
	if want := at.Add(RetryDelay(1)); !it.NextAttempt.Equal(want) {
		t.Fatalf("NextAttempt = %v, want %v", it.NextAttempt, want)
	}
	if it.LastErr != "boom" {
		t.Fatalf("LastErr = %q", it.LastErr)
	}
	// A second failure doubles the wait again.
	q.Record(p.CID, at, errors.New("boom again"))
	if got := q.Snapshot()[0].NextAttempt; !got.Equal(at.Add(RetryDelay(2))) {
		t.Fatalf("second NextAttempt = %v, want %v", got, at.Add(RetryDelay(2)))
	}
	// Recording an unknown CID is a no-op, not a panic.
	q.Record([32]byte{0xaa}, at, errors.New("x"))
}

func TestRetryQueueResolveRemoves(t *testing.T) {
	q := NewRetryQueue(4)
	now := time.Now()
	p := newTestPointer(1, now.Add(time.Hour))
	q.Add(p, "a", "t1", now)

	if !q.Resolve(p.CID) {
		t.Fatal("Resolve of a queued CID reported not found")
	}
	if q.Len() != 0 {
		t.Fatalf("Len = %d after resolve", q.Len())
	}
	if q.Resolve(p.CID) {
		t.Fatal("Resolve of an unknown CID reported found")
	}
}

// TestRetryQueueExpiredEvictsPastDeadline: past the pointer deadline the store
// is entitled to have reaped the body, so the entry is a confirmed loss and
// must leave the queue (never be retried forever).
func TestRetryQueueExpiredEvictsPastDeadline(t *testing.T) {
	q := NewRetryQueue(4)
	now := time.Now()
	live := newTestPointer(1, now.Add(time.Hour))
	dead := newTestPointer(2, now.Add(time.Minute))
	q.Add(live, "a", "t1", now)
	q.Add(dead, "a", "t2", now)

	if got := q.Expired(now); len(got) != 0 {
		t.Fatalf("Expired(now) = %#v, want none", got)
	}
	got := q.Expired(now.Add(2 * time.Minute))
	if len(got) != 1 || got[0].Pointer.CID[0] != 2 {
		t.Fatalf("Expired = %#v, want only the past-deadline entry", got)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1 remaining", q.Len())
	}
	// Idempotent: the eviction does not repeat.
	if again := q.Expired(now.Add(3 * time.Minute)); len(again) != 0 {
		t.Fatalf("Expired repeated: %#v", again)
	}
}

func TestRetryQueueNoteFetchFailure(t *testing.T) {
	now := time.Now()
	p := newTestPointer(1, now.Add(time.Hour))
	err := errors.New("unavailable")

	q := NewRetryQueue(4)
	if !q.NoteFetchFailure(p, "alice", "tx1", now, err) {
		t.Fatal("NoteFetchFailure refused")
	}
	it := q.Snapshot()[0]
	if it.Attempts != 1 || it.Sender != "alice" || it.TxID != "tx1" {
		t.Fatalf("entry = %#v", it)
	}
	if it.LastErr != err.Error() {
		t.Fatalf("LastErr = %q, want %q", it.LastErr, err.Error())
	}

	// A nil queue is tolerated so callers need no nil check.
	var nilQ *RetryQueue
	if nilQ.NoteFetchFailure(p, "a", "t", now, err) {
		t.Fatal("nil queue reported success")
	}
}

func TestNewRetryQueueDefaultsCapacity(t *testing.T) {
	if got := NewRetryQueue(0).Cap(); got != DefaultRetryQueueCap {
		t.Fatalf("Cap = %d, want the default %d", got, DefaultRetryQueueCap)
	}
	if got := NewRetryQueue(-1).Cap(); got != DefaultRetryQueueCap {
		t.Fatalf("negative capacity = %d, want the default", got)
	}
	if got := NewRetryQueue(7).Cap(); got != 7 {
		t.Fatalf("Cap = %d, want 7", got)
	}
}

// ---- end to end ----

// TestRetryRecoversMessageOnceBodyAppears is the point of the feature: a body
// that was not fetchable when the pointer arrived is delivered on a later
// attempt, without the sender doing anything.
func TestRetryRecoversMessageOnceBodyAppears(t *testing.T) {
	st := newTogglableStore()
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	key := filled(9)
	now := time.Now()

	aliceStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(st, aliceStates, now)
	if err != nil {
		t.Fatal(err)
	}
	bobStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(st, bobStates, now)
	if err != nil {
		t.Fatal(err)
	}

	deadline := now.Add(time.Hour)
	bobSPK := filled(3)
	initPtr, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("hello"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := FetchFrame(st, initPtr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := initFrame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReceiveFirst(bobID, bobSPK, opk, initFrame, raw); err != nil {
		t.Fatal(err)
	}

	ids := alice.Sessions.IDs()
	nextPtr, _, err := alice.SendNext(ids[0], []byte("the payload that was not there yet"), deadline)
	if err != nil {
		t.Fatal(err)
	}

	// The body is not fetchable yet.
	st.setUnavailable(nextPtr.CID, true)
	q := NewRetryQueue(8)

	if _, err := bob.ReceiveNext(nextPtr, now); err == nil {
		t.Fatal("received a message whose body was unavailable")
	}
	if !q.NoteFetchFailure(nextPtr, "alice", "tx1", now, errors.New("store: temporarily unavailable")) {
		t.Fatal("failed fetch was not queued")
	}
	if q.Len() != 1 {
		t.Fatalf("queue length = %d, want 1", q.Len())
	}

	// The body shows up, but a retry before the backoff elapses must not fire.
	st.setUnavailable(nextPtr.CID, false)
	if due := q.Due(now); len(due) != 0 {
		t.Fatalf("retry fired before the backoff elapsed: %#v", due)
	}

	// Once due, the retry delivers the message and clears the queue.
	at := now.Add(RetryDelay(1))
	due := q.Due(at)
	if len(due) != 1 {
		t.Fatalf("Due = %d entries, want 1", len(due))
	}
	plain, err := bob.ReceiveNext(due[0].Pointer, at)
	if err != nil {
		t.Fatalf("retry failed to deliver: %v", err)
	}
	if !bytes.Equal(plain, []byte("the payload that was not there yet")) {
		t.Fatalf("recovered plaintext = %q", plain)
	}
	if !q.Resolve(due[0].Pointer.CID) {
		t.Fatal("resolved entry was not in the queue")
	}
	if q.Len() != 0 {
		t.Fatalf("queue length = %d after recovery, want 0", q.Len())
	}
}

// TestRetryClosesARatchetGap connects the two mechanisms: a message that was
// skipped (because a later one arrived first) is recovered by retrying its
// body, which is what actually closes the gap the loss ledger reported.
func TestRetryClosesARatchetGap(t *testing.T) {
	st := newTogglableStore()
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	key := filled(9)
	now := time.Now()

	aliceStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(st, aliceStates, now)
	if err != nil {
		t.Fatal(err)
	}
	bobStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(st, bobStates, now)
	if err != nil {
		t.Fatal(err)
	}

	deadline := now.Add(time.Hour)
	bobSPK := filled(3)
	initPtr, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("zero"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	initFrame, err := FetchFrame(st, initPtr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := initFrame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReceiveFirst(bobID, bobSPK, opk, initFrame, raw); err != nil {
		t.Fatal(err)
	}

	ids := alice.Sessions.IDs()
	missingPtr, _, err := alice.SendNext(ids[0], []byte("the one that got skipped"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	thirdPtr, _, err := alice.SendNext(ids[0], []byte("the one that arrived"), deadline)
	if err != nil {
		t.Fatal(err)
	}

	// Third arrives, second does not: the ratchet records a gap.
	if _, err := bob.ReceiveNext(thirdPtr, now); err != nil {
		t.Fatal(err)
	}
	gaps := bob.Gaps()
	if len(gaps.Pending) != 1 || gaps.Pending[0].N != 1 {
		t.Fatalf("pending gaps = %#v, want message 1", gaps.Pending)
	}

	// Retry the missing body; success must close the gap.
	q := NewRetryQueue(8)
	st.setUnavailable(missingPtr.CID, true)
	if _, err := bob.ReceiveNext(missingPtr, now); err == nil {
		t.Fatal("received a message whose body was unavailable")
	}
	if !q.NoteFetchFailure(missingPtr, "alice", "tx2", now, errors.New("unavailable")) {
		t.Fatal("failed fetch was not queued")
	}

	st.setUnavailable(missingPtr.CID, false)
	at := now.Add(RetryDelay(1))
	due := q.Due(at)
	if len(due) != 1 {
		t.Fatalf("Due = %d, want 1", len(due))
	}
	plain, err := bob.ReceiveNext(due[0].Pointer, at)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if !bytes.Equal(plain, []byte("the one that got skipped")) {
		t.Fatalf("recovered plaintext = %q", plain)
	}

	q.Resolve(due[0].Pointer.CID)
	if after := bob.Gaps(); len(after.Pending) != 0 {
		t.Fatalf("gap survived recovery: %#v", after.Pending)
	}
}

// TestFetchIncomingE2ReturnsPointerOnFetchFailure pins the contract the retry
// queue depends on: an unavailable body must NOT discard the known address.
func TestFetchIncomingE2ReturnsPointerOnFetchFailure(t *testing.T) {
	st := newTogglableStore()
	deadline := time.Now().Add(time.Hour)
	ptr := newTestPointer(7, deadline)

	codec := CanonicalChainCodec{}
	payload, err := codec.EncodePointer(PointerPayload{
		Version: PointerV1, Route: ptr.Route, CID: ptr.CID, BurnDeadline: ptr.BurnDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := ChainCarrier{Chain: &adversarialCarrier{}, Codec: codec}

	st.setUnavailable(ptr.CID, true)
	_, got, err := c.FetchIncomingE2(st, chain.Incoming{TxID: "tx-1", Payload: payload}, time.Now())
	if err == nil {
		t.Fatal("fetch of an unavailable body reported success")
	}
	if got.CID != ptr.CID || got.Route != ptr.Route {
		t.Fatalf("pointer discarded on fetch failure: got %#v, want CID %x", got, ptr.CID[:4])
	}
}

// TestRetryReconstructsTheOriginalPointer pins the invariant retryDue depends
// on: a queued Pointer can be re-encoded into a chain payload and decoded back
// to the SAME pointer. If this drifting, a retry would fetch the wrong body —
// or silently never succeed — and nothing else would notice.
func TestRetryReconstructsTheOriginalPointer(t *testing.T) {
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	original := newTestPointer(9, deadline)
	codec := CanonicalChainCodec{}

	// What retryDue does with a queue entry.
	payload, err := codec.EncodePointer(PointerPayload{
		Version:      PointerV1,
		Route:        original.Route,
		CID:          original.CID,
		BurnDeadline: original.BurnDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := ChainCarrier{Chain: &adversarialCarrier{}, Codec: codec}
	got, err := c.DecodeIncomingE2(chain.Incoming{TxID: "tx", Payload: payload})
	if err != nil {
		t.Fatalf("reconstructed pointer did not decode: %v", err)
	}
	if got != original {
		t.Fatalf("reconstructed pointer drifted:\n got  %#v\n want %#v", got, original)
	}
}

// TestRetryQueueSurvivesPointerDeadlineBoundary: a body whose deadline is
// still in the future at retry time must remain retryable; Expired must not
// claim it early.
func TestRetryQueueSurvivesPointerDeadlineBoundary(t *testing.T) {
	now := time.Now()
	// Deadline comfortably beyond the first backoff, so the entry is live
	// when its first retry comes due.
	p := newTestPointer(3, now.Add(time.Hour))
	q := NewRetryQueue(4)
	if !q.Add(p, "a", "t", now) {
		t.Fatal("add refused")
	}
	at := now.Add(retryBaseDelay)
	if got := q.Expired(at); len(got) != 0 {
		t.Fatalf("expired a body that is still live: %#v", got)
	}
	if due := q.Due(at); len(due) != 1 {
		t.Fatalf("Due = %d, want 1 (still retryable)", len(due))
	}

	// A body whose deadline falls BEFORE its first retry is correctly
	// abandoned rather than retried: the store may already have reaped it.
	q2 := NewRetryQueue(4)
	p2 := newTestPointer(4, now.Add(time.Second))
	if !q2.Add(p2, "a", "t", now) {
		t.Fatal("add refused")
	}
	if got := q2.Expired(at); len(got) != 1 {
		t.Fatalf("a past-deadline body was not abandoned: %#v", got)
	}
	if due := q2.Due(at); len(due) != 0 {
		t.Fatalf("abandoned body was still due: %#v", due)
	}
}
