package ratchetwire

import (
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// lossFixture builds a sender/receiver endpoint pair over a shared in-memory
// body store, then sends three messages on ONE session and returns the sender,
// receiver, and the three pointers.
func lossFixture(t *testing.T, deadline time.Time) (*DurableEndpoint, *DurableEndpoint, []Pointer, []byte, []byte) {
	t.Helper()
	body := newAdversarialBodyStore()
	bundle, aliceID, bobID, _ := adversarialFixture(t)
	key := filled(9)
	now := time.Now()

	aliceStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(body, aliceStates, now)
	if err != nil {
		t.Fatal(err)
	}
	bobStates, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(body, bobStates, now)
	if err != nil {
		t.Fatal(err)
	}

	bobSPK := filled(3)
	bobSig := mustSig(t, bobID)
	ptrs := make([]Pointer, 3)
	ptrs[0], _, err = alice.SendFirst(aliceID, bundle, bobSig, []byte("message 0"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	ids := alice.Sessions.IDs()
	if len(ids) != 1 {
		t.Fatalf("sender sessions = %d, want 1", len(ids))
	}
	ptrs[1], _, err = alice.SendNext(ids[0], []byte("message 1"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	ptrs[2], _, err = alice.SendNext(ids[0], []byte("message 2"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, ptrs, bobID, bobSPK
}

// receiveFirst fetches and decrypts an init frame for the receiver.
func receiveFirst(t *testing.T, bob *DurableEndpoint, st BodyStore, ptr Pointer, bobID, bobSPK []byte) {
	t.Helper()
	frame, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var opk [32]byte
	copy(opk[:], filled(4))
	if _, err := bob.ReceiveFirst(bobID, bobSPK, &opk, frame, raw); err != nil {
		t.Fatal(err)
	}
}

// TestEndpointReportsPendingGapBeforeDeadline covers the recoverable half:
// before the deadline the endpoint must report a PENDING gap and must not
// record any loss.
func TestEndpointReportsPendingGapBeforeDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	_, bob, ptrs, bobID, bobSPK := lossFixture(t, deadline)

	if r := bob.Gaps(); !r.Empty() {
		t.Fatalf("fresh endpoint reported gaps: %#v", r)
	}
	receiveFirst(t, bob, bob.Store, ptrs[0], bobID, bobSPK)
	// Deliver the third, skipping the second.
	if _, err := bob.ReceiveNext(ptrs[2], time.Now()); err != nil {
		t.Fatal(err)
	}

	r := bob.Gaps()
	if len(r.Pending) != 1 || r.Pending[0].N != 1 {
		t.Fatalf("pending = %#v, want exactly message 1", r.Pending)
	}
	if r.LostTotal != 0 {
		t.Fatalf("LostTotal = %d before the deadline, want 0", r.LostTotal)
	}
	if !r.Pending[0].Pending(time.Now()) {
		t.Fatal("gap inside its deadline reported as not pending")
	}

	// The late message still arrives: a pending gap is recoverable in full.
	if _, err := bob.ReceiveNext(ptrs[1], time.Now()); err != nil {
		t.Fatalf("pending gap failed to recover: %v", err)
	}
	if r := bob.Gaps(); !r.Empty() {
		t.Fatalf("gaps remained after recovery: %#v", r)
	}
}

// TestEndpointRecordsConfirmedLossAfterExpiry covers the terminal half: once
// the deadline passes, Expire must record a confirmed loss, the gap must leave
// the pending set, and the message must be undecryptable afterwards.
func TestEndpointRecordsConfirmedLossAfterExpiry(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second)
	_, bob, ptrs, bobID, bobSPK := lossFixture(t, deadline)

	receiveFirst(t, bob, bob.Store, ptrs[0], bobID, bobSPK)
	if _, err := bob.ReceiveNext(ptrs[2], time.Now()); err != nil {
		t.Fatal(err)
	}

	// Expiring before the deadline must not count a loss.
	if n := bob.Expire(time.Now()); n != 0 {
		t.Fatalf("Expire before the deadline removed %d, want 0", n)
	}
	if r := bob.Gaps(); r.LostTotal != 0 || len(r.Pending) != 1 {
		t.Fatalf("pre-deadline state wrong: %#v", r)
	}

	// Past the deadline the gap is a confirmed, counted loss.
	if n := bob.Expire(deadline.Add(time.Second)); n != 1 {
		t.Fatalf("Expire after the deadline removed %d, want 1", n)
	}
	r := bob.Gaps()
	if r.LostTotal != 1 {
		t.Fatalf("LostTotal = %d, want 1", r.LostTotal)
	}
	if len(r.Lost) != 1 || r.Lost[0].N != 1 {
		t.Fatalf("lost = %#v, want exactly message 1", r.Lost)
	}
	if len(r.Pending) != 0 {
		t.Fatalf("lost gap still listed as pending: %#v", r.Pending)
	}
	if r.LostTruncated {
		t.Fatal("a single loss must not report truncation")
	}

	// The claim, at endpoint level: the message is gone for good.
	if _, err := bob.ReceiveNext(ptrs[1], time.Now()); err == nil {
		t.Fatal("a confirmed-lost message was still delivered")
	}

	// Idempotent: expiring again must not double-count.
	if n := bob.Expire(deadline.Add(time.Hour)); n != 0 {
		t.Fatalf("Expire double-counted: removed %d", n)
	}
	if r := bob.Gaps(); r.LostTotal != 1 {
		t.Fatalf("LostTotal drifted to %d after a second Expire", r.LostTotal)
	}
}

// TestSessionTableSweepGapsMatchesCountOnlySweep confirms the reporting form
// and the count-only form agree, so existing callers that only need a number
// cannot silently diverge from the ledger.
func TestSessionTableSweepGapsMatchesCountOnlySweep(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second)
	_, bob, ptrs, bobID, bobSPK := lossFixture(t, deadline)
	receiveFirst(t, bob, bob.Store, ptrs[0], bobID, bobSPK)
	if _, err := bob.ReceiveNext(ptrs[2], time.Now()); err != nil {
		t.Fatal(err)
	}

	expired := deadline.Add(time.Second)
	gaps := bob.Sessions.SweepGaps(expired)
	if len(gaps) != 1 || gaps[0].N != 1 {
		t.Fatalf("SweepGaps = %#v, want one gap at n=1", gaps)
	}
	if n := bob.Sessions.Sweep(expired); n != 0 {
		t.Fatalf("Sweep returned %d after SweepGaps already drained, want 0", n)
	}
	// And the outstanding view is now empty.
	if out := bob.Sessions.Outstanding(); len(out) != 0 {
		t.Fatalf("Outstanding = %#v after sweep", out)
	}
}

// TestGapsAcrossSessionsStayAttributed checks a gap is never reported against
// the wrong session when an endpoint holds more than one conversation.
func TestGapsAcrossSessionsStayAttributed(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	_, bob, ptrs, bobID, bobSPK := lossFixture(t, deadline)
	receiveFirst(t, bob, bob.Store, ptrs[0], bobID, bobSPK)
	if _, err := bob.ReceiveNext(ptrs[2], time.Now()); err != nil {
		t.Fatal(err)
	}

	r := bob.Gaps()
	if len(r.Pending) != 1 {
		t.Fatalf("pending = %#v", r.Pending)
	}
	// Exactly one session exists, and the gap must name it.
	ids := bob.Sessions.IDs()
	if len(ids) != 1 {
		t.Fatalf("sessions = %d, want 1", len(ids))
	}
	if r.Pending[0].SessionID != ids[0] {
		t.Fatalf("gap attributed to %x, session is %x", r.Pending[0].SessionID, ids[0])
	}
}

// TestLossLedgerIsBoundedButCounterExact proves the cap protects memory without
// lying about the count.
func TestLossLedgerIsBoundedButCounterExact(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	_, bob, _, _, _ := lossFixture(t, deadline)

	// Feed the ledger more losses than it will enumerate.
	over := maxRecordedLosses + 10
	batch := make([]MessageGap, over)
	for i := range batch {
		batch[i] = MessageGap{N: uint32(i), Deadline: deadline}
	}
	bob.noteLost(batch)

	total := bob.LostCount()
	if total != uint64(over) {
		t.Fatalf("LostCount = %d, want %d (the counter must stay exact)", total, over)
	}
	r := bob.Gaps()
	if len(r.Lost) != maxRecordedLosses {
		t.Fatalf("enumerated losses = %d, want the cap of %d", len(r.Lost), maxRecordedLosses)
	}
	if !r.LostTruncated {
		t.Fatal("truncation was not reported — the view claims to be complete")
	}
}

// TestRatchetLossRecordPendingBoundary pins the exact comparison: a gap is
// pending while its deadline is strictly in the future.
func TestRatchetLossRecordPendingBoundary(t *testing.T) {
	now := time.Now()
	if (ratchet.LossRecord{Deadline: now}).Pending(now) {
		t.Fatal("a gap at its deadline must not be pending")
	}
	if !(ratchet.LossRecord{Deadline: now.Add(time.Second)}).Pending(now) {
		t.Fatal("a gap before its deadline must be pending")
	}
	if !(ratchet.LossRecord{}).Pending(now) {
		t.Fatal("a gap with no deadline never expires and must be pending")
	}
}
