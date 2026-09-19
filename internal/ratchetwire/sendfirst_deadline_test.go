package ratchetwire

import (
	"testing"
	"time"
)

// TestDurableSendFirstWithUntruncatedDeadline reproduces a bug that made
// `spore msg send-e2` fail from the CLI while every test passed.
//
// DurableEndpoint.SendFirst read the frame it had just stored back out of the
// body store (to learn the session id) and passed
// `deadline.Add(-time.Nanosecond)` as "now" to FetchFrame. FetchFrame rejects
// when now.Unix() >= pointer.BurnDeadline, and PutBody truncates the stored
// deadline to whole seconds.
//
// With a TRUNCATED deadline (what every existing test uses:
// now.Truncate(time.Second)), deadline has zero nanoseconds, so subtracting
// one nanosecond rolls back a full second and the check passes.
//
// With an UNTRUNCATED deadline (what the CLI produces: time.Now().Add(ttl),
// nanoseconds intact), subtracting one nanosecond stays inside the same
// second, so now.Unix() == BurnDeadline and FetchFrame returns ErrExpired.
// The send fails after the body was already stored — the worst outcome, since
// it looks like a store/expiry problem rather than a read-back hack.
func TestDurableSendFirstWithUntruncatedDeadline(t *testing.T) {
	st := newAdversarialBodyStore()
	bundle, aliceID, bobID, _ := adversarialFixture(t)
	key := filled(12)
	as, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(st, as, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Deliberately UNTRUNCATED — exactly what the CLI passes.
	deadline := time.Now().Add(24 * time.Hour)
	if deadline.Nanosecond() == 0 {
		// Astronomically unlikely; force it so the test is deterministic
		// rather than accidentally passing like the truncated-time tests did.
		deadline = deadline.Add(time.Nanosecond)
	}

	_, _, err = alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("real CLI send"), deadline)
	if err != nil {
		t.Fatalf("SendFirst with an untruncated deadline failed: %v", err)
	}

	// The session must be durably persisted, which is the whole point of the
	// read-back: without it, reply-e2 cannot continue the conversation.
	if ids := alice.Sessions.IDs(); len(ids) != 1 {
		t.Fatalf("sessions after SendFirst = %d, want 1", len(ids))
	}
	as2, err := NewFileStateStore(as.dir, key)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := as2.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("persisted sessions = %d, want 1 (SendFirst must durably save the initiator session)", len(stored))
	}
}
