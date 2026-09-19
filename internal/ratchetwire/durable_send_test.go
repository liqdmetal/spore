package ratchetwire

import (
	"testing"
	"time"
)

// TestDurableSendFirstSessionPersists is a regression guard for a real bug
// caught only by a live multi-device run.
//
// DurableEndpoint embeds *Endpoint, so a caller that wanted the new session id
// and called SendFirstSession got the PROMOTED Endpoint method: it compiled,
// the send returned a txid, and the session was never written to the state
// store. The failure surfaced later and elsewhere as "unknown session" on a
// continuation, long after the send looked successful.
//
// The guard is the store, not the return value: the session id that comes back
// must be loadable from the store afterwards, or the send was not durable.
func TestDurableSendFirstSessionPersists(t *testing.T) {
	store := newAdversarialBodyStore()
	bundle, aliceID, bobID, _ := adversarialFixture(t)
	key := filled(9)
	now := time.Now().Truncate(time.Second)
	deadline := now.Add(time.Hour)

	states, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(store, states, now)
	if err != nil {
		t.Fatal(err)
	}

	_, _, sessID, err := alice.SendFirstSession(aliceID, bundle, mustSig(t, bobID), []byte("durable?"), deadline)
	if err != nil {
		t.Fatal(err)
	}
	if sessID == ([8]byte{}) {
		t.Fatal("SendFirstSession returned a zero session id")
	}

	// The actual assertion: is it on disk?
	if _, err := states.Load(sessID); err != nil {
		t.Fatalf("session %x was not persisted by SendFirstSession: %v", sessID, err)
	}

	// And is it usable? A continuation must find it. This is the shape the
	// live failure took.
	if _, _, err := alice.SendNext(sessID, []byte("continuation"), deadline); err != nil {
		t.Fatalf("continuation on the just-sent session failed: %v", err)
	}
}

// TestDurableSendFirstStillReturnsTwoValues pins the older API: SendFirst must
// keep working for callers that do not need the id, and must still persist.
func TestDurableSendFirstStillReturnsTwoValues(t *testing.T) {
	store := newAdversarialBodyStore()
	bundle, aliceID, bobID, _ := adversarialFixture(t)
	now := time.Now().Truncate(time.Second)
	states, err := NewFileStateStore(t.TempDir(), filled(4))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(store, states, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("still durable"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ids, err := states.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("SendFirst persisted %d sessions, want 1", len(ids))
	}
}
