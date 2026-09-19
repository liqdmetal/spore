package ratchetwire

import (
	"testing"
	"time"
)

// The four existing ratchetwire test files build deadlines from
// `time.Now().Truncate(time.Second)`, which has ZERO nanoseconds. That is not
// what the CLI passes (`time.Now().Add(ttl)`), and the difference hid a real
// bug that made `spore msg send-e2` fail for every real user while the whole
// suite stayed green.
//
// These tests are the guard for that CLASS of bug: they drive the full
// send → receive roundtrip using deadlines that carry nanoseconds, exactly
// like production. If any code path ever re-derives an instant by nudging a
// deadline by sub-second amounts, or compares a truncated stored deadline
// against an untruncated "now", these fail.

// cliDeadline mimics what every cmd/spore send path constructs.
func cliDeadline(ttl time.Duration) time.Time {
	d := time.Now().Add(ttl)
	if d.Nanosecond() == 0 {
		// Astronomically unlikely; force nanoseconds so the test cannot
		// accidentally regress into the truncated case that hid the bug.
		d = d.Add(37 * time.Nanosecond)
	}
	return d
}

// TestFullRoundTripWithCLIShapedDeadlines is the end-to-end production shape:
// Alice sends a first message with an untruncated deadline, Bob (restarted from
// durable state) receives it, then Alice continues the thread and Bob receives
// that too. No deadline anywhere is truncated to a second.
func TestFullRoundTripWithCLIShapedDeadlines(t *testing.T) {
	st := newAdversarialBodyStore()
	bundle, aliceID, bobID, opk := adversarialFixture(t)
	key := filled(13)

	as, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := NewFileStateStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}

	// Untruncated "now" everywhere — this is the production clock.
	alice, err := NewDurableEndpoint(st, as, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewDurableEndpoint(st, bs, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	ptr, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("cli-shaped hello"), cliDeadline(24*time.Hour))
	if err != nil {
		t.Fatalf("SendFirst with CLI-shaped deadline: %v", err)
	}

	// Bob fetches and decrypts using the REAL current time, not a truncated
	// fixture.
	frame, err := FetchFrame(st, ptr, time.Now())
	if err != nil {
		t.Fatalf("FetchFrame at real now: %v", err)
	}
	body, err := GetBody(st, ptr, time.Now())
	if err != nil {
		t.Fatalf("GetBody at real now: %v", err)
	}
	plain, err := bob.ReceiveFirst(bobID, filled(3), opk, frame, body)
	if err != nil || string(plain) != "cli-shaped hello" {
		t.Fatalf("ReceiveFirst: %q, %v", plain, err)
	}

	// Continuation on the same session, same untruncated deadlines.
	next, _, err := alice.SendNext(frame.SessionID, []byte("and a reply"), cliDeadline(24*time.Hour))
	if err != nil {
		t.Fatalf("SendNext with CLI-shaped deadline: %v", err)
	}
	plain, err = bob.ReceiveNext(next, time.Now())
	if err != nil || string(plain) != "and a reply" {
		t.Fatalf("ReceiveNext: %q, %v", plain, err)
	}

	// The session must survive a restart (this is what the deleted read-back
	// was for — proving the id is still persisted correctly without it).
	bob2, err := NewDurableEndpoint(st, bs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	third, _, err := alice.SendNext(frame.SessionID, []byte("after restart"), cliDeadline(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err = bob2.ReceiveNext(third, time.Now()); err != nil || string(plain) != "after restart" {
		t.Fatalf("ReceiveNext after restart: %q, %v", plain, err)
	}
}

// TestSendFirstSucceedsAcrossTheWholeNanosecondRange walks deadlines whose
// nanosecond component spans the second boundary. The original bug only fired
// when the nanosecond part was nonzero, so a single "lucky" clock reading could
// let it pass; this makes the coverage explicit and clock-independent.
func TestSendFirstSucceedsAcrossTheWholeNanosecondRange(t *testing.T) {
	base := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	for _, ns := range []int{0, 1, 500_000_000, 999_999_998, 999_999_999} {
		ns := ns
		t.Run(time.Duration(ns).String(), func(t *testing.T) {
			st := newAdversarialBodyStore()
			bundle, aliceID, bobID, _ := adversarialFixture(t)
			as, err := NewFileStateStore(t.TempDir(), filled(14))
			if err != nil {
				t.Fatal(err)
			}
			alice, err := NewDurableEndpoint(st, as, base)
			if err != nil {
				t.Fatal(err)
			}
			deadline := base.Add(24*time.Hour + time.Duration(ns)*time.Nanosecond)
			if _, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("ns boundary"), deadline); err != nil {
				t.Fatalf("SendFirst with deadline ns=%d failed: %v", ns, err)
			}
		})
	}
}

// TestSendFirstFailureDoesNotLeaveOrphanSession pins the cleanup guarantee: if
// the body store rejects the frame, the just-installed session is erased rather
// than left behind (it would otherwise linger in durable state for a
// conversation that never happened).
func TestSendFirstFailureDoesNotLeaveOrphanSession(t *testing.T) {
	st := &failingPutStore{adversarialBodyStore: newAdversarialBodyStore()}
	bundle, aliceID, bobID, _ := adversarialFixture(t)
	as, err := NewFileStateStore(t.TempDir(), filled(15))
	if err != nil {
		t.Fatal(err)
	}
	alice, err := NewDurableEndpoint(st, as, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := alice.SendFirst(aliceID, bundle, mustSig(t, bobID), []byte("doomed"), cliDeadline(time.Hour)); err == nil {
		t.Fatal("expected the failing store to reject the send")
	}
	if n := len(alice.Sessions.IDs()); n != 0 {
		t.Fatalf("failed SendFirst left %d orphan session(s) installed", n)
	}
	ids, err := as.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("failed SendFirst persisted %d orphan session file(s)", len(ids))
	}
}

// failingPutStore accepts reads but refuses every write, simulating a store
// outage at exactly the worst moment (after the session is installed).
type failingPutStore struct {
	*adversarialBodyStore
}

func (s *failingPutStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	return errStoreDown
}

var errStoreDown = errPut("store down")

type errPut string

func (e errPut) Error() string { return string(e) }
