package ratchet

import (
	"fmt"
	"testing"
	"time"
)

// TestOutstandingReportsRecoverableGap covers the latency half of the
// classification: a message whose ciphertext has not arrived YET is pending,
// not lost, and still decrypts when it finally turns up.
func TestOutstandingReportsRecoverableGap(t *testing.T) {
	p := establishPair(t, true)
	m0, err := p.alice.Encrypt([]byte("zero"))
	if err != nil {
		t.Fatal(err)
	}
	m1, err := p.alice.Encrypt([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := p.alice.Encrypt([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Hour)
	if _, err := p.bob.DecryptWithDeadline(m0, deadline); err != nil {
		t.Fatal(err)
	}
	// Deliver the third message, skipping the second.
	if _, err := p.bob.DecryptWithDeadline(m2, deadline); err != nil {
		t.Fatal(err)
	}

	out := p.bob.Outstanding()
	if len(out) != 1 {
		t.Fatalf("outstanding = %#v, want exactly one gap", out)
	}
	if out[0].N != 1 {
		t.Fatalf("gap numbered %d, want 1", out[0].N)
	}
	if !out[0].Deadline.Equal(deadline) {
		t.Fatalf("gap did not inherit the message deadline: got %v want %v", out[0].Deadline, deadline)
	}
	if !out[0].Pending(time.Now()) {
		t.Fatal("a gap inside its deadline must be pending, not lost")
	}

	// The late message must still decrypt: that is what makes it a gap in
	// delivery rather than a gap in the conversation.
	if _, err := p.bob.DecryptWithDeadline(m1, deadline); err != nil {
		t.Fatalf("pending gap failed to recover: %v", err)
	}
	if out := p.bob.Outstanding(); len(out) != 0 {
		t.Fatalf("outstanding after recovery = %#v, want empty", out)
	}
}

// TestSweptGapIsLostAndUnrecoverable is the load-bearing test for the whole
// loss model. Claiming a message is "lost" is only meaningful if it is
// genuinely undecryptable afterwards — so this asserts the negative, using the
// ciphertext we still hold.
func TestSweptGapIsLostAndUnrecoverable(t *testing.T) {
	p := establishPair(t, true)
	m0, err := p.alice.Encrypt([]byte("zero"))
	if err != nil {
		t.Fatal(err)
	}
	m1, err := p.alice.Encrypt([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := p.alice.Encrypt([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(30 * time.Second)
	if _, err := p.bob.DecryptWithDeadline(m0, deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.DecryptWithDeadline(m2, deadline); err != nil {
		t.Fatal(err)
	}

	// Before the deadline: nothing is swept and the gap stays recoverable.
	if swept := p.bob.SweepSkippedDetailed(time.Now()); len(swept) != 0 {
		t.Fatalf("swept a gap that has not expired: %#v", swept)
	}
	if n := len(p.bob.Outstanding()); n != 1 {
		t.Fatalf("outstanding = %d, want 1 before expiry", n)
	}

	// Past the deadline the key is gone and the message is lost.
	swept := p.bob.SweepSkippedDetailed(deadline.Add(time.Second))
	if len(swept) != 1 || swept[0].N != 1 {
		t.Fatalf("swept = %#v, want exactly message 1", swept)
	}
	if n := len(p.bob.Outstanding()); n != 0 {
		t.Fatalf("outstanding = %d after sweep, want 0", n)
	}

	// THE CLAIM: a confirmed loss cannot be recovered, even by the holder of
	// the original ciphertext. Forward secrecy deletes the key permanently.
	if _, err := p.bob.DecryptWithDeadline(m1, deadline); err == nil {
		t.Fatal("a confirmed-lost message decrypted — 'lost' does not mean unrecoverable")
	}

	// Sweeping again must not re-report the same loss.
	if again := p.bob.SweepSkippedDetailed(deadline.Add(time.Hour)); len(again) != 0 {
		t.Fatalf("the same loss was counted twice: %#v", again)
	}
}

// TestInOrderStreamReportsNoGaps is the false-positive guard: a clean,
// in-order conversation must report nothing at all.
func TestInOrderStreamReportsNoGaps(t *testing.T) {
	p := establishPair(t, true)
	deadline := time.Now().Add(time.Hour)
	for i := 0; i < 6; i++ {
		m, err := p.alice.Encrypt([]byte(fmt.Sprintf("message %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.bob.DecryptWithDeadline(m, deadline); err != nil {
			t.Fatalf("in-order message %d failed: %v", i, err)
		}
	}
	if out := p.bob.Outstanding(); len(out) != 0 {
		t.Fatalf("clean stream reported gaps: %#v", out)
	}
	if swept := p.bob.SweepSkippedDetailed(deadline.Add(time.Hour)); len(swept) != 0 {
		t.Fatalf("clean stream reported losses: %#v", swept)
	}
}

// TestLossRecordsCarryExactChainAndNumber checks that each gap is attributed to
// the right chain and message number, so a report can be acted on.
func TestLossRecordsCarryExactChainAndNumber(t *testing.T) {
	p := establishPair(t, true)
	msgs := make([]Message, 5)
	for i := range msgs {
		m, err := p.alice.Encrypt([]byte(fmt.Sprintf("message %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		msgs[i] = m
	}

	deadline := time.Now().Add(time.Hour)
	// Deliver the first and the last, leaving 1, 2, 3 outstanding.
	if _, err := p.bob.DecryptWithDeadline(msgs[0], deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.DecryptWithDeadline(msgs[4], deadline); err != nil {
		t.Fatal(err)
	}

	out := p.bob.Outstanding()
	if len(out) != 3 {
		t.Fatalf("outstanding = %#v, want 3 gaps", out)
	}
	for i, rec := range out {
		want := uint32(i + 1)
		if rec.N != want {
			t.Fatalf("gap %d numbered %d, want %d", i, rec.N, want)
		}
		if rec.RatchetKey != msgs[0].Header.DHPub {
			t.Fatalf("gap %d attributed to the wrong chain", i)
		}
	}
	// Deterministic order, so repeated reports agree.
	again := p.bob.Outstanding()
	for i := range out {
		if out[i] != again[i] {
			t.Fatalf("outstanding order is not stable at %d", i)
		}
	}
}

// TestZeroDeadlineGapsNeverSweep pins the documented exception: an unbounded
// message has no deadline to inherit, so it is bounded by the hard caps rather
// than swept. Such a gap stays recoverable forever.
func TestZeroDeadlineGapsNeverSweep(t *testing.T) {
	p := establishPair(t, true)
	m0, err := p.alice.Encrypt([]byte("zero"))
	if err != nil {
		t.Fatal(err)
	}
	m1, err := p.alice.Encrypt([]byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := p.alice.Encrypt([]byte("two"))
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt (not DecryptWithDeadline) leaves the skipped key with no deadline.
	if _, err := p.bob.Decrypt(m0); err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.Decrypt(m2); err != nil {
		t.Fatal(err)
	}

	out := p.bob.Outstanding()
	if len(out) != 1 {
		t.Fatalf("outstanding = %#v, want 1", out)
	}
	if !out[0].Deadline.IsZero() {
		t.Fatalf("expected no inherited deadline, got %v", out[0].Deadline)
	}
	if swept := p.bob.SweepSkippedDetailed(time.Now().Add(1000 * time.Hour)); len(swept) != 0 {
		t.Fatalf("a deadline-less gap was swept: %#v", swept)
	}
	if _, err := p.bob.Decrypt(m1); err != nil {
		t.Fatalf("deadline-less gap did not recover: %v", err)
	}
}
