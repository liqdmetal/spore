package notify

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxSuppressesDuplicatePendingEventIDs(t *testing.T) {
	// A webhook that always fails keeps the events pending: this test pins
	// ENQUEUE-time dedup (a repeated TxID is suppressed at Enqueue), which
	// is only observable while delivery is failing. The original no-op
	// dispatcher made the race detector fire on CI: Send succeeds, the
	// drain worker removes the event (outbox.go post-dispatch), and that
	// write raced the test's unsynchronized read of o.pending — and a
	// quiescing Close would then assert an empty queue. Failing delivery
	// holds the queue stable under the outbox's at-least-once contract.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d, err := New(Options{WebhookURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOutbox(filepath.Join(t.TempDir(), "outbox.jsonl"), d, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	e := Event{TxID: "stable-event", Subject: "Spore continuity release-ready"}
	if err := o.Enqueue(e); err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(Event{TxID: e.TxID, Subject: "different duplicate subject"}); err != nil {
		t.Fatal(err)
	}
	// Quiesce the drain worker before inspecting internal state: Close joins
	// the goroutine (wg.Wait), so the read below is race-free by
	// happens-before, not by luck of scheduling. Delivery failing keeps the
	// event queued, so the count is deterministic under any schedule.
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if len(o.pending) != 1 {
		t.Fatalf("pending events = %d, want 1", len(o.pending))
	}
}
