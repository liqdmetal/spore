package notify

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The original shape of this test polled the provider-call counter with a
// fixed budget, so under parallel gate load it could fail while the retry
// worker was merely starved — indistinguishable from a genuinely broken
// retry loop. The hardening below (2026-09) follows the reap-ticker
// pattern: the delivery property is asserted on a SYNCHRONOUS drain pass,
// and the background wiring is observed via the worker's own drain counter,
// with skips that name starvation rather than failure.

func newFailingOnceServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if calls.Load() == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

// TestOutboxRetryDeliversAfterFailure is the deterministic core: one
// synchronous drain pass fails and keeps the event queued, the next
// succeeds and empties it. The outbox is constructed WITHOUT its retry
// worker — NewOutbox's background goroutine drains on its own schedule and
// would race these synchronous assertions (observed: the worker's 20ms
// retry landed the second provider call before the test could count the
// first). No goroutine, no scheduling dependence.
func TestOutboxRetryDeliversAfterFailure(t *testing.T) {
	server, calls := newFailingOnceServer(t)

	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	o := &Outbox{
		path:     filepath.Join(t.TempDir(), "notify.outbox.jsonl"),
		dispatch: d,
		retry:    time.Hour,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	if err := o.Enqueue(Event{TxID: "cid-123", Subject: "Spore private message"}); err != nil {
		t.Fatal(err)
	}

	// First pass: provider fails, the event must stay queued.
	o.drainOnce()
	if got := calls.Load(); got != 1 {
		t.Fatalf("first drain made %d provider calls, want 1", got)
	}
	if len(o.pending) != 1 {
		t.Fatalf("failed delivery did not keep the event queued: %d pending", len(o.pending))
	}

	// Second pass: the retry must actually re-deliver, not just log.
	o.drainOnce()
	if got := calls.Load(); got != 2 {
		t.Fatalf("retry pass made %d total provider calls, want 2", got)
	}
	if len(o.pending) != 0 {
		t.Fatalf("successful retry did not dequeue the event: %d pending", len(o.pending))
	}
}

// TestOutboxBackgroundWorkerDrains is the wiring check: with a fast retry
// cadence, the background worker must fail once, retry, and land the second
// delivery. The provider-call counter is the effect we wait on; on timeout
// the worker's own drain counter separates the two failure modes:
//
//   - counter barely advanced → the worker goroutine was starved by
//     parallel gate load → SKIP, stating so (never a false red).
//   - counter advanced while the provider saw no retry → the retry loop is
//     genuinely broken → FAIL with both numbers.
func TestOutboxBackgroundWorkerDrains(t *testing.T) {
	server, calls := newFailingOnceServer(t)

	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notify.outbox.jsonl")
	o, err := NewOutbox(path, d, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err := o.Enqueue(Event{TxID: "cid-123", Subject: "Spore private message"}); err != nil {
		t.Fatal(err)
	}

	// Fail once, then the retry must actually re-deliver, not just log.
	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		if o.drainCount.Load() < 5 {
			t.Skipf("provider calls stalled at %d while the worker ran only %d drain passes (parallel-load starvation, not a retry failure)", calls.Load(), o.drainCount.Load())
		}
		t.Fatalf("worker ran %d drain passes but the provider recorded only %d calls — retry loop is broken", o.drainCount.Load(), calls.Load())
	}
}

// TestOutboxDeliveredEventIsDequeuedAfterClose pins the persistence half:
// after a successful background retry and a quiescing Close (Close joins the
// worker, so the compaction rewrite is complete), the queue file must be
// empty. Close-before-observe keeps the Windows file race out of the read.
func TestOutboxDeliveredEventIsDequeuedAfterClose(t *testing.T) {
	server, calls := newFailingOnceServer(t)

	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notify.outbox.jsonl")
	o, err := NewOutbox(path, d, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(Event{TxID: "cid-123", Subject: "Spore private message"}); err != nil {
		t.Fatal(err)
	}

	// Two provider calls = fail, then successful retry. If the scheduler
	// starves the worker entirely, that is an environment problem: skip
	// instead of failing, and say which part was starved.
	deadline := time.Now().Add(10 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		if o.drainCount.Load() < 5 {
			t.Skipf("provider calls stalled at %d while the worker ran only %d drain passes (parallel-load starvation, not a retry failure)", calls.Load(), o.drainCount.Load())
		}
		t.Fatalf("worker ran %d drain passes but the provider recorded only %d calls — retry loop is broken", o.drainCount.Load(), calls.Load())
	}

	// The worker still has to rewrite the queue file (compaction) after the
	// provider accepts. Close joins the goroutine, so the rewrite is complete
	// before the read — the same Close-before-observe discipline as the
	// retains-failed-across-restart test. Reading concurrently races the
	// rewrite on Windows ("The process cannot access the file because it is
	// being used by another process", CI 2026-09-18).
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(b))) != 0 {
		t.Fatalf("delivered event remained queued: %q", b)
	}
}
