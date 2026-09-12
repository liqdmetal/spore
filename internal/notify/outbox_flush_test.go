package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutboxFlushAttemptsDurableEventBeforeClose(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	o, err := NewOutbox(path, d, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(Event{TxID: "flush-id", Subject: "Spore continuity release-ready"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls.Load())
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
}
