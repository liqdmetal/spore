package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutboxRetriesAndPersistsOnlyMetadata(t *testing.T) {
	var calls atomic.Int32
	firstRequest := make(chan struct{})
	secondRequest := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	var secondOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(firstRequest)
			<-releaseFirst
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		secondOnce.Do(func() { close(secondRequest) })
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notify.outbox.jsonl")
	o, err := NewOutbox(path, d, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	t.Cleanup(release)
	if err := o.Enqueue(Event{TxID: "cid-123", Subject: "Spore private message"}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-firstRequest:
	case <-time.After(2 * time.Second):
		t.Fatal("outbox did not start delivery")
	}
	// Hold the first request open so the worker cannot compact the queue while
	// the test verifies its durable, metadata-only representation.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatalf("decode persisted metadata: %v", err)
	}
	if len(fields) != 3 || string(fields["TxID"]) != `"cid-123"` || string(fields["Subject"]) != `"Spore private message"` {
		t.Fatalf("unexpected persisted event fields: %s", b)
	}
	release()

	select {
	case <-secondRequest:
	case <-time.After(2 * time.Second):
		t.Fatalf("outbox did not retry, calls=%d", calls.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := o.Flush(ctx); err != nil {
		t.Fatalf("flush delivered event: %v", err)
	}
	b, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(b))) != 0 {
		t.Fatalf("delivered event remained queued: %q", b)
	}
}

func TestOutboxRetainsFailedEventAcrossRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer server.Close()
	d, err := New(Options{WebhookURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "notify.outbox.jsonl")
	o, err := NewOutbox(path, d, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(Event{TxID: "cid-keep"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "cid-keep") {
		t.Fatalf("failed event was not durable: %q", b)
	}
}
