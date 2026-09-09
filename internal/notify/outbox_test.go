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

func TestOutboxRetriesAndPersistsOnlyMetadata(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if calls.Load() == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

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
	defer o.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("outbox did not retry, calls=%d", calls.Load())
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, _ := os.ReadFile(path)
	t.Fatalf("delivered event remained queued: %q", b)
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
