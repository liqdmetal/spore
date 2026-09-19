package continuity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/notify"
)

func TestWatchOutboxSyntheticWebhookMetadataOnly(t *testing.T) {
	v, _, _ := testChainAnchor(t)
	observerPriv, _, err := NewObserverKey()
	if err != nil {
		t.Fatal(err)
	}
	now := v.Checkins[len(v.Checkins)-1].Deadline
	var payload map[string]any
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d, err := notify.New(notify.Options{WebhookURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	outboxPath := filepath.Join(t.TempDir(), "notify.jsonl")
	o, err := notify.NewOutbox(outboxPath, d, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	state, err := NewWatchState(v, observerPriv)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := Observe(v, observerPriv, now)
	if err != nil {
		t.Fatal(err)
	}
	id := WatchEventID(state)
	if err := o.Enqueue(notify.Event{TxID: id, Subject: "Spore continuity release-ready", Received: time.Unix(now, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkNotificationQueued(observerPriv, notice, now); err != nil {
		t.Fatal(err)
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls)
	}
	if payload["txid"] != id || payload["subject"] != "Spore continuity release-ready" {
		t.Fatalf("unexpected metadata payload: %#v", payload)
	}
	if _, ok := payload["plaintext"]; ok {
		t.Fatal("webhook payload has plaintext")
	}
	if _, ok := payload["body"]; ok {
		t.Fatal("webhook payload has body")
	}
	if b, err := os.ReadFile(outboxPath); err != nil {
		t.Fatal(err)
	} else if len(b) != 0 {
		t.Fatalf("delivered outbox not compacted: %q", b)
	}
}
