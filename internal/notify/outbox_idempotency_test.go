package notify

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxSuppressesDuplicatePendingEventIDs(t *testing.T) {
	d, err := New(Options{})
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
	if len(o.pending) != 1 {
		t.Fatalf("pending events = %d, want 1", len(o.pending))
	}
}
