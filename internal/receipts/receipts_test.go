package receipts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendListRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := Append(path, Record{At: 100, Session: "abc", Peer: "dero1x", Direction: "sent", Kind: "invoice", InvoiceID: "inv-1", Asset: "dero", Atomic: 2_500_000, TxID: "tx1"}); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, Record{At: 200, Session: "abc", Peer: "dero1x", Direction: "received", Kind: "payment", InvoiceID: "inv-1", Asset: "dero", Atomic: 2_500_000, TxID: "tx2"}); err != nil {
		t.Fatal(err)
	}
	// a corrupt line must not break the ledger
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("not-json\n")
	_ = f.Close()

	all, err := List(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 records, got %d", len(all))
	}
	if all[0].TxID != "tx2" {
		t.Fatalf("newest-first violated: %+v", all[0])
	}
	bySession, err := List(path, "ABC") // case-insensitive filter
	if err != nil {
		t.Fatal(err)
	}
	if len(bySession) != 2 {
		t.Fatalf("session filter: want 2, got %d", len(bySession))
	}
	none, _ := List(path, "zzz")
	if len(none) != 0 {
		t.Fatalf("unmatched session returned records")
	}
	// missing file = empty, not an error
	empty, err := List(filepath.Join(t.TempDir(), "nope.jsonl"), "")
	if err != nil || len(empty) != 0 {
		t.Fatalf("missing file: err=%v n=%d", err, len(empty))
	}
}
