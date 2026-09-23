package maildb

import (
	"path/filepath"
	"testing"
	"time"
)

// TestSearchUsesIndexAfterReopen is the regression guard for the headline
// gap: Open never rebuilt the inverted index, so after a restart search ran
// against an empty index. With the index wired into Search, results must be
// identical before and after a reopen.
func TestSearchUsesIndexAfterReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.json")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	msgs := []struct {
		tid, peer, body string
		offset          time.Duration
	}{
		{"tx1", "dero1alice", "meet at the usual place, bring the thing", 0},
		{"tx2", "dero1bob", "meeting moved to thursday", time.Minute},
		{"tx3", "dero1alice", "the warehouse delivery is confirmed", 2 * time.Minute},
	}
	for _, m := range msgs {
		if err := db.RecordMessage("sess"+m.tid, m.peer, m.tid, base.Add(m.offset), []byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	before := db.Search(SearchQuery{All: []string{"meet"}})
	if len(before) != 2 {
		t.Fatalf("pre-reopen: want 2 hits for 'meet', got %d", len(before))
	}

	db2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	after := db2.Search(SearchQuery{All: []string{"meet"}})
	if len(after) != len(before) {
		t.Fatalf("post-reopen: want %d hits for 'meet', got %d", len(before), len(after))
	}
	for i := range after {
		if after[i].TxID != before[i].TxID {
			t.Fatalf("post-reopen hit %d = %s, want %s", i, after[i].TxID, before[i].TxID)
		}
	}
	// Scope fields survive too.
	alice := db2.Search(SearchQuery{Peer: "dero1alice"})
	if len(alice) != 2 {
		t.Fatalf("post-reopen peer scope: want 2, got %d", len(alice))
	}
}

// TestSearchSubstringSemanticsPreserved pins the contract that the index
// prefilter must not change match semantics: every query shape must return
// exactly what a pure linear scan returns, including substring matches
// ("meet" matching "meeting") that whole-token lookups would miss.
func TestSearchSubstringSemanticsPreserved(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	bodies := []string{
		"meet at the dock at dawn",
		"meeting postponed until the morning",
		"cargo manifest attached below",
		"the morning shift starts early",
		"bring the manifest to the meeting",
	}
	for i, b := range bodies {
		tid := "tx" + string(rune('a'+i))
		if err := db.RecordMessage("sess"+tid, "dero1p", tid, base.Add(time.Duration(i)*time.Minute), []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	queries := []SearchQuery{
		{All: []string{"meet"}},                                          // substring inside a longer token
		{All: []string{"the", "meeting"}},                                // mixed whole + substring
		{AnyOf: []string{"dock", "cargo"}},                               // OR group
		{All: []string{"morning"}, Not: []string{"postponed"}},           // AND + NOT
		{AnyOf: []string{"manifest", "dock"}, Not: []string{"attached"}}, // OR + NOT
		{Phrase: "at the dock"},                                          // phrase only
		{All: []string{"meet"}, Phrase: "dawn"},                          // AND + phrase
		{Peer: "dero1p"},                                                 // scope only (no terms)
		{All: []string{"nonexistent"}},                                   // empty result path
	}
	for qi, q := range queries {
		want := []MessageMeta{}
		for _, mm := range db.Messages() { // Messages() is a copy, newest first
			if matchesQuery(mm, q) {
				want = append(want, mm)
			}
		}
		got := db.Search(q)
		if len(got) != len(want) {
			t.Fatalf("query %d: got %d hits, want %d", qi, len(got), len(want))
		}
		for i := range got {
			if got[i].TxID != want[i].TxID {
				t.Fatalf("query %d hit %d = %s, want %s", qi, i, got[i].TxID, want[i].TxID)
			}
		}
	}
}

// TestPurgeKeepsSearchCorrect guards the index/rebuild contract: Purge
// compacts m.messages positionally, so a stale append-only index would
// misalign candidates against the wrong snippets and silently corrupt
// search results.
func TestPurgeKeepsSearchCorrect(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Order matters: the keeper's snippet must NOT appear at the purged
	// message's index position after compaction.
	if err := db.RecordMessage("s1", "dero1p", "txOld", now.Add(-96*time.Hour), []byte("zebra umbrella")); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordMessage("s1", "dero1p", "txKeep", now.Add(-time.Hour), []byte("harbor lantern")); err != nil {
		t.Fatal(err)
	}
	n, err := db.Purge(now.Add(-72 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	hits := db.Search(SearchQuery{All: []string{"lantern"}})
	if len(hits) != 1 || hits[0].TxID != "txKeep" {
		t.Fatalf("post-purge search corrupted: %+v", hits)
	}
	if got := db.Search(SearchQuery{All: []string{"zebra"}}); len(got) != 0 {
		t.Fatalf("purged message resurrected by search: %+v", got)
	}
}

// TestPositionsContaining is the primitive-level check: it must find terms
// embedded inside longer tokens ("meet" ⊂ "meeting") and union positions
// across OR terms, while returning nothing for absent terms.
func TestPositionsContaining(t *testing.T) {
	idx := NewInvertedIndex(0)
	idx.Add("t1", "p", 1, "meeting postponed")
	idx.Add("t2", "p", 2, "cargo manifest")
	idx.Add("t3", "p", 3, "dawn patrol")
	got := idx.PositionsContaining([]string{"meet", "cargo"})
	if len(got) != 2 {
		t.Fatalf("want positions {0,1}, got %v", got)
	}
	if _, ok := got[0]; !ok {
		t.Fatal("position 0 missing (meet ⊂ meeting)")
	}
	if _, ok := got[1]; !ok {
		t.Fatal("position 1 missing (cargo exact)")
	}
	if got := idx.PositionsContaining([]string{"zebra"}); len(got) != 0 {
		t.Fatalf("absent term returned hits: %v", got)
	}
	if got := idx.PositionsContaining(nil); len(got) != 0 {
		t.Fatalf("empty terms returned hits: %v", got)
	}
}
