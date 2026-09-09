package maildb

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestContactUpsertAndLookup(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertContact(Contact{Address: "dero1alice", Nickname: "Alice", Pinned: "aabb"}); err != nil {
		t.Fatal(err)
	}
	c, ok := db.Contact("dero1alice")
	if !ok || c.Nickname != "Alice" || c.Pinned != "aabb" {
		t.Fatalf("contact = %+v", c)
	}
	// Upsert with empty pinned preserves the existing pin (TOFU continuity).
	if err := db.UpsertContact(Contact{Address: "dero1alice", Nickname: "Alice2"}); err != nil {
		t.Fatal(err)
	}
	c, _ = db.Contact("dero1alice")
	if c.Pinned != "aabb" {
		t.Fatalf("pin was dropped: %+v", c)
	}
}

func TestAllowlistBlocklist(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(filepath.Join(dir, "mail.json"))
	// Unknown addresses allowed by default (blocklist semantics).
	if !db.Allowed("dero1unknown") {
		t.Fatal("unknown should be allowed by default")
	}
	// Blocked contact denied.
	_ = db.UpsertContact(Contact{Address: "dero1spam", Blocked: true})
	if db.Allowed("dero1spam") {
		t.Fatal("blocked contact allowed")
	}
	// Allowlist-only mode: unknown denied.
	db.SetAllowOnly(true)
	if db.Allowed("dero1unknown") {
		t.Fatal("unknown allowed in allowlist-only mode")
	}
	_ = db.UpsertContact(Contact{Address: "dero1friend"})
	if !db.Allowed("dero1friend") {
		t.Fatal("known contact denied in allowlist-only mode")
	}
}

func TestPurgeRemovesOldMessagesAndEmptyThreads(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	// Thread A: one old, one recent message.
	if err := db.RecordMessage("threadA", "peerA", "tx1", old, []byte("old body")); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordMessage("threadA", "peerA", "tx2", now, []byte("recent body")); err != nil {
		t.Fatal(err)
	}
	// Thread B: only old messages — must vanish entirely.
	if err := db.RecordMessage("threadB", "peerB", "tx3", old, []byte("gone soon")); err != nil {
		t.Fatal(err)
	}
	n, err := db.Purge(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("purged = %d, want 2", n)
	}
	msgs := db.Messages()
	if len(msgs) != 1 || msgs[0].TxID != "tx2" {
		t.Fatalf("messages after purge = %+v", msgs)
	}
	threads := db.Threads()
	if len(threads) != 1 || threads[0].SessionID != "threadA" || threads[0].Count != 1 {
		t.Fatalf("threads after purge = %+v", threads)
	}
	// Purge survives reopen (persisted, not in-memory only).
	db2, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(db2.Messages()) != 1 || len(db2.Threads()) != 1 {
		t.Fatalf("purge did not persist: msgs=%d threads=%d", len(db2.Messages()), len(db2.Threads()))
	}
	// Nothing to purge -> zero, no error.
	n, err = db2.Purge(now.Add(-24 * time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("second purge = %d, %v", n, err)
	}
}

func TestRecordMessageThreadAndSearch(t *testing.T) {
	dir := t.TempDir()
	db, _ := Open(filepath.Join(dir, "mail.json"))
	now := time.Now()
	if err := db.RecordMessage("abcd", "dero1alice", "tx1", now, []byte("meet at the dock at noon")); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordMessage("abcd", "dero1alice", "tx2", now.Add(time.Second), []byte("bring the invoice")); err != nil {
		t.Fatal(err)
	}
	// Thread grouped + counted.
	threads := db.Threads()
	if len(threads) != 1 || threads[0].SessionID != "abcd" || threads[0].Count != 2 {
		t.Fatalf("threads = %+v", threads)
	}
	// Search hits (simple AND query).
	if got := db.SearchSimple("invoice"); len(got) != 1 {
		t.Fatalf("search invoice = %+v", got)
	}
	if got := db.SearchSimple("DOCK"); len(got) != 1 {
		t.Fatalf("search DOCK = %+v", got)
	}
	if got := db.SearchSimple("nonexistent"); len(got) != 0 {
		t.Fatalf("search nonexistent = %+v", got)
	}
	// AND: both terms must match.
	if got := db.Search(SearchQuery{All: []string{"dock", "noon"}}); len(got) != 1 {
		t.Fatalf("search dock+noon = %+v", got)
	}
	if got := db.Search(SearchQuery{All: []string{"dock", "invoice"}}); len(got) != 0 {
		t.Fatalf("search dock+invoice should be empty = %+v", got)
	}
	// Phrase.
	if got := db.Search(SearchQuery{Phrase: "at the dock"}); len(got) != 1 {
		t.Fatalf("search phrase = %+v", got)
	}
	// NOT.
	if got := db.Search(SearchQuery{Not: []string{"invoice"}}); len(got) != 1 {
		t.Fatalf("search not-invoice = %+v", got)
	}
	// Scope by peer.
	if got := db.Search(SearchQuery{Peer: "dero1alice"}); len(got) != 2 {
		t.Fatalf("search peer = %+v", got)
	}
	if got := db.Search(SearchQuery{Peer: "dero1nobody"}); len(got) != 0 {
		t.Fatalf("search wrong peer = %+v", got)
	}
	// Highlight marks only the matched term.
	hl := db.Highlight("meet at the dock at noon", []string{"dock"})
	if hl != "meet at the \x1edock\x1f at noon" {
		t.Fatalf("highlight = %q", hl)
	}
	// Persistence: reopen and confirm everything survived.
	db2, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(db2.Threads()) != 1 || len(db2.Messages()) != 2 {
		t.Fatalf("after reopen threads=%d messages=%d", len(db2.Threads()), len(db2.Messages()))
	}
	// File perms: 0600 on POSIX; Windows reports 0666 regardless (the
	// restrictive mode is still requested — see the mailbox prekey tests).
	fi, err := os.Stat(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 && fi.Mode().Perm() != 0666 {
		t.Fatalf("mail.json perms = %v, want 0600 (or Windows 0666)", fi.Mode().Perm())
	}
}
