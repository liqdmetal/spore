package mailbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testLogKey(t *testing.T) []byte {
	t.Helper()
	k, err := LogKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestLog(t *testing.T) (*MessageLog, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "messages.log")
	l, err := OpenLog(path, testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}

func msg(txid, text string, receivedAt int64) Message {
	return Message{Kind: "text", TxID: txid, Text: text, ReceivedAt: receivedAt}
}

func TestLogKeyDerivation(t *testing.T) {
	k1, err := LogKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LogKey(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("log key length = %d/%d, want 32/32", len(k1), len(k2))
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different scalars must derive different log keys")
	}
	if _, err := LogKey(make([]byte, 31)); err == nil {
		t.Fatal("short scalar must be rejected")
	}
}

// The core H5 fix, proven at the byte level: the on-disk log must contain NO
// plaintext message content.
func TestLogEncryptedAtRest(t *testing.T) {
	l, path := newTestLog(t)
	secret := "the mail server operator must not read this"
	if err := l.Add(msg("tx-1", secret, time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("plaintext message found in the on-disk log — encryption failed")
	}
	if strings.Contains(string(raw), `"text"`) {
		t.Fatal("raw JSON structure found in the on-disk log")
	}
	// But the logical content round-trips.
	all, err := l.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Text != secret {
		t.Fatalf("round-trip lost the message: %+v", all)
	}
	// And a fresh log instance (restart) decrypts it via the same key.
	l2, err := OpenLog(path, testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	all2, _ := l2.All()
	if len(all2) != 1 || all2[0].Text != secret {
		t.Fatalf("restart lost the message: %+v", all2)
	}
}

// A wrong key must not decrypt lines.
func TestLogWrongKeyCannotRead(t *testing.T) {
	l, path := newTestLog(t)
	if err := l.Add(msg("tx-1", "for the rightful operator", time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	wrong, err := LogKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	l2, err := OpenLog(path, wrong)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := l2.All()
	if len(all) != 0 {
		t.Fatalf("wrong key decrypted %d messages", len(all))
	}
	if l2.CorruptLines() != 1 {
		t.Fatalf("wrong-key lines should count as corrupt, got %d", l2.CorruptLines())
	}
}

// Corrupt (crash-truncated) lines must be SKIPPED, not brick the whole log —
// the old code failed All() wholesale AND silently disabled dedup (audit H5).
func TestLogCorruptLineSkipped(t *testing.T) {
	l, path := newTestLog(t)
	if err := l.Add(msg("tx-1", "before crash", time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-write: a partial (garbage) line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("ZmFrZS1iYXNlNjQtYnV0LW5vdC1hLWNpcGhlcnQ") // truncated, no newline
	f.WriteString("\n")
	f.Close()
	if err := l.Add(msg("tx-2", "after crash", time.Now().Unix())); err != nil {
		t.Fatal(err)
	}

	l2, err := OpenLog(path, testLogKey(t))
	if err != nil {
		t.Fatalf("corrupt line must not brick the log: %v", err)
	}
	all, _ := l2.All()
	if len(all) != 2 || all[0].Text != "before crash" || all[1].Text != "after crash" {
		t.Fatalf("valid messages lost around a corrupt line: %+v", all)
	}
	if l2.CorruptLines() != 1 {
		t.Fatalf("corrupt line not counted: %d", l2.CorruptLines())
	}
	// Dedup still works across the corruption: re-adding tx-1 must not duplicate.
	if err := l2.Add(msg("tx-1", "before crash", time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	all2, _ := l2.All()
	if len(all2) != 2 {
		t.Fatalf("dedup broken after corruption: %d messages", len(all2))
	}
}

// Trim drops messages older than the TTL and re-encrypts legacy plaintext
// lines in the same rewrite (audit H5: rot + migration).
func TestLogTrimDropsRottedAndMigratesLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "messages.log")
	now := time.Now()

	// Pre-seed a LEGACY plaintext JSONL log (old format): one fresh, one old.
	legacy := `{"kind":"text","txid":"legacy-fresh","text":"fresh legacy","received_at":` +
		i64(now.Add(-time.Hour).Unix()) + `}` + "\n" +
		`{"kind":"text","txid":"legacy-old","text":"ancient legacy","received_at":` +
		i64(now.Add(-90*24*time.Hour).Unix()) + `}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLog(path, testLogKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// Add one encrypted message, then trim with a 30-day TTL.
	if err := l.Add(msg("new-1", "brand new", now.Unix())); err != nil {
		t.Fatal(err)
	}
	kept, err := l.Trim(now, DefaultLogTTL)
	if err != nil {
		t.Fatal(err)
	}
	if kept != 2 {
		t.Fatalf("Trim kept %d, want 2 (fresh legacy + new; ancient dropped)", kept)
	}

	// The rewritten log must contain NO plaintext (legacy line re-encrypted).
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "fresh legacy") || strings.Contains(string(raw), "ancient legacy") {
		t.Fatal("legacy plaintext survived the rewrite — Trim must re-encrypt")
	}
	// The rotted message is gone; the survivors are intact.
	all, _ := l.All()
	if len(all) != 2 {
		t.Fatalf("post-trim message count = %d, want 2", len(all))
	}
	for _, m := range all {
		if m.TxID == "legacy-old" {
			t.Fatal("rotted message survived Trim")
		}
	}
	// Dedup survives the rewrite.
	if err := l.Add(msg("legacy-fresh", "fresh legacy", now.Add(-time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	all2, _ := l.All()
	if len(all2) != 2 {
		t.Fatalf("dedup broken after trim: %d messages", len(all2))
	}
}

// The O(1) index: Has must reflect Add without a file rescan, and duplicates
// are never appended.
func TestLogDedupIndex(t *testing.T) {
	l, path := newTestLog(t)
	m := msg("tx-dup", "once only", time.Now().Unix())
	if err := l.Add(m); err != nil {
		t.Fatal(err)
	}
	if !l.Has("tx-dup") {
		t.Fatal("Has(key) false right after Add — index not maintained")
	}
	for i := 0; i < 10; i++ {
		if err := l.Add(m); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	lines := bytes.Count(raw, []byte("\n"))
	if lines != 1 {
		t.Fatalf("log has %d lines after 11 identical Adds, want 1 (dedup must be O(1), not rescan-dependent)", lines)
	}
	if c, _ := l.Count(); c != 1 {
		t.Fatalf("Count = %d, want 1", c)
	}
	// Keyed by CID when TxID is empty (long messages).
	if err := l.Add(Message{Kind: "long", CID: "abc123", Text: "by cid"}); err != nil {
		t.Fatal(err)
	}
	if !l.Has("abc123") {
		t.Fatal("CID delivery key not indexed")
	}
	if err := l.Add(Message{Kind: "long", CID: "abc123", Text: "by cid"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := l.Count(); c != 2 {
		t.Fatalf("Count = %d, want 2 after cid-keyed dedup", c)
	}
}

func TestMailboxTrimLogIntegration(t *testing.T) {
	dir := t.TempDir()
	m, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Inject a stale message directly through the log.
	stale := msg("stale-tx", "ancient", time.Now().Add(-DefaultLogTTL-time.Hour).Unix())
	if err := m.log.Add(stale); err != nil {
		t.Fatal(err)
	}
	fresh := msg("fresh-tx", "recent", time.Now().Unix())
	if err := m.log.Add(fresh); err != nil {
		t.Fatal(err)
	}
	kept, err := m.TrimLog(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Fatalf("TrimLog kept %d, want 1", kept)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].TxID != "fresh-tx" {
		t.Fatalf("post-trim list wrong: %+v", list)
	}
	// The default TTL flows through Open.
	if m.logTTL != DefaultLogTTL {
		t.Fatalf("default log TTL = %v, want %v", m.logTTL, DefaultLogTTL)
	}
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }
