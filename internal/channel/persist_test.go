package channel

import (
	"testing"
	"time"
)

// TestPersistentBoxSurvivesRestart: post lines, "restart" the box from the same
// dir, confirm the lines + nextSeq came back.
func TestPersistentBoxSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := BoxConfig{LineTTL: time.Hour, PresenceTTL: time.Minute, ReapEvery: time.Hour, MaxLines: 100}

	b, err := NewPersistentBox(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Post("#dao", "alice", false, []byte("motion 1: raise treasury"))
	b.Post("#dao", "bob", false, []byte("seconded"))

	// restart from same dir
	b2, err := NewPersistentBox(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := b2.Poll("#dao", 0)
	if len(lines) != 2 {
		t.Fatalf("after restart got %d lines, want 2", len(lines))
	}
	if lines[0].Sender != "alice" || lines[1].Sender != "bob" {
		t.Fatalf("lines out of order: %+v", lines)
	}
	// nextSeq must continue (post again -> seq 3)
	ln := b2.Post("#dao", "carol", false, []byte("third"))
	if ln.Seq != 3 {
		t.Fatalf("nextSeq not preserved: got %d, want 3", ln.Seq)
	}
	b2.Stop()
}

// TestPersistentBoxSeparateRoomsIsolated: rooms don't bleed across each other
// on reload.
func TestPersistentBoxSeparateRooms(t *testing.T) {
	dir := t.TempDir()
	cfg := BoxConfig{LineTTL: time.Hour, ReapEvery: time.Hour}
	b, _ := NewPersistentBox(cfg, dir)
	b.Post("#a", "x", false, []byte("in a"))
	b.Post("#b", "y", false, []byte("in b"))

	b2, _ := NewPersistentBox(cfg, dir)
	if got := b2.Poll("#a", 0); len(got) != 1 || got[0].Data[0] != 'i' {
		t.Fatalf("#a not isolated: %+v", got)
	}
	if got := b2.Poll("#b", 0); len(got) != 1 || string(got[0].Data) != "in b" {
		t.Fatalf("#b not isolated: %+v", got)
	}
}

// TestPersistentBoxRotAfterReload: lines older than LineTTL are pruned on load
// (rot still applies across restarts).
func TestPersistentBoxRotAfterReload(t *testing.T) {
	dir := t.TempDir()
	cfg := BoxConfig{LineTTL: time.Minute, ReapEvery: time.Hour}
	b, _ := NewPersistentBox(cfg, dir)
	b.Post("#r", "x", false, []byte("fresh"))

	b2, _ := NewPersistentBox(cfg, dir)
	// age the stored lines past TTL then reap
	for _, r := range b2.channels {
		for i := range r.lines {
			r.lines[i].TS = time.Now().Add(-time.Hour).UnixMilli()
		}
	}
	b2.Reap(time.Now())
	b2.saveLocked()
	b3, _ := NewPersistentBox(cfg, dir)
	if got := b3.Poll("#r", 0); len(got) != 0 {
		t.Fatalf("expired line survived reload+reap: %+v", got)
	}
	b3.Stop()
}
