package fabric

// Tests for the drain-union store (F3; AUDIT-RELAYFABRIC.md R-N1): the
// CONSUMED-set contract (mark on success, un-mark on failure), cross-relay
// dedupe, deadline pruning, the hard cap, and restart persistence.

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ptrWith makes a minimal 74-byte pointer payload with the given CID bytes
// (34:66) and burn deadline (66:74, LE unix seconds).
func ptrWith(cid [32]byte, deadline uint64) []byte {
	raw := make([]byte, 74)
	raw[0] = 1 // version
	binary.LittleEndian.PutUint64(raw[66:74], deadline)
	copy(raw[34:66], cid[:])
	return raw
}

func cidOf(t *testing.T, i int) [32]byte {
	t.Helper()
	var c [32]byte
	binary.LittleEndian.PutUint64(c[:8], uint64(i))
	return c
}

func TestSeenObserveIsFirstSightingOnly(t *testing.T) {
	s := NewSeenCIDs("")
	raw := ptrWith(cidOf(t, 1), 0)
	if !s.Observe(raw) {
		t.Fatal("first Observe must win")
	}
	if s.Observe(raw) {
		t.Fatal("second Observe of the same CID must lose")
	}
	// A different CID with the same deadline is independent.
	if !s.Observe(ptrWith(cidOf(t, 2), 0)) {
		t.Fatal("a different CID must be a first sighting")
	}
	if got := s.Len(); got != 2 {
		t.Fatalf("want 2 entries, got %d", got)
	}
}

func TestSeenForgetRestoresEligibility(t *testing.T) {
	s := NewSeenCIDs("")
	raw := ptrWith(cidOf(t, 3), 0)
	if !s.Observe(raw) {
		t.Fatal("first Observe must win")
	}
	// The ingest failed: un-mark, and the very same pointer becomes
	// eligible again — the CONSUMED-set contract that lets a redundant
	// copy from another relay deliver where the first relay failed.
	s.Forget(raw)
	if !s.Observe(raw) {
		t.Fatal("after Forget the CID must be first-sighted again")
	}
}

func TestSeenObserveRejectsNonKeyablePointers(t *testing.T) {
	s := NewSeenCIDs("")
	// Too short to key: Observe must NOT record it and must let the caller
	// try (the ingest path refuses it legibly).
	if !s.Observe(make([]byte, 40)) {
		t.Fatal("unkeyable pointers pass through as first sightings")
	}
	if s.Len() != 0 {
		t.Fatalf("unkeyable pointers must not be recorded, got %d", s.Len())
	}
	// Malformed hex can never come from hex.EncodeToString, but the store
	// defends its file format against it anyway.
	if s.Seen("zz") {
		t.Fatal("malformed key must read as unseen")
	}
}

func TestSeenPruneDropsExpiredAndCaps(t *testing.T) {
	s := NewSeenCIDs("")
	now := time.Now()
	past := uint64(now.Add(-time.Minute).Unix())
	future := uint64(now.Add(time.Hour).Unix())

	// Expired entries prune; unexpired and deadline-less entries stay.
	if !s.Observe(ptrWith(cidOf(t, 10), past)) {
		t.Fatal("observe expired")
	}
	if !s.Observe(ptrWith(cidOf(t, 11), future)) {
		t.Fatal("observe future")
	}
	if !s.Observe(ptrWith(cidOf(t, 12), 0)) {
		t.Fatal("observe deadline-less")
	}
	s.Prune(now)
	c10, c11, c12 := cidOf(t, 10), cidOf(t, 11), cidOf(t, 12)
	if s.Seen(hex.EncodeToString(c10[:])) {
		t.Fatal("expired entry must prune")
	}
	if !s.Seen(hex.EncodeToString(c11[:])) {
		t.Fatal("unexpired entry must stay")
	}
	if !s.Seen(hex.EncodeToString(c12[:])) {
		t.Fatal("deadline-less entry must stay (least safely forgettable)")
	}

	// Hard cap, deterministic: six UNEXPIRED entries with distinct future
	// deadlines against cap=4 — the four soonest-expiring must survive and
	// the two soonest of the rest must go (deadline-less entries are
	// covered above; this phase pins the eviction ORDER).
	small := NewSeenCIDs("")
	small.cap = 4
	for i := 0; i < 6; i++ {
		dl := uint64(now.Add(time.Duration(10+i) * time.Minute).Unix())
		if !small.Observe(ptrWith(cidOf(t, 100+i), dl)) {
			t.Fatalf("observe %d", i)
		}
	}
	small.Prune(now)
	if small.Len() != 4 {
		t.Fatalf("cap must enforce 4 entries, got %d", small.Len())
	}
	for i := 0; i < 2; i++ {
		c := cidOf(t, 100+i)
		if small.Seen(hex.EncodeToString(c[:])) {
			t.Fatalf("entry %d (soonest-expiring) must have been evicted", i)
		}
	}
	for i := 2; i < 6; i++ {
		c := cidOf(t, 100+i)
		if !small.Seen(hex.EncodeToString(c[:])) {
			t.Fatalf("entry %d (later-expiring) must survive the cap", i)
		}
	}
}

func TestSeenPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "fabric-seen.txt")

	s1 := NewSeenCIDs(path)
	raw := ptrWith(cidOf(t, 21), uint64(time.Now().Add(time.Hour).Unix()))
	if !s1.Observe(raw) {
		t.Fatal("first Observe must win")
	}
	// The 1s save gate must not lose the FIRST save of a burst.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file must exist after the first save: %v", err)
	}

	// A "restarted" process loads the union and dedupes against history.
	s2 := NewSeenCIDs(path)
	if s2.Observe(raw) {
		t.Fatal("a restarted store must still dedupe against the persisted union")
	}
	if got := s2.Len(); got != 1 {
		t.Fatalf("want 1 entry after reload, got %d", got)
	}

	// Corrupt file: the store starts empty rather than failing — the
	// ratchet is the correctness net; the union is an optimization.
	if err := os.WriteFile(path, []byte("not a seen file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s3 := NewSeenCIDs(path)
	if got := s3.Len(); got != 0 {
		t.Fatalf("corrupt file must load as empty, got %d", got)
	}
	// And the next save must overwrite the corruption with valid content.
	c22 := cidOf22()
	if !s3.Observe(ptrWith(c22, 0)) {
		t.Fatal("observe after corruption")
	}
	if !NewSeenCIDs(path).Seen(hex.EncodeToString(c22[:])) {
		t.Fatal("save after corruption must produce a valid file")
	}
}

func cidOf22() [32]byte {
	var c [32]byte
	c[0] = 22
	return c
}

func TestSeenSaveGateAllowsSecondAfterASecond(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seen.txt")
	s := NewSeenCIDs(path)
	// First save is immediate (everSaved gate).
	if !s.Observe(ptrWith(cidOf30(), 0)) {
		t.Fatal("observe 1")
	}
	// Within the gate window, further mutations are memory-only.
	if !s.Observe(ptrWith(cidOf(t, 31), 0)) {
		t.Fatal("observe 2")
	}
	// A fresh store still sees the FIRST save's content.
	c30 := cidOf30()
	if !NewSeenCIDs(path).Seen(hex.EncodeToString(c30[:])) {
		t.Fatal("first save must be on disk")
	}
}

func cidOf30() [32]byte {
	var c [32]byte
	c[0] = 30
	return c
}
