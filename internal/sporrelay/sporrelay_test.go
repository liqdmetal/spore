package sporrelay

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

var uuidReplacer = strings.NewReplacer("-", "")

func TestGenerateObjIDIsUUIDv7(t *testing.T) {
	id := generateObjID()
	if len(id) != 36 {
		t.Fatalf("generateObjID() = %q (len %d), want 36-char canonical UUID", id, len(id))
	}
	for _, pos := range []int{8, 13, 18, 23} {
		if id[pos] != '-' {
			t.Errorf("id %q: byte %d = %q, want '-'", id, pos, id[pos])
		}
	}
	for i, c := range uuidReplacer.Replace(id) {
		switch i {
		case 12:
			if c != '7' {
				t.Errorf("version nibble = %q, want '7'", c)
			}
		case 16:
			if c != '8' && c != '9' && c != 'a' && c != 'b' {
				t.Errorf("variant nibble = %q, want 8/9/a/b", c)
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("id %q: non-hex character %q at %d", id, c, i)
			}
		}
	}
}

func TestGenerateObjIDTimestampIsUnixMilli(t *testing.T) {
	before := time.Now().UnixMilli()
	id := generateObjID()
	after := time.Now().UnixMilli()
	// unixmilli is the first 48 bits: hex chars 0-7 and 9-12 of the
	// canonical string (dashes at 8 and 13).
	var ms int64
	for _, c := range uuidReplacer.Replace(id[:13]) {
		var n int64
		switch {
		case c >= '0' && c <= '9':
			n = int64(c - '0')
		case c >= 'a' && c <= 'f':
			n = int64(c-'a') + 10
		default:
			t.Fatalf("bad hex char %q in timestamp field", c)
		}
		ms = ms*16 + n
	}
	if ms < before || ms > after {
		t.Errorf("embedded timestamp %d outside [%d, %d]", ms, before, after)
	}
}

func TestGenerateObjIDUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := generateObjID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID %q after %d generations", id, i+1)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateObjIDConcurrentUnique(t *testing.T) {
	const goroutines = 8
	const perG = 250
	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*perG)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 0, perG)
			for i := 0; i < perG; i++ {
				local = append(local, generateObjID())
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate ID %q across goroutines", id)
					return
				}
				seen[id] = struct{}{}
			}
		}()
	}
	wg.Wait()
}

func TestGenerateObjIDRandomBitsDiffer(t *testing.T) {
	// Two IDs generated in the same millisecond must still differ in the
	// 74 random bits (rand_a + rand_b); with the timestamp bits masked
	// equal, at least one random byte pair should differ.
	a := generateObjID()
	b := generateObjID()
	sameCount := 0
	for i := 24; i < 36; i++ { // hex chars of rand_b field only
		if a[i] == b[i] {
			sameCount++
		}
	}
	if sameCount == 12 {
		t.Errorf("rand_b fields identical across two IDs:\n %s\n %s", a, b)
	}
}

func TestNewObjectiveUsesGeneratedID(t *testing.T) {
	obj := NewObjective(Source{}, Destination{}, 0.002)
	if obj.ID == "" {
		t.Fatal("NewObjective produced empty objective ID")
	}
	if len(obj.ID) != 36 {
		t.Fatalf("objective ID %q is not a canonical UUID", obj.ID)
	}
	for _, pos := range []int{8, 13, 18, 23} {
		if obj.ID[pos] != '-' {
			t.Fatalf("objective ID %q: byte %d = %q, want '-'", obj.ID, pos, obj.ID[pos])
		}
	}
	if obj.ID[14] != '7' {
		t.Fatalf("objective ID %q: version nibble = %q, want '7'", obj.ID, obj.ID[14])
	}
}

// --- monotonic ordering (RFC 9562 §6.2, the Monotonic Flag method) ---

// unixMilliOf decodes the 48-bit timestamp field of a canonical UUIDv7.
func unixMilliOf(t *testing.T, id string) int64 {
	t.Helper()
	var ms int64
	for _, c := range uuidReplacer.Replace(id[:13]) {
		var n int64
		switch {
		case c >= '0' && c <= '9':
			n = int64(c - '0')
		case c >= 'a' && c <= 'f':
			n = int64(c-'a') + 10
		default:
			t.Fatalf("bad hex char %q in timestamp field", c)
		}
		ms = ms*16 + n
	}
	return ms
}

// counterOf decodes the 12-bit rand_a counter (version nibble masked out).
func counterOf(t *testing.T, id string) uint16 {
	t.Helper()
	var v uint64
	for _, c := range id[14:18] {
		var n uint64
		switch {
		case c >= '0' && c <= '9':
			n = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n = uint64(c-'a') + 10
		default:
			t.Fatalf("bad hex char %q in rand_a field", c)
		}
		v = v*16 + n
	}
	return uint16(v & 0x0fff)
}

func TestGenerateObjIDStrictlyMonotonic(t *testing.T) {
	const n = 100_000
	prev := generateObjID()
	for i := 1; i < n; i++ {
		id := generateObjID()
		// Canonical fixed-length lowercase hex sorts byte-identically to the
		// underlying 16 bytes, so string compare IS the RFC's byte ordering.
		if id <= prev {
			t.Fatalf("ID %d not strictly greater than predecessor:\n %s\n %s", i, prev, id)
		}
		prev = id
	}
}

func TestGenerateObjIDConcurrentPerGoroutineMonotonic(t *testing.T) {
	const goroutines = 8
	const perG = 2_000
	var mu sync.Mutex
	all := make([]string, 0, goroutines*perG)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]string, 0, perG)
			for i := 0; i < perG; i++ {
				local = append(local, generateObjID())
			}
			for i := 1; i < len(local); i++ {
				if local[i] <= local[i-1] {
					t.Errorf("goroutine-local sequence not monotonic at %d:\n %s\n %s", i, local[i-1], local[i])
					return
				}
			}
			mu.Lock()
			all = append(all, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	// And globally unique (monotonic implies unique, but assert the union).
	seen := make(map[string]struct{}, len(all))
	for _, id := range all {
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID %q across goroutines", id)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateObjIDFreezesOnClockRegression(t *testing.T) {
	// Simulate having minted an ID "one hour in the future" (a clock that
	// has since been set back). The next mint must NOT follow the regressed
	// clock backwards: it freezes at the last minted timestamp.
	future := time.Now().Add(time.Hour).UnixMilli()
	objIDMu.Lock()
	objIDLastMS = future
	objIDCounter = 100
	objIDMu.Unlock()
	defer func() {
		objIDMu.Lock()
		objIDLastMS = math.MinInt64 // reset for other tests
		objIDCounter = 0
		objIDMu.Unlock()
	}()
	id := generateObjID()
	if got := unixMilliOf(t, id); got != future {
		t.Errorf("frozen timestamp = %d, want %d (clock regression must not rewind IDs)", got, future)
	}
	if got := counterOf(t, id); got != 101 {
		t.Errorf("counter after freeze = %d, want 101 (frozen ms keeps counting forward)", got)
	}
}

func TestGenerateObjIDCounterRolloverBorrowsMillisecond(t *testing.T) {
	// Counter one below exhaustion: the next mint must advance the
	// timestamp one millisecond past the clock (rollover borrow) instead
	// of wrapping to a lower counter value.
	now := time.Now().UnixMilli()
	objIDMu.Lock()
	objIDLastMS = now
	objIDCounter = (1 << 12) - 1
	objIDMu.Unlock()
	defer func() {
		objIDMu.Lock()
		objIDLastMS = math.MinInt64
		objIDCounter = 0
		objIDMu.Unlock()
	}()
	id := generateObjID()
	if got := unixMilliOf(t, id); got != now+1 {
		t.Errorf("timestamp after rollover = %d, want %d (borrow one ms)", got, now+1)
	}
	// And the borrowed millisecond keeps counting monotonically.
	id2 := generateObjID()
	if id2 <= id {
		t.Error("second mint in borrowed millisecond must still be greater")
	}
	if got := unixMilliOf(t, id2); got != now+1 {
		t.Errorf("second mint timestamp = %d, want %d (still in borrowed ms)", got, now+1)
	}
}

func TestGenerateObjIDCounterReseedsOnNewMillisecond(t *testing.T) {
	// Force many "new millisecond" transitions; the counter must be
	// randomly re-seeded (not reset to a constant, not continued).
	seen := map[uint16]bool{}
	for i := 0; i < 50; i++ {
		objIDMu.Lock()
		objIDLastMS = time.Now().UnixMilli() - 1 // force "new ms" on next mint
		objIDMu.Unlock()
		seen[counterOf(t, generateObjID())] = true
	}
	if len(seen) == 1 {
		t.Error("counter identical across 50 forced new-millisecond reseeds")
	}
}

func TestGenerateObjIDMonotonicUnderCounterReplay(t *testing.T) {
	// A countereverything sanity pair: two mints in the same millisecond
	// differ in rand_a (counter), while rand_b stays fresh random. Decode
	// both fields and check the intended layout is where we say it is.
	objIDMu.Lock()
	objIDLastMS = math.MinInt64
	objIDMu.Unlock()
	a := generateObjID()
	b := generateObjID()
	if unixMilliOf(t, a) != unixMilliOf(t, b) {
		return // crossed a ms boundary mid-test; layout assertions below still hold
	}
	ca, cb := counterOf(t, a), counterOf(t, b)
	if cb != ca+1 {
		t.Errorf("same-ms counters = %d, %d; want increment by 1", ca, cb)
	}
	// rand_b (bytes 10..15, hex chars 24..36) must differ between the two.
	if a[24:] == b[24:] {
		t.Errorf("rand_b identical across two mints:\n %s\n %s", a, b)
	}
}
