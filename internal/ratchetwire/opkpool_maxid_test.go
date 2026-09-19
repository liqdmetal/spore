package ratchetwire

import (
	"path/filepath"
	"testing"
)

func TestOPKPoolMaxID(t *testing.T) {
	pool, err := NewPersistentOPKPool(filepath.Join(t.TempDir(), "pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if pool.MaxID() != 0 {
		t.Fatalf("empty pool MaxID = %d, want 0", pool.MaxID())
	}
	for id, k := range map[uint32][32]byte{5: {1}, 3: {2}, 9: {3}} {
		if err := pool.Add(id, k); err != nil {
			t.Fatal(err)
		}
	}
	if got := pool.MaxID(); got != 9 {
		t.Fatalf("MaxID = %d, want 9", got)
	}
	// Consuming keys lowers the live set but MaxID tracks what remains;
	// after taking 9 the max is 5.
	if _, err := pool.Take(9); err != nil {
		t.Fatal(err)
	}
	if got := pool.MaxID(); got != 5 {
		t.Fatalf("MaxID after take(9) = %d, want 5", got)
	}
}
