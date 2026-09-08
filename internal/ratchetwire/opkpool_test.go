package ratchetwire

import (
	"path/filepath"
	"testing"
)

func TestOPKPoolSingleUse(t *testing.T) {
	p := NewOPKPool()
	var k [32]byte
	k[0] = 1
	if err := p.Add(7, k); err != nil {
		t.Fatal(err)
	}
	got, err := p.Take(7)
	if err != nil || got != k {
		t.Fatalf("take: %v", err)
	}
	if _, err := p.Take(7); err != ErrNoOPK {
		t.Fatalf("reused OPK: %v", err)
	}
}

func TestPersistentOPKPoolConsumptionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint", "opks.json")
	var key [32]byte
	key[0] = 9
	p, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(42, key); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Take(42); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Len() != 0 {
		t.Fatalf("consumed OPK restored after restart: len=%d", restarted.Len())
	}
	if _, err := restarted.Take(42); err != ErrNoOPK {
		t.Fatalf("reused after restart: %v", err)
	}
}

func TestPersistentOPKPoolAddSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opks.json")
	var key [32]byte
	key[0] = 3
	p, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(8, key); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPersistentOPKPool(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Take(8)
	if err != nil || got != key {
		t.Fatalf("restored take: %v", err)
	}
}
