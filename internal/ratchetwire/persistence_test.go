package ratchetwire

import (
	"testing"
)

func TestProtectedStateEncryptsAuthenticatesAndBindsSession(t *testing.T) {
	key := filled(9)
	p, err := NewStateProtector(key)
	if err != nil {
		t.Fatal(err)
	}
	var id [8]byte
	copy(id[:], []byte("session1"))
	record, err := ProtectSession(p, id, 7, []byte("private ratchet state"))
	if err != nil {
		t.Fatal(err)
	}
	if contains(record, []byte("private ratchet state")) {
		t.Fatal("plaintext state leaked")
	}
	seq, got, err := UnprotectSession(p, id, record)
	if err != nil || seq != 7 || string(got) != "private ratchet state" {
		t.Fatalf("open seq=%d got=%q err=%v", seq, got, err)
	}
	corrupt := append([]byte(nil), record...)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, err := UnprotectSession(p, id, corrupt); err == nil {
		t.Fatal("tampered record accepted")
	}
	var other [8]byte
	copy(other[:], []byte("session2"))
	if _, _, err := UnprotectSession(p, other, record); err == nil {
		t.Fatal("cross-session state accepted")
	}
}

func TestFileStateStoreContinuesSequenceAfterRestart(t *testing.T) {
	dir := t.TempDir()
	key := filled(21)
	var id [8]byte
	copy(id[:], []byte("restart1"))
	first, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Save(id, []byte("one")); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStateStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Save(id, []byte("two")); err != nil {
		t.Fatal(err)
	}
	got, err := second.Load(id)
	if err != nil || string(got) != "two" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
