package ratchet

import (
	"math"
	"testing"
	"time"
)

// L1 (audit): the u32 message number must never be allowed to wrap. Encrypt
// refuses a chain at MaxUint32; decrypt refuses an incoming MaxUint32 header;
// skipTo refuses to advance the receiving cursor onto MaxUint32.

func TestEncryptRefusesExhaustedSendingChain(t *testing.T) {
	p := establishPair(t, true)
	// Force the sending chain cursor to the last legal message number.
	p.alice.ns = math.MaxUint32
	if _, err := p.alice.Encrypt([]byte("overflow")); err == nil {
		t.Fatal("Encrypt accepted a sending chain at MaxUint32 — counter would wrap")
	}
	// Sanity: the unmodified responder still works (guards a broken fixture).
	if _, err := p.bob.Encrypt([]byte("normal")); err != nil {
		t.Fatalf("unrelated encrypt broke: %v", err)
	}
}

func TestDecryptRefusesMaxUint32MessageNumber(t *testing.T) {
	p := establishPair(t, true)
	m, err := p.alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	m.Header.N = math.MaxUint32
	if _, err := p.bob.DecryptWithDeadline(m, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("Decrypt accepted message number MaxUint32")
	}
	// The refusal must happen before state mutation: a normal message still
	// decrypts afterwards.
	m2, err := p.alice.Encrypt([]byte("still works"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.bob.Decrypt(m2); err != nil {
		t.Fatalf("state was corrupted by the overflow refusal: %v", err)
	}
}

func TestSkipToRefusesCursorAtMaxUint32(t *testing.T) {
	p := establishPair(t, true)
	m, err := p.alice.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// A gap whose `to` is MaxUint32 must fail closed instead of parking the
	// receiving cursor one below wrap.
	m.Header.N = math.MaxUint32
	m.Header.PN = math.MaxUint32
	if _, err := p.bob.DecryptWithDeadline(m, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("skipTo accepted a target cursor of MaxUint32")
	}
}
