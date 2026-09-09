package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/maildb"
)

// TestLooksLikeAddressGenericChainAddresses covers the addresses that have no
// prefix this code recognises. This matters for the compose→flush path:
// compose RESOLVES a nickname to an address and stores it, then flush hands
// that address back through resolveTo. If a Solana base58 / TON / Cosmos
// address is mistaken for a nickname, a correctly-composed queued message
// fails at flush time — after the user thinks it is safely queued.
func TestLooksLikeAddressGenericChainAddresses(t *testing.T) {
	// Real-shaped addresses with no prefix that looksLikeAddress recognises.
	// These must be caught by the STRUCTURAL check so a resolved address is
	// never re-resolved as a nickname on the flush path.
	yes := []string{
		// Solana base58 (32-byte pubkey)
		"4a3DB9nd5q37nCJbgTSDaNML8Vn5nCJNAuJUHpMNmXpa",
		// TON raw (workchain : 64 hex)
		"0:8a90f7f6c8b5e6d90f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70",
		// Generic long base58/hex token
		strings.Repeat("a", 44),
	}
	for _, s := range yes {
		if !looksLikeStructuralAddress(s) {
			t.Errorf("looksLikeStructuralAddress(%q) = false; a resolved chain address must never be re-resolved as a nickname", s)
		}
		// And resolveTo must pass it through with NO maildb and NO daemon —
		// the flush-on-another-machine case.
		got, _, err := resolveTo(context.Background(), s, "", "")
		if err != nil {
			t.Errorf("resolveTo(%q) failed with no maildb/daemon: %v", s, err)
		} else if got != s {
			t.Errorf("resolveTo(%q) = %q, changed the address", s, got)
		}
	}
	// Human nicknames must still NOT match — these are what the address book
	// is for. Short, or containing spaces/punctuation.
	no := []string{"alice", "bob", "My Friend", "driftpile-cfo", "a", strings.Repeat("a", 31), "hello.world", "acct@bank"}
	for _, s := range no {
		if looksLikeStructuralAddress(s) {
			t.Errorf("looksLikeStructuralAddress(%q) = true; a human nickname must fall through to the address book", s)
		}
	}
}

// TestComposeThenFlushResolvesTwice is the regression guard for the
// double-resolution path: resolving an already-resolved non-DERO address must
// pass it through unchanged rather than failing.
func TestComposeThenFlushResolvesTwice(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	solAddr := "4a3DB9nd5q37nCJbgTSDaNML8Vn5nCJNAuJUHpMNmXpa"
	if err := db.UpsertContact(maildb.Contact{Address: solAddr, Nickname: "solfriend", Pinned: "cc"}); err != nil {
		t.Fatal(err)
	}

	// Step 1 (compose time): nickname -> address + pinned.
	addr1, pinned1, err := resolveTo(context.Background(), "solfriend", dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if addr1 != solAddr || pinned1 != "cc" {
		t.Fatalf("compose resolution = %q/%q", addr1, pinned1)
	}

	// Step 2 (flush time): the stored address goes back through resolveTo
	// WITHOUT the maildb available (e.g. flushed on another machine). It must
	// still pass through, because it is recognisably an address.
	addr2, _, err := resolveTo(context.Background(), addr1, "", "")
	if err != nil {
		t.Fatalf("re-resolving a resolved address failed: %v", err)
	}
	if addr2 != solAddr {
		t.Fatalf("address changed on re-resolution: %q != %q", addr2, solAddr)
	}
}
