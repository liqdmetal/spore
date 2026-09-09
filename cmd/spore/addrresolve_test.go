package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/maildb"
)

func TestLooksLikeAddress(t *testing.T) {
	yes := []string{
		"dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz",
		"0x1234567890abcdef1234567890abcdef12345678",
		"npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu",
	}
	for _, s := range yes {
		if !looksLikeAddress(s) {
			t.Errorf("looksLikeAddress(%q) = false, want true", s)
		}
	}
	// Human names must NEVER be mistaken for addresses: a false positive here
	// would silently post to a wrong destination instead of resolving a name.
	no := []string{"alice", "bob.dero", "dero1", "0x123", "npub1abc", "bc1q", "cosmos1", "", "My Friend"}
	for _, s := range no {
		if looksLikeAddress(s) {
			t.Errorf("looksLikeAddress(%q) = true, want false (must fall through to name resolution)", s)
		}
	}
}

func TestResolveToPassesAddressThrough(t *testing.T) {
	addr := "dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz"
	got, pinned, err := resolveTo(context.Background(), addr, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Fatalf("addr changed: %q", got)
	}
	if pinned != "" {
		t.Fatalf("address pass-through must not invent a pinned sig, got %q", pinned)
	}
}

func TestResolveToNicknameSuppliesAddressAndPinned(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	addr := "dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz"
	if err := db.UpsertContact(maildb.Contact{Address: addr, Nickname: "Alice", Pinned: "aabbccdd"}); err != nil {
		t.Fatal(err)
	}

	// The whole point: one remembered name replaces a 66-char address AND a
	// separate pinned-sig blob. Case-insensitive match.
	for _, name := range []string{"Alice", "alice", "ALICE", "  alice  "} {
		got, pinned, err := resolveTo(context.Background(), name, dbPath, "")
		if err != nil {
			t.Fatalf("resolve %q: %v", name, err)
		}
		if got != addr {
			t.Fatalf("resolve %q addr = %q, want %q", name, got, addr)
		}
		if pinned != "aabbccdd" {
			t.Fatalf("resolve %q pinned = %q, want the contact's pinned sig", name, pinned)
		}
	}
}

func TestResolveToUnknownNameFailsLoudly(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	// Open for its side effect (create the store) — the contact set is
	// deliberately EMPTY so the nickname cannot be found.
	if _, err := maildb.Open(dbPath); err != nil {
		t.Fatal(err)
	}
	// No -daemon: an unknown nickname must error with actionable guidance,
	// never silently send somewhere.
	_, _, err := resolveTo(context.Background(), "ghost", dbPath, "")
	if err == nil {
		t.Fatal("unknown name resolved without a daemon")
	}
	if !strings.Contains(err.Error(), "msg mail add") {
		t.Fatalf("error should tell the user how to add the contact: %v", err)
	}
}

func TestResolveToUnreadableMaildbFallsThrough(t *testing.T) {
	// A maildb we cannot use must not block sending to a raw address.
	bad := filepath.Join(t.TempDir(), "mail.json")
	if _, err := maildb.Open(bad); err != nil {
		t.Fatal(err)
	}
	addr := "dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz"
	got, _, err := resolveTo(context.Background(), addr, bad, "")
	if err != nil || got != addr {
		t.Fatalf("address pass-through broke: %q %v", got, err)
	}
}

func TestResolveToEmptyRejected(t *testing.T) {
	if _, _, err := resolveTo(context.Background(), "   ", "", ""); err == nil {
		t.Fatal("empty -to accepted")
	}
}

func TestContactByNicknameNoFuzzyMatch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	addr := "dero1qywrzl2mc2juju4ryqassffu47pmevmns909jnrq9jurdpveyvh27qgke8uqz"
	if err := db.UpsertContact(maildb.Contact{Address: addr, Nickname: "Alice"}); err != nil {
		t.Fatal(err)
	}
	// Fuzzy matching would risk messaging the wrong person. "ali" must miss.
	for _, miss := range []string{"ali", "alic", "alice2", "", "  "} {
		if _, ok := contactByNickname(db, miss); ok {
			t.Errorf("contactByNickname(%q) matched; nicknames must match exactly", miss)
		}
	}
	if _, ok := contactByNickname(db, "alice"); !ok {
		t.Fatal("exact case-insensitive match failed")
	}
}
