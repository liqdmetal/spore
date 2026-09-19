package maildb

import (
	"path/filepath"
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// TestUpsertContactPreservesInviteRoute: a contact introduced by a signed
// invite carries a prekey route. Re-adding that contact by address alone (the
// original onboarding path, or a typo-fix of the nickname) must NOT silently
// drop the route — otherwise a later `send-e2 -to <nick>` fails for a reason
// the user never caused, with no hint about what changed.
func TestUpsertContactPreservesInviteRoute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.json")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := ratchet.BuildBundle(
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("fedcba9876543210fedcba9876543210"),
		4, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	const addr = "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4"

	if err := db.UpsertContact(Contact{
		Address:   addr,
		Nickname:  "alice",
		Pinned:    "aabbcc",
		PrekeyURL: "https://mailbox.example.net/u/alice/prekey",
		Bundle:    bundle,
	}); err != nil {
		t.Fatal(err)
	}

	// Re-add by address only, changing the nickname.
	if err := db.UpsertContact(Contact{Address: addr, Nickname: "alice2"}); err != nil {
		t.Fatal(err)
	}

	c, ok := db.Contact(addr)
	if !ok {
		t.Fatal("contact vanished")
	}
	if c.Nickname != "alice2" {
		t.Fatalf("nickname update lost: %q", c.Nickname)
	}
	if c.PrekeyURL != "https://mailbox.example.net/u/alice/prekey" {
		t.Fatalf("prekey URL was dropped by a bare re-add: %q", c.PrekeyURL)
	}
	if c.Bundle == nil || c.Bundle.IKPub != bundle.IKPub {
		t.Fatal("stored bundle was dropped by a bare re-add")
	}
	if c.Pinned != "aabbcc" {
		t.Fatalf("pinned sig was dropped by a bare re-add: %q", c.Pinned)
	}

	// And it must survive a reload, since the send path reads it fresh.
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Contact(addr)
	if !ok || got.PrekeyURL == "" || got.Bundle == nil {
		t.Fatalf("invite route did not survive reload: %#v", got)
	}
}

// TestUpsertContactExplicitValuesOverride: preservation must not make a stale
// value impossible to replace. Supplying a NEW prekey route wins.
func TestUpsertContactExplicitValuesOverride(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "mail.json"))
	if err != nil {
		t.Fatal(err)
	}
	const addr = "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4"
	if err := db.UpsertContact(Contact{Address: addr, PrekeyURL: "https://old.example.net/prekey"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertContact(Contact{Address: addr, PrekeyURL: "https://new.example.net/prekey"}); err != nil {
		t.Fatal(err)
	}
	c, _ := db.Contact(addr)
	if c.PrekeyURL != "https://new.example.net/prekey" {
		t.Fatalf("a new prekey URL did not replace the old one: %q", c.PrekeyURL)
	}
}
