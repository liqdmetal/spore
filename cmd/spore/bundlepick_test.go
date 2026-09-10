package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchet"
)

// bundleFixture builds a real, verifiable SPKBundle so the resolution tests
// exercise genuine bundle material rather than a zero struct.
func bundleFixture(t *testing.T, fill byte, withOPK bool) *ratchet.SPKBundle {
	t.Helper()
	id := make([]byte, 32)
	spk := make([]byte, 32)
	for i := range id {
		id[i] = fill
		spk[i] = fill + 1
	}
	var opk *[32]byte
	opkID := uint32(0)
	if withOPK {
		var o [32]byte
		for i := range o {
			o[i] = fill + 2
		}
		opk = &o
		opkID = 3
	}
	b, err := ratchet.BuildBundle(id, spk, 7, opk, opkID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noWarn(string) {}

// TestPickBundlePrefersExplicitFile: -bundle always wins, and no contact or
// network is consulted.
func TestPickBundlePrefersExplicitFile(t *testing.T) {
	want := bundleFixture(t, 0x10, false)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	fetched := false
	fetch := func(context.Context, string, string) (*ratchet.SPKBundle, error) {
		fetched = true
		return nil, errors.New("must not fetch")
	}
	contact := maildb.Contact{PrekeyURL: "https://example.test/prekey", Bundle: bundleFixture(t, 0x20, false)}
	got, err := pickBundle(context.Background(), path, "", "", contact, true, fetch, noWarn)
	if err != nil {
		t.Fatal(err)
	}
	if fetched {
		t.Fatal("an explicit -bundle still triggered a network fetch")
	}
	if got.IKPub != want.IKPub {
		t.Fatalf("picked the wrong bundle: got ik_pub %.8x, want %.8x", got.IKPub[:8], want.IKPub[:8])
	}
}

// TestPickBundlePrefersExplicitURLOverContact: an explicit -bundle-url beats
// whatever the contact recorded, so a user can always override.
func TestPickBundlePrefersExplicitURLOverContact(t *testing.T) {
	explicit := bundleFixture(t, 0x30, false)
	contactBundle := bundleFixture(t, 0x40, false)

	var asked string
	fetch := func(_ context.Context, url, _ string) (*ratchet.SPKBundle, error) {
		asked = url
		return explicit, nil
	}
	contact := maildb.Contact{PrekeyURL: "https://contact.example.test/prekey", Bundle: contactBundle}
	got, err := pickBundle(context.Background(), "", "https://explicit.example.test/prekey", "tok", contact, true, fetch, noWarn)
	if err != nil {
		t.Fatal(err)
	}
	if asked != "https://explicit.example.test/prekey" {
		t.Fatalf("fetched %q, want the explicit URL", asked)
	}
	if got.IKPub != explicit.IKPub {
		t.Fatal("returned the contact's bundle instead of the explicit one")
	}
}

// TestPickBundleUsesContactPrekeyURL: no flags, contact has a URL — the URL is
// used, because it yields a FRESH single-use prekey.
func TestPickBundleUsesContactPrekeyURL(t *testing.T) {
	fromURL := bundleFixture(t, 0x50, true)
	embedded := bundleFixture(t, 0x60, false)

	var asked string
	fetch := func(_ context.Context, url, _ string) (*ratchet.SPKBundle, error) {
		asked = url
		return fromURL, nil
	}
	contact := maildb.Contact{PrekeyURL: "https://contact.example.test/prekey", Bundle: embedded}
	got, err := pickBundle(context.Background(), "", "", "", contact, true, fetch, noWarn)
	if err != nil {
		t.Fatal(err)
	}
	if asked != "https://contact.example.test/prekey" {
		t.Fatalf("fetched %q, want the contact's URL", asked)
	}
	if got.IKPub != fromURL.IKPub {
		t.Fatal("did not prefer the live prekey URL over the embedded bundle")
	}
}

// TestPickBundleFallsBackToEmbeddedWhenURLFails is the offline path: the
// contact's mailbox is down, so the invite's embedded bundle is used — with a
// warning, because it may be a spent single-use prekey.
func TestPickBundleFallsBackToEmbeddedWhenURLFails(t *testing.T) {
	embedded := bundleFixture(t, 0x70, true)
	fetch := func(context.Context, string, string) (*ratchet.SPKBundle, error) {
		return nil, errors.New("connection refused")
	}
	var warnings []string
	warn := func(m string) { warnings = append(warnings, m) }
	contact := maildb.Contact{PrekeyURL: "https://down.example.test/prekey", Bundle: embedded}

	got, err := pickBundle(context.Background(), "", "", "", contact, true, fetch, warn)
	if err != nil {
		t.Fatalf("fallback to the embedded bundle failed: %v", err)
	}
	if got.IKPub != embedded.IKPub {
		t.Fatal("did not fall back to the embedded bundle")
	}
	if len(warnings) == 0 {
		t.Fatal("falling back to a single-use embedded prekey must warn")
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "unreachable") {
		t.Fatalf("warning does not explain the fallback: %v", warnings)
	}
	if !strings.Contains(joined, "one sender") {
		t.Fatalf("warning does not disclose the single-use limitation: %v", warnings)
	}
}

// TestPickBundleNoContactIsActionable: with no flags and no contact, the error
// must name the fix rather than just failing.
func TestPickBundleNoContactIsActionable(t *testing.T) {
	fetch := func(context.Context, string, string) (*ratchet.SPKBundle, error) {
		return nil, errors.New("must not fetch")
	}
	_, err := pickBundle(context.Background(), "", "", "", maildb.Contact{}, false, fetch, noWarn)
	if err == nil {
		t.Fatal("resolved a bundle with no flags and no contact")
	}
	if !strings.Contains(err.Error(), "mail add -invite") {
		t.Fatalf("error does not tell the user how to fix it: %v", err)
	}
}

// TestPickBundleContactWithoutRouteExplains: a contact added by address alone
// has no prekey route; the error must say so and name the address.
func TestPickBundleContactWithoutRouteExplains(t *testing.T) {
	fetch := func(context.Context, string, string) (*ratchet.SPKBundle, error) {
		return nil, errors.New("must not fetch")
	}
	c := maildb.Contact{Address: "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4"}
	_, err := pickBundle(context.Background(), "", "", "", c, true, fetch, noWarn)
	if err == nil {
		t.Fatal("resolved a bundle for a contact with no prekey route")
	}
	if !strings.Contains(err.Error(), c.Address) {
		t.Fatalf("error omits the contact address: %v", err)
	}
}

// TestPickBundleURLFailureWithNoFallbackIsFatal: if the URL fails and there is
// nothing embedded, the failure must surface rather than silently doing nothing.
func TestPickBundleURLFailureWithNoFallbackIsFatal(t *testing.T) {
	fetch := func(context.Context, string, string) (*ratchet.SPKBundle, error) {
		return nil, errors.New("connection refused")
	}
	contact := maildb.Contact{PrekeyURL: "https://down.example.test/prekey"}
	if _, err := pickBundle(context.Background(), "", "", "", contact, true, fetch, noWarn); err == nil {
		t.Fatal("a failing prekey URL with no fallback was reported as success")
	}
}

// TestPickBundleFetchesOverRealHTTP exercises the actual fetchBundle wire path
// against a real server, so the contact's PrekeyURL is proven to work through
// the same code the CLI uses — not a stub.
func TestPickBundleFetchesOverRealHTTP(t *testing.T) {
	want := bundleFixture(t, 0x80, true)

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prekey" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %q", r.Method)
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Bundle ratchet.SPKBundle `json:"bundle"`
		}{Bundle: *want})
	}))
	defer srv.Close()

	// The embedded bundle is deliberately a DIFFERENT key, so a pass proves the
	// HTTP result was used rather than the offline fallback.
	contact := maildb.Contact{
		PrekeyURL: srv.URL + "/prekey",
		Bundle:    bundleFixture(t, 0x90, false),
	}
	got, err := pickBundle(context.Background(), "", "", "", contact, true, fetchBundle, noWarn)
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("server saw %d requests, want exactly 1", hits)
	}
	if got.IKPub != want.IKPub {
		t.Fatal("did not use the bundle served over HTTP")
	}
	if got.OPKPub == nil {
		t.Fatal("lost the one-time prekey in transit")
	}
}
