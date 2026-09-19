package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/mailbox"
	"github.com/liqdmetal/spore/internal/ratchet"
)

// publishBundle PUTs a bundle to a mailbox's /prekey endpoint exactly as a
// real operator client would, using the same wire shape mailbox.PrekeyBundle
// expects ({"bundle": {...}}).
func publishBundle(t *testing.T, url string, b ratchet.SPKBundle) {
	t.Helper()
	publishBundleWithToken(t, url, b, "")
}

func publishBundleWithToken(t *testing.T, url string, b ratchet.SPKBundle, token string) {
	t.Helper()
	body, err := json.Marshal(struct {
		Bundle ratchet.SPKBundle `json:"bundle"`
	}{Bundle: b})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("publish bundle: unexpected status %s", resp.Status)
	}
}

// TestFetchBundleAgainstRealMailboxHandler proves fetchBundle's wire format
// matches production end to end: publish a real bundle to a real
// mailbox.Handler() via PUT /prekey (exactly as a recv-e2 operator would),
// then fetch it with fetchBundle exactly as send-e2 -bundle-url does, and
// confirm the bundle round-trips byte-for-byte. This is the integration
// proof that the two independently-implemented sides (mailbox package,
// cmd/spore package) actually agree on the wire contract.
func TestFetchBundleAgainstRealMailboxHandler(t *testing.T) {
	dir := t.TempDir()
	m, err := mailbox.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Build a real X3DH bundle the way `spore msg prekeygen` does.
	key := func() []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	ik, spk := key(), key()
	want, err := ratchet.BuildBundle(ik, spk, 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	// Publish exactly as an operator's PUT /prekey client would.
	publishBundle(t, srv.URL+"/prekey", *want)

	// Fetch exactly as send-e2 -bundle-url does.
	got, err := fetchBundle(context.Background(), srv.URL+"/prekey", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.IKPub != want.IKPub || got.SPKPub != want.SPKPub || got.SPKID != want.SPKID || got.SPKSig != want.SPKSig {
		t.Fatalf("round-tripped bundle mismatch:\n got  %+v\n want %+v", got, want)
	}
}

// TestFetchBundleAgainstRealMailboxHandlerWithAuth proves the token path also
// works against the real authenticated handler (HandlerToken), not just the
// open one.
func TestFetchBundleAgainstRealMailboxHandlerWithAuth(t *testing.T) {
	dir := t.TempDir()
	m, err := mailbox.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := func() []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	want, err := ratchet.BuildBundle(key(), key(), 1, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	const token = "test-token-value"
	srv := httptest.NewServer(m.HandlerToken(token))
	defer srv.Close()

	publishBundleWithToken(t, srv.URL+"/prekey", *want, token)

	// Wrong/missing token must fail.
	if _, err := fetchBundle(context.Background(), srv.URL+"/prekey", ""); err == nil {
		t.Fatal("expected error fetching from an auth-gated mailbox without a token")
	}
	if _, err := fetchBundle(context.Background(), srv.URL+"/prekey", "wrong"); err == nil {
		t.Fatal("expected error fetching from an auth-gated mailbox with the wrong token")
	}

	// Correct token succeeds.
	got, err := fetchBundle(context.Background(), srv.URL+"/prekey", token)
	if err != nil {
		t.Fatal(err)
	}
	if got.IKPub != want.IKPub {
		t.Fatalf("bundle mismatch fetching with valid token")
	}
}
