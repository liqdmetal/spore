package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// TestReadBundleDiagnosesWrongFile covers the onboarding dead end found by
// live testing: `spore init` used to write bundle.json containing an identity
// CARD, but `send-e2 -bundle` expects an ratchet.SPKBundle. A raw Go
// unmarshal type error tells the user nothing; the diagnosis must name the
// mistake and the fix.
func TestReadBundleDiagnosesWrongFile(t *testing.T) {
	dir := t.TempDir()

	// An identity card (what init writes for out-of-band sharing).
	card := filepath.Join(dir, "identity-card.json")
	if err := os.WriteFile(card, []byte(`{"ik_pub":"aa","pinned_sig":"bb"}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readBundle(card)
	if err == nil {
		t.Fatal("identity card accepted as a bundle")
	}
	if !strings.Contains(err.Error(), "identity CARD") || !strings.Contains(err.Error(), "-bundle-url") {
		t.Fatalf("card error should name the mistake and the fix: %v", err)
	}

	// A prekey batch (what `prekeybatch gen` writes).
	batch := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(batch, []byte(`{"bundles":[{"ik_pub":"aa"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = readBundle(batch)
	if err == nil {
		t.Fatal("batch accepted as a bundle")
	}
	if !strings.Contains(err.Error(), "BATCH") || !strings.Contains(err.Error(), "prekeybatch push") {
		t.Fatalf("batch error should point at prekeybatch push: %v", err)
	}

	// Arbitrary JSON that decodes into an all-zero bundle must be REJECTED.
	// json.Unmarshal ignores unknown fields, so without the structural gate
	// these would reach the X3DH handshake as a zero bundle.
	for name, content := range map[string]string{
		"empty object":   `{}`,
		"unrelated json": `{"foo":"bar"}`,
		"empty bundles":  `{"bundles":[]}`,
		"partial bundle": `{"ik_pub":"` + strings.Repeat("aa", 32) + `"}`,
	} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBundle(p); err == nil {
			t.Errorf("%s: readBundle accepted %q (would send a zero bundle into X3DH)", name, content)
		}
	}

	// Arbitrary garbage still errors, and says which file.
	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte(`not json at all`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = readBundle(junk)
	if err == nil {
		t.Fatal("garbage accepted")
	}
	if !strings.Contains(err.Error(), "junk.json") {
		t.Fatalf("error should name the offending file: %v", err)
	}
}

// TestFetchBundleRejectsZeroBundle covers the same structural gate on the
// discovery path: a mailbox returning {"bundle":{}} must not yield a zero
// bundle that sails into the handshake.
func TestFetchBundleRejectsZeroBundle(t *testing.T) {
	for _, body := range []string{`{"bundle":{}}`, `{"bundle":{"ik_pub":"` + strings.Repeat("00", 32) + `"}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		_, err := fetchBundle(context.Background(), srv.URL+"/prekey", "")
		srv.Close()
		if err == nil {
			t.Fatalf("fetchBundle accepted a zero/partial bundle: %s", body)
		}
	}
}

func TestValidateBundleStructDirect(t *testing.T) {
	if err := validateBundleStruct(nil); err == nil {
		t.Fatal("nil bundle accepted")
	}
	if err := validateBundleStruct(&ratchet.SPKBundle{}); err == nil {
		t.Fatal("zero bundle accepted")
	}
	// OPK id with no OPK public key is inconsistent.
	b := ratchet.SPKBundle{OPKID: 7}
	b.IKPub[0] = 1
	b.SPKPub[0] = 2
	b.SPKSig[0] = 3
	if err := validateBundleStruct(&b); err == nil {
		t.Fatal("OPK id without OPK pubkey accepted")
	}
	// Degraded mode (no OPK at all) IS valid.
	b.OPKID = 0
	if err := validateBundleStruct(&b); err != nil {
		t.Fatalf("valid degraded bundle rejected: %v", err)
	}
}

func TestReadBundleMissingFileErrors(t *testing.T) {
	if _, err := readBundle(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing bundle file accepted")
	}
}
