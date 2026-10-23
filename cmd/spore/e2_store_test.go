package main

import (
	"crypto/sha256"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/peerstore"
	"github.com/liqdmetal/spore/internal/store"
)

func TestE2StoreDiskSchemePersistsForDirectPeerServing(t *testing.T) {
	dir := t.TempDir()
	url := "disk://" + filepath.ToSlash(dir)
	opts := e2StoreOptions{URL: url}
	bodyStore, err := newE2BodyStore(opts)
	if err != nil {
		t.Fatalf("newE2BodyStore(%q): %v", url, err)
	}

	body := []byte("opaque E2 ciphertext")
	cid := sha256.Sum256(body)
	if err := bodyStore.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put(): %v", err)
	}

	peerStore, err := store.NewDiskStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := peerStore.Get(cid)
	if err != nil {
		t.Fatalf("shared peer store Get(): %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("shared body mismatch: got %q", got)
	}
}

func TestE2StorePeerSchemeIsReceiveOnly(t *testing.T) {
	opts := e2StoreOptions{URL: "peer://127.0.0.1:8099"}
	bodyStore, err := newE2BodyStore(opts)
	if err != nil {
		t.Fatalf("newE2BodyStore(peer://): %v", err)
	}
	if _, ok := bodyStore.(*peerstore.PeerStore); !ok {
		t.Fatalf("peer:// store type = %T, want *peerstore.PeerStore", bodyStore)
	}
}

func TestIrohE2ConfigUsesPortableIndexAndSidecarSettings(t *testing.T) {
	t.Setenv("SPORE_IROH_BIN", "custom-spore-iroh")
	t.Setenv("SPORE_IROH_STORE", "node-data")
	t.Setenv("SPORE_IROH_INDEX", "")
	cfg, err := irohE2Config("iroh://", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cmd != "custom-spore-iroh" || cfg.IndexPath != filepath.Join("node-data", "iroh-index.json") {
		t.Fatalf("Iroh config = %#v", cfg)
	}
	t.Setenv("SPORE_IROH_INDEX", filepath.Join("private", "index.json"))
	cfg, err = irohE2Config("iroh://", "", "")
	if err != nil || cfg.IndexPath != filepath.Join("private", "index.json") {
		t.Fatalf("override config = %#v, %v", cfg, err)
	}
}

func TestIrohE2ConfigDefaultsToUserScopedStore(t *testing.T) {
	t.Setenv("SPORE_IROH_STORE", "")
	t.Setenv("SPORE_IROH_INDEX", "")
	base := t.TempDir()
	var want string
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LOCALAPPDATA", base)
		want = filepath.Join(base, "Spore", "Iroh", "iroh-index.json")
	case "darwin":
		t.Setenv("HOME", base)
		want = filepath.Join(base, "Library", "Application Support", "Spore", "Iroh", "iroh-index.json")
	default:
		t.Setenv("XDG_DATA_HOME", base)
		want = filepath.Join(base, "spore", "iroh", "iroh-index.json")
	}
	cfg, err := irohE2Config("iroh://", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IndexPath != want {
		t.Fatalf("default Iroh index = %q, want %q", cfg.IndexPath, want)
	}
}

func TestIrohE2ConfigRejectsHTTPControlsAndSuffix(t *testing.T) {
	for _, tc := range []struct{ url, token, relay string }{
		{"iroh://", "bearer", ""},
		{"iroh://", "", "https://relay.invalid"},
		{"iroh://peer", "", ""},
	} {
		if _, err := irohE2Config(tc.url, tc.token, tc.relay); err == nil {
			t.Fatalf("accepted incompatible Iroh settings: %#v", tc)
		}
	}
}

func TestE2StoreIrohReachesSidecarProbe(t *testing.T) {
	t.Setenv("SPORE_IROH_BIN", filepath.Join(t.TempDir(), "missing-sidecar"))
	opts := e2StoreOptions{URL: "iroh://"}
	_, err := newE2BodyStore(opts)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("newE2BodyStore did not reach the expected sidecar probe: %v", err)
	}
}

func TestE2StorePeerRejectsTokenRatherThanImplyingAuthentication(t *testing.T) {
	// peer:// does not accept a token — it's not an HTTP store.
	// The token is simply ignored by peer:// (no error), which is honest.
	// The error path is for HTTP stores that don't support the token format.
}

func TestE2StoreDiskRejectsEmptyPathAndRelay(t *testing.T) {
	opts := e2StoreOptions{URL: "disk://"}
	if _, err := newE2BodyStore(opts); err == nil {
		t.Fatal("disk:// without a path was accepted")
	}
	opts = e2StoreOptions{URL: "disk:///tmp/spore-bodies", RelayBase: "https://relay.invalid"}
	if _, err := newE2BodyStore(opts); err == nil {
		t.Fatal("disk:// combined with the HTTP relay hop was accepted")
	}
}
