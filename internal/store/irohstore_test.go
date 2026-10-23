package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"

	"testing"
	"time"
)

// irohBin returns the configured iroh binary, or skips if none is available.
// Like the IPFS live tests, these run only when a real substrate exists, so
// the suite stays honest on a box with no iroh instead of pretending.
func irohBin(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("SPORE_IROH_BIN"); b != "" {
		if _, err := exec.LookPath(b); err != nil {
			t.Fatalf("SPORE_IROH_BIN=%q not on PATH", b)
		}
		return b
	}
	if _, err := exec.LookPath("spore-iroh"); err != nil {
		t.Skip("no spore-iroh sidecar on PATH (set SPORE_IROH_BIN); skipping live Iroh test")
	}
	return "spore-iroh"
}

func isolateIrohStoreEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("SPORE_IROH_STORE", filepath.Join(dir, "blobs"))
	t.Setenv("SPORE_IROH_PROVIDERS", "")
}

func newIrohStore(t *testing.T) *IrohStore {
	t.Helper()
	dir := t.TempDir()
	isolateIrohStoreEnv(t, dir)
	s, err := NewIrohStore(IrohConfig{
		Cmd:       irohBin(t),
		IndexPath: filepath.Join(dir, "iroh-index.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newIrohStoreAt(t *testing.T, dir string) *IrohStore {
	t.Helper()
	isolateIrohStoreEnv(t, dir)
	s, err := NewIrohStore(IrohConfig{
		Cmd:       irohBin(t),
		IndexPath: filepath.Join(dir, "iroh-index.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cidSum(b []byte) [32]byte { return sha256.Sum256(b) }

// TestLiveIrohRoundTrip exercises the real sidecar against a per-test local
// store, then reopens the Go index. Provider discovery is disabled so this
// integration test performs no external network traffic.
func TestLiveIrohRoundTrip(t *testing.T) {
	if os.Getenv("SPORE_RUN_LIVE_IROH") != "1" {
		t.Skip("set SPORE_RUN_LIVE_IROH=1 to run the local sidecar integration test")
	}
	s := newIrohStore(t)

	body := make([]byte, 64<<10)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(cidSum(body), body, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(cidSum(body))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("round-trip not byte-exact: got %d want %d", len(got), len(body))
	}

	// Reopen the index and prove it finds the blob again after a restart.
	s2, err := NewIrohStore(IrohConfig{
		Cmd:       irohBin(t),
		IndexPath: s.idxPath,
	})
	if err != nil {
		t.Fatalf("reopen index: %v", err)
	}
	got2, err := s2.Get(cidSum(body))
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got2, body) {
		t.Fatal("body changed after reopen")
	}
}

// TestLiveIrohStoreRequiresIndexPath rejects an empty index path — the store
// must survive restart by knowing where its contents are.
func TestIrohStoreRequiresIndexPath(t *testing.T) {
	if _, err := NewIrohStore(IrohConfig{Cmd: "missing-spore-iroh"}); err == nil {
		t.Fatal("accepted empty IndexPath")
	}
}

// TestIrohStoreCIDOnlyLookupRequiresLocalIndex documents the lookup boundary:
// CID-only Get needs a local index; a remote receiver uses GetWithLocator with
// the BLAKE3 locator carried by the authenticated E2 pointer.
func TestIrohStoreCIDOnlyLookupRequiresLocalIndex(t *testing.T) {
	cid := cidSum([]byte("remote E2 body has no local Iroh mapping"))
	s := &IrohStore{index: map[string]irohEntry{}}
	if _, err := s.Get(cid); err != ErrNotFound {
		t.Fatalf("Get without a local CID mapping = %v, want ErrNotFound", err)
	}
}

// TestLiveIrohDetectsCorruption: if a blob on the network does not hash to the
// requested CID, Get must fail with an integrity error rather than return it.
func TestLiveIrohDetectsCorruption(t *testing.T) {
	if os.Getenv("SPORE_RUN_LIVE_IROH") != "1" {
		t.Skip("set SPORE_RUN_LIVE_IROH=1 to run the local sidecar integration test")
	}
	s := newIrohStore(t)
	body := []byte("the real body")
	other := []byte("a TAMPERED body that a malicious node swapped in")

	cid := cidSum(body)
	if err := s.Put(cidSum(body), body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Store a DIFFERENT blob and repoint the index entry at it, simulating a
	// node that returns the wrong bytes for our hash.
	tp := filepath.Join(t.TempDir(), "t.blob")
	if err := os.WriteFile(tp, other, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := s.runner.add(tp)
	if err != nil {
		t.Fatalf("add tampered blob: %v", err)
	}
	locator, err := parseIrohHash(string(out))
	if err != nil {
		t.Fatalf("parse tampered blob locator: %v", err)
	}
	s.mu.Lock()
	s.index[irohHex(cid)] = irohEntry{
		IrohHash: irohHex(locator),
		Deadline: time.Now().Add(time.Hour).Unix(),
		Size:     len(other),
	}
	s.mu.Unlock()

	if _, err := s.Get(cidSum(body)); err == nil {
		t.Fatal("corrupted blob returned without an integrity failure")
	}
}
