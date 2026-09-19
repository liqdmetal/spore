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
	if _, err := exec.LookPath("iroh"); err != nil {
		t.Skip("no iroh binary on PATH (set SPORE_IROH_BIN); skipping live iroh test")
	}
	return "iroh"
}

func newIrohStore(t *testing.T) *IrohStore {
	t.Helper()
	dir := t.TempDir()
	idx := filepath.Join(dir, "iroh-index.json")
	s, err := NewIrohStore(IrohConfig{Cmd: irohBin(t), IndexPath: idx})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cidSum(b []byte) [32]byte { return sha256.Sum256(b) }

func TestLiveIrohRoundTrip(t *testing.T) {
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
		t.Fatalf("round trip not byte-exact: got %d bytes want %d", len(got), len(body))
	}
	// Persisted index: reopen and find the body again (an archive that forgets
	// its own contents after a restart is not an archive).
	s2, err := NewIrohStore(IrohConfig{Cmd: irohBin(t), IndexPath: s.idxPath})
	if err != nil {
		t.Fatal(err)
	}
	got2, err := s2.Get(cidSum(body))
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got2, body) {
		t.Fatal("body differs after reopen")
	}
}

// TestLiveIrohDetectsCorruption: if a blob on the network does not hash to the
// requested CID, Get must fail with an integrity error rather than return it.
func TestLiveIrohDetectsCorruption(t *testing.T) {
	s := newIrohStore(t)
	body := []byte("the real body")
	other := []byte("a TAMPERED body that a malicious node swapped in")

	if err := s.Put(cidSum(body), body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Store a DIFFERENT blob and repoint the index entry at it, simulating a
	// node that returns the wrong bytes for our hash.
	tp := filepath.Join(t.TempDir(), "t.blob")
	if err := os.WriteFile(tp, other, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(s.cmd, "blob", "add", tp).Output()
	if err != nil {
		t.Skipf("cannot add tampered blob: %v", err)
	}
	s.mu.Lock()
	s.index[hexOf(cidSum(body))] = irohEntry{
		IrohHash: string(bytes.TrimSpace(out)),
		Deadline: time.Now().Add(time.Hour).Unix(),
		Size:     len(other),
	}
	s.mu.Unlock()

	if _, err := s.Get(cidSum(body)); err == nil {
		t.Fatal("corrupted blob returned without an integrity failure")
	}
}

func TestIrohStoreRequiresIndexPath(t *testing.T) {
	if _, err := NewIrohStore(IrohConfig{Cmd: irohBin(t), IndexPath: ""}); err == nil {
		t.Fatal("NewIrohStore accepted an empty IndexPath — bodies would be unfindable after restart")
	}
}
