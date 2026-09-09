package store

// Live IPFS integration test. It is SKIPPED unless SPORE_IPFS_API is set, so
// the normal test suite never depends on a running daemon:
//
//	SPORE_IPFS_API=http://127.0.0.1:5001 go test ./internal/store -run TestLiveIPFS -v
//
// This is the test that distinguishes "we wrote a Kubo client" from "the Kubo
// client works against a real daemon". Everything else in this package is
// stubs; this one hits a live node, so it proves add/pin/cat/unpin for real.

import (
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func liveIPFS(t *testing.T) *IPFSStore {
	t.Helper()
	api := os.Getenv("SPORE_IPFS_API")
	if api == "" {
		t.Skip("SPORE_IPFS_API not set; skipping live IPFS test")
	}
	s, err := NewIPFSStore(IPFSConfig{
		APIURL:    api,
		IndexPath: filepath.Join(t.TempDir(), "idx.json"),
		Timeout:   60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Health(); err != nil {
		t.Fatalf("daemon at %s is not healthy: %v", api, err)
	}
	return s
}

// TestLiveIPFSRoundTrip: add a body, read it back byte-exact, verify the CID.
func TestLiveIPFSRoundTrip(t *testing.T) {
	s := liveIPFS(t)

	data := make([]byte, 64<<10) // 64 KiB, a realistic newsletter body
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	cid := sha256.Sum256(data)

	if err := s.Put(cid, data, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("Put to live daemon: %v", err)
	}
	path, ok := s.PathOf(cid)
	if !ok {
		t.Fatal("no ipfs path recorded after Put")
	}
	t.Logf("stored %d bytes at %s", len(data), path)

	got, err := s.Get(cid)
	if err != nil {
		t.Fatalf("Get from live daemon: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("got %d bytes, want %d", len(got), len(data))
	}
	if sha256.Sum256(got) != cid {
		t.Fatal("body fetched from IPFS does not match its CID")
	}
	t.Log("live IPFS round trip byte-exact")

	// Delete must unpin without error.
	if err := s.Delete(cid); err != nil {
		t.Fatalf("Delete (unpin): %v", err)
	}
	if _, ok := s.PathOf(cid); ok {
		t.Fatal("index still lists the body after Delete")
	}
}

// TestLiveIPFSDetectsCorruption proves the integrity guarantee is OURS, not the
// daemon's: a body fetched under the wrong CID must be rejected.
func TestLiveIPFSDetectsCorruption(t *testing.T) {
	s := liveIPFS(t)

	data := []byte("the real newsletter body")
	cid := sha256.Sum256(data)
	if err := s.Put(cid, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Delete(cid) }()

	// Point a DIFFERENT cid at the same ipfs path, simulating a lying index or
	// a substrate that serves the wrong object.
	other := sha256.Sum256([]byte("a different body entirely"))
	path, _ := s.PathOf(cid)
	s.mu.Lock()
	s.index[hexOf(other)] = ipfsEntry{Path: path, Deadline: time.Now().Add(time.Hour).Unix(), Size: len(data)}
	_ = s.saveIndexLocked()
	s.mu.Unlock()

	if _, err := s.Get(other); err == nil {
		t.Fatal("Get returned a body whose SHA-256 does not match the requested CID")
	} else {
		t.Logf("correctly rejected mismatched body: %v", err)
	}
}

// TestLiveIPFSMultiStoreSurvivesIPFSLoss is the archive claim end to end: a
// body mirrored to disk + live IPFS is still recoverable when IPFS is gone.
func TestLiveIPFSMultiStoreSurvivesIPFSLoss(t *testing.T) {
	ipfs := liveIPFS(t)

	disk, err := NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ms, err := NewMultiStore(
		Substrate{Name: "ipfs", Store: ipfs},
		Substrate{Name: "disk", Store: disk},
	)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("issue #1: the well came in at 40 feet")
	cid := sha256.Sum256(data)
	rep, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mirrored: %s", rep)
	if !rep.Durable() {
		t.Fatalf("expected a durable (multi-substrate) write, got %s", rep)
	}

	// Both substrates must independently hold a verified copy.
	avail := ms.Availability(cid)
	for name, ok := range avail {
		t.Logf("available on %-6s %v", name, ok)
		if !ok {
			t.Fatalf("substrate %s does not hold a verified copy", name)
		}
	}

	// Now lose IPFS entirely: unpin and drop it from the index.
	if err := ipfs.Delete(cid); err != nil {
		t.Fatal(err)
	}
	got, err := ms.Get(cid)
	if err != nil {
		t.Fatalf("body unrecoverable after losing IPFS: %v", err)
	}
	if sha256.Sum256(got) != cid {
		t.Fatal("recovered body failed verification")
	}
	t.Log("archive survived losing the IPFS substrate")
	_ = ms.Delete(cid)
}

func hexOf(b [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
