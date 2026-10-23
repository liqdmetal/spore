package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeIrohRunner struct {
	bodies   map[string][]byte
	locator  [32]byte
	badAdd   string
	requests []string
}

func (f *fakeIrohRunner) add(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if f.badAdd != "" {
		return []byte(f.badAdd), nil
	}
	hash := hex.EncodeToString(f.locator[:])
	f.bodies[hash] = append([]byte(nil), body...)
	return []byte(hash + "\n"), nil
}

func (f *fakeIrohRunner) get(hash string) ([]byte, error) {
	f.requests = append(f.requests, hash)
	body, ok := f.bodies[hash]
	if !ok {
		return nil, errors.New("not served")
	}
	return append([]byte(nil), body...), nil
}

func TestIrohPortableLocatorFetchesAcrossIndependentIndexes(t *testing.T) {
	locator := [32]byte{0x51, 0xA2}
	runner := &fakeIrohRunner{bodies: make(map[string][]byte), locator: locator}
	body := []byte("opaque encrypted E2 frame")
	cid := sha256.Sum256(body)
	deadline := time.Now().Add(time.Hour)

	sender := &IrohStore{cmd: "fake", idxPath: filepath.Join(t.TempDir(), "sender.json"), runner: runner, index: make(map[string]irohEntry)}
	gotLocator, err := sender.PutWithLocator(cid, body, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if gotLocator != locator {
		t.Fatalf("locator = %x, want %x", gotLocator, locator)
	}
	if got, err := sender.Get(cid); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("sender local lookup = %q, %v", got, err)
	}

	// The receiver's index is deliberately empty: the E2 pointer carries the
	// Iroh hash needed to locate the body on the sender's provider.
	receiver := &IrohStore{cmd: "fake", idxPath: filepath.Join(t.TempDir(), "receiver.json"), runner: runner, index: make(map[string]irohEntry)}
	got, err := receiver.GetWithLocator(cid, gotLocator)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("remote locator returned different body")
	}
	if len(runner.requests) != 2 || runner.requests[1] != hex.EncodeToString(locator[:]) {
		t.Fatalf("get requests = %v", runner.requests)
	}
}

func TestIrohPortableLocatorRejectsTamperingAndIndexConflict(t *testing.T) {
	locator := [32]byte{0x61, 0xB2}
	runner := &fakeIrohRunner{bodies: make(map[string][]byte), locator: locator}
	body := []byte("original ciphertext")
	cid := sha256.Sum256(body)
	hash := hex.EncodeToString(locator[:])
	runner.bodies[hash] = []byte("tampered ciphertext")
	receiver := &IrohStore{cmd: "fake", runner: runner, index: make(map[string]irohEntry)}
	if _, err := receiver.GetWithLocator(cid, locator); err == nil || !strings.Contains(err.Error(), "INTEGRITY FAILURE") {
		t.Fatalf("tamper error = %v", err)
	}

	other := [32]byte{0x62, 0xB2}
	receiver.index[irohHex(cid)] = irohEntry{IrohHash: irohHex(other)}
	if _, err := receiver.GetWithLocator(cid, locator); err == nil || !strings.Contains(err.Error(), "conflicts with local index") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestIrohPortableLocatorRejectsBadCIDAndMalformedNativeHash(t *testing.T) {
	locator := [32]byte{0x71, 0xC2}
	runner := &fakeIrohRunner{bodies: make(map[string][]byte), locator: locator}
	st := &IrohStore{cmd: "fake", idxPath: filepath.Join(t.TempDir(), "index.json"), runner: runner, index: make(map[string]irohEntry)}
	body := []byte("body")
	wrongCID := sha256.Sum256([]byte("not body"))
	if _, err := st.PutWithLocator(wrongCID, body, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("accepted a mismatched SHA-256 CID")
	}
	if len(st.index) != 0 || len(runner.bodies) != 0 {
		t.Fatal("bad CID reached the Iroh add command or index")
	}

	runner.badAdd = "not-64-hex"
	if _, err := st.PutWithLocator(sha256.Sum256(body), body, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("accepted malformed Iroh locator")
	}
	if len(st.index) != 0 {
		t.Fatal("malformed Iroh hash was persisted")
	}
}

func TestIrohIndexRejectsMalformedLocators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	bad := `{"` + strings.Repeat("a", 64) + `":{"iroh_hash":"bad","deadline":0,"size":1}}`
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	st := &IrohStore{idxPath: path, index: make(map[string]irohEntry)}
	if err := st.loadIndex(); err == nil {
		t.Fatal("loaded an index with malformed native locator")
	}
}

func TestIrohProbeRequiresPortableMinimalSidecar(t *testing.T) {
	valid := []byte("spore-iroh 0.1.0; " + requiredIrohCapabilities + "; iroh 1.2.0 / iroh-blobs 0.103.0")
	if err := validateIrohVersion(valid); err != nil {
		t.Fatalf("valid capability marker rejected: %v", err)
	}
	for _, old := range [][]byte{
		[]byte("iroh 0.1.0 (spore-iroh; Online preset)"),
		[]byte("iroh 1.2.0"),
	} {
		if err := validateIrohVersion(old); err == nil {
			t.Fatalf("accepted incompatible sidecar version %q", old)
		}
	}
}
