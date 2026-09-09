package store

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// stubStore is a controllable Store for MultiStore tests: it can fail, lie
// (return bytes that do not match the CID), or work normally.
type stubStore struct {
	name     string
	bodies   map[[32]byte][]byte
	putErr   error
	getErr   error
	delErr   error
	lie      bool // return corrupted bytes on Get
	putCalls int
}

func newStub(name string) *stubStore {
	return &stubStore{name: name, bodies: map[[32]byte][]byte{}}
}

func (s *stubStore) Put(cid [32]byte, body []byte, _ time.Time) error {
	s.putCalls++
	if s.putErr != nil {
		return s.putErr
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	s.bodies[cid] = cp
	return nil
}

func (s *stubStore) Get(cid [32]byte) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	b, ok := s.bodies[cid]
	if !ok {
		return nil, ErrNotFound
	}
	if s.lie {
		return []byte("this is not the body you asked for"), nil
	}
	return b, nil
}

func (s *stubStore) Delete(cid [32]byte) error {
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.bodies, cid)
	return nil
}

func (s *stubStore) Reap(time.Time) int { return 0 }
func (s *stubStore) Len() int           { return len(s.bodies) }

func body(t *testing.T, n int) ([]byte, [32]byte) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b, sha256.Sum256(b)
}

func TestMultiStoreMirrorsToEverySubstrate(t *testing.T) {
	a, b, c := newStub("a"), newStub("b"), newStub("c")
	ms, err := NewMultiStore(
		Substrate{Name: "a", Store: a},
		Substrate{Name: "b", Store: b},
		Substrate{Name: "c", Store: c},
	)
	if err != nil {
		t.Fatal(err)
	}

	data, cid := body(t, 4096)
	rep, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Accepted) != 3 || len(rep.Failed) != 0 {
		t.Fatalf("report = %s", rep)
	}
	if !rep.Durable() {
		t.Fatal("three substrates should be durable")
	}
	// Every substrate must hold it independently.
	for _, s := range []*stubStore{a, b, c} {
		if _, ok := s.bodies[cid]; !ok {
			t.Fatalf("substrate %s did not store the body", s.name)
		}
	}
	got, err := ms.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != cid {
		t.Fatal("Get returned bytes that do not match the cid")
	}
}

// TestSurvivesLosingSubstrates is the archive property: the whole point of
// mirroring is that backends can die.
func TestSurvivesLosingSubstrates(t *testing.T) {
	a, b, c := newStub("a"), newStub("b"), newStub("c")
	ms, _ := NewMultiStore(
		Substrate{Name: "a", Store: a},
		Substrate{Name: "b", Store: b},
		Substrate{Name: "c", Store: c},
	)
	data, cid := body(t, 2048)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Kill two of three.
	a.getErr = errors.New("disk died")
	b.getErr = errors.New("operator seized")

	got, err := ms.Get(cid)
	if err != nil {
		t.Fatalf("body should still be recoverable from the last substrate: %v", err)
	}
	if sha256.Sum256(got) != cid {
		t.Fatal("recovered body failed verification")
	}

	// Kill the last one: now it is genuinely gone, and that must be an error
	// rather than a silent empty body.
	c.getErr = errors.New("relay expired it")
	if _, err := ms.Get(cid); err == nil {
		t.Fatal("Get succeeded with every substrate down")
	}
}

// TestByzantineSubstrateIsSkipped: a substrate that returns wrong bytes must
// not poison a read. This is what makes fetching from public infrastructure
// safe at all.
func TestByzantineSubstrateIsSkipped(t *testing.T) {
	liar, honest := newStub("liar"), newStub("honest")
	ms, _ := NewMultiStore(
		Substrate{Name: "liar", Store: liar}, // tried FIRST
		Substrate{Name: "honest", Store: honest},
	)
	data, cid := body(t, 1024)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	liar.lie = true

	got, err := ms.Get(cid)
	if err != nil {
		t.Fatalf("a lying substrate blocked the read: %v", err)
	}
	if sha256.Sum256(got) != cid {
		t.Fatal("MultiStore returned corrupted bytes")
	}
}

// TestAllSubstratesLyingIsReportedAsCorruption, not as "not found": the
// operator needs to know their mirrors are serving garbage.
func TestAllSubstratesLyingIsReportedAsCorruption(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	ms, _ := NewMultiStore(Substrate{Name: "a", Store: a}, Substrate{Name: "b", Store: b})
	data, cid := body(t, 512)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	a.lie, b.lie = true, true

	_, err := ms.Get(cid)
	if err == nil {
		t.Fatal("corrupted reads succeeded")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error should wrap ErrNotFound: %v", err)
	}
	// And it must name the offending substrates, not just fail vaguely.
	if !contains(err.Error(), "DID NOT MATCH") {
		t.Fatalf("error should report the CID mismatch: %v", err)
	}
}

func TestPartialWriteIsASuccessWithAWarning(t *testing.T) {
	good, bad := newStub("good"), newStub("bad")
	bad.putErr = errors.New("ipfs daemon down")
	ms, _ := NewMultiStore(Substrate{Name: "good", Store: good}, Substrate{Name: "bad", Store: bad})

	data, cid := body(t, 256)
	rep, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("one failing backend must not block publishing: %v", err)
	}
	if len(rep.Accepted) != 1 || len(rep.Failed) != 1 {
		t.Fatalf("report = %s", rep)
	}
	// A single-substrate write is NOT durable and must say so.
	if rep.Durable() {
		t.Fatal("one substrate reported as durable")
	}
	if !contains(rep.String(), "not durable") {
		t.Fatalf("report should warn: %s", rep)
	}
}

func TestPutFailsOnlyWhenEverySubstrateFails(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	a.putErr = errors.New("down")
	b.putErr = errors.New("down")
	ms, _ := NewMultiStore(Substrate{Name: "a", Store: a}, Substrate{Name: "b", Store: b})

	data, cid := body(t, 128)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("Put succeeded with every substrate failing")
	}
}

// TestPutRejectsMismatchedCID: storing a body under the wrong address makes it
// unfetchable on every substrate at once, so it must be caught before any write.
func TestPutRejectsMismatchedCID(t *testing.T) {
	a := newStub("a")
	ms, _ := NewMultiStore(Substrate{Name: "a", Store: a})
	data, _ := body(t, 64)
	var wrong [32]byte
	wrong[0] = 0xff

	if _, err := ms.PutWithReport(wrong, data, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("MultiStore stored a body under a cid that does not match it")
	}
	if a.putCalls != 0 {
		t.Fatal("a mismatched body was written to a substrate before validation")
	}
}

func TestReadOnlySubstrateServesReadsButNotWrites(t *testing.T) {
	rw, ro := newStub("rw"), newStub("ro")
	ms, _ := NewMultiStore(
		Substrate{Name: "rw", Store: rw},
		Substrate{Name: "ro", Store: ro, ReadOnly: true},
	)
	data, cid := body(t, 256)
	rep, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Accepted) != 1 || rep.Accepted[0] != "rw" {
		t.Fatalf("read-only substrate was written to: %s", rep)
	}
	if ro.putCalls != 0 {
		t.Fatal("Put reached a read-only substrate")
	}

	// But a body already present on the read-only mirror must be readable.
	ro.bodies[cid] = data
	rw.getErr = errors.New("primary down")
	if _, err := ms.Get(cid); err != nil {
		t.Fatalf("read-only mirror did not serve a read: %v", err)
	}
}

func TestAllReadOnlyCannotPublish(t *testing.T) {
	ro := newStub("ro")
	ms, _ := NewMultiStore(Substrate{Name: "ro", Store: ro, ReadOnly: true})
	data, cid := body(t, 32)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("publishing succeeded with no writable substrate")
	}
}

func TestAvailabilityCountsIndependentCopies(t *testing.T) {
	a, b, c := newStub("a"), newStub("b"), newStub("c")
	ms, _ := NewMultiStore(
		Substrate{Name: "a", Store: a},
		Substrate{Name: "b", Store: b},
		Substrate{Name: "c", Store: c},
	)
	data, cid := body(t, 512)
	if _, err := ms.PutWithReport(cid, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	b.getErr = errors.New("down")
	c.lie = true // present but serving garbage: NOT a real copy

	avail := ms.Availability(cid)
	if !avail["a"] {
		t.Fatal("healthy substrate reported unavailable")
	}
	if avail["b"] {
		t.Fatal("down substrate reported available")
	}
	if avail["c"] {
		t.Fatal("a substrate serving corrupted bytes was counted as a copy")
	}
}

func TestNewMultiStoreValidates(t *testing.T) {
	if _, err := NewMultiStore(); err == nil {
		t.Fatal("empty MultiStore accepted")
	}
	if _, err := NewMultiStore(Substrate{Name: "", Store: newStub("x")}); err == nil {
		t.Fatal("unnamed substrate accepted")
	}
	if _, err := NewMultiStore(Substrate{Name: "a", Store: nil}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewMultiStore(
		Substrate{Name: "dup", Store: newStub("a")},
		Substrate{Name: "dup", Store: newStub("b")},
	); err == nil {
		t.Fatal("duplicate substrate names accepted")
	}
}

func TestNamesAndLen(t *testing.T) {
	a, b := newStub("a"), newStub("b")
	ms, _ := NewMultiStore(
		Substrate{Name: "disk", Store: a},
		Substrate{Name: "ipfs", Store: b, ReadOnly: true},
	)
	names := ms.Names()
	if len(names) != 2 || names[0] != "disk" || names[1] != "ipfs (ro)" {
		t.Fatalf("names = %v", names)
	}
	// Len is the max across substrates, not the sum (mirrors are the same body).
	data, cid := body(t, 64)
	_ = a.Put(cid, data, time.Now())
	_ = b.Put(cid, data, time.Now())
	if got := ms.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (mirrors must not be double-counted)", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// ---- IPFSStore unit tests that need no daemon ----

func TestNewIPFSStoreValidates(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewIPFSStore(IPFSConfig{APIURL: "", IndexPath: filepath.Join(dir, "i.json")}); err == nil {
		t.Fatal("empty API URL accepted")
	}
	if _, err := NewIPFSStore(IPFSConfig{APIURL: "http://127.0.0.1:5001", IndexPath: ""}); err == nil {
		t.Fatal("empty index path accepted: the store could not find its own bodies after a restart")
	}
	s, err := NewIPFSStore(IPFSConfig{
		APIURL:    "http://127.0.0.1:5001/",
		IndexPath: filepath.Join(dir, "idx.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("fresh store Len = %d", s.Len())
	}
	if _, ok := s.PathOf(sha256.Sum256([]byte("nope"))); ok {
		t.Fatal("unknown cid reported as present")
	}
}

func TestIPFSStoreIndexSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	idx := filepath.Join(dir, "idx.json")
	cfg := IPFSConfig{APIURL: "http://127.0.0.1:5001", IndexPath: idx}

	s1, err := NewIPFSStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Inject an index entry the way a successful Put would, then reload.
	data, cid := body(t, 128)
	s1.mu.Lock()
	s1.index[fmt.Sprintf("%x", cid)] = ipfsEntry{
		Path:     "/ipfs/bafyfake",
		Deadline: time.Now().Add(time.Hour).Unix(),
		Size:     len(data),
	}
	err = s1.saveIndexLocked()
	s1.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	s2, err := NewIPFSStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 1 {
		t.Fatalf("reloaded index has %d entries, want 1", s2.Len())
	}
	p, ok := s2.PathOf(cid)
	if !ok || p != "/ipfs/bafyfake" {
		t.Fatalf("reloaded path = %q ok=%v", p, ok)
	}
}

func TestIPFSStoreHealthFailsWithNoDaemon(t *testing.T) {
	// Port 1 is reserved and never has a Kubo daemon.
	s, err := NewIPFSStore(IPFSConfig{
		APIURL:    "http://127.0.0.1:1",
		IndexPath: filepath.Join(t.TempDir(), "i.json"),
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Health(); err == nil {
		t.Fatal("Health passed with no daemon listening")
	}
}
