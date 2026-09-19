package nostr

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"

	"github.com/liqdmetal/spore/internal/store"
)

// fakePool is an in-memory relay commons: it holds published events and serves
// them back for matching filters, so the store can be tested with no network.
type fakePool struct {
	mu     sync.Mutex
	events []nostr.Event
	// failPublish / failQuery let a test simulate an unreachable commons.
	failPublish bool
	failQuery   bool
	// serveForged, when set, makes Query return a tampered copy of a stored
	// event (simulating a hostile relay).
	serveForged func(ev nostr.Event) nostr.Event
}

func (p *fakePool) Publish(_ context.Context, ev nostr.Event) error {
	if p.failPublish {
		return ErrNoRelay
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	return nil
}

func (p *fakePool) Query(_ context.Context, f nostr.Filter) ([]*nostr.Event, error) {
	if p.failQuery {
		return nil, ErrNoRelay
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []*nostr.Event{}
	for _, ev := range p.events {
		if len(f.Kinds) > 0 && !containsInt(f.Kinds, ev.Kind) {
			continue
		}
		if !matchesTags(ev.Tags, f.Tags) {
			continue
		}
		served := ev
		if p.serveForged != nil {
			served = p.serveForged(ev)
		}
		cp := served
		out = append(out, &cp)
	}
	return out, nil
}

// published returns everything the pool holds (test inspection).
func (p *fakePool) published() []nostr.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]nostr.Event(nil), p.events...)
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func matchesTags(tags nostr.Tags, want nostr.TagMap) bool {
	for k, vals := range want {
		got := tagValue(tags, k)
		ok := false
		for _, v := range vals {
			if got == v {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// testKey is a fixed valid secp256k1 private key (hex) for deterministic tests.
const testKey = "5ee1c8000be2852402b61ba7d79d06a2d8404e79b3c0c9d2ff1f8a7a1a6f0e2c"

func newTestStore(t *testing.T, pool Pool, indexPath string) *NostrStore {
	t.Helper()
	cfg := NostrStoreConfig{PrivateKey: testKey, IndexPath: indexPath, Pool: pool, Timeout: 5 * time.Second}
	s, err := NewNostrStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cidOf(b []byte) [32]byte { return sha256.Sum256(b) }

func TestNewNostrStoreValidation(t *testing.T) {
	if _, err := NewNostrStore(NostrStoreConfig{}); err == nil {
		t.Fatal("missing private key accepted")
	}
	if _, err := NewNostrStore(NostrStoreConfig{PrivateKey: "zz"}); err == nil {
		t.Fatal("malformed private key accepted")
	}
	if _, err := NewNostrStore(NostrStoreConfig{PrivateKey: testKey}); err == nil {
		t.Fatal("no relays and no pool accepted")
	}
	if _, err := NewNostrStore(NostrStoreConfig{PrivateKey: testKey, Relays: []string{""}}); err == nil {
		t.Fatal("empty relay URL accepted")
	}
	// A dedicated storage key that is valid constructs fine.
	if _, err := NewNostrStore(NostrStoreConfig{PrivateKey: testKey, Relays: []string{"wss://relay.example"}}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestNostrStoreRoundTrip(t *testing.T) {
	pool := &fakePool{}
	s := newTestStore(t, pool, "")

	body := []byte("ratcheted ciphertext bytes")
	cid := cidOf(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("get = %q, want %q", got, body)
	}

	// The published event carries NO plaintext other than base64 ciphertext,
	// is the right kind, and is tagged with cid+exp.
	evs := pool.published()
	if len(evs) != 1 {
		t.Fatalf("published %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Kind != BodyKind {
		t.Fatalf("kind = %d, want %d", ev.Kind, BodyKind)
	}
	if tagValue(ev.Tags, "cid") != hex.EncodeToString(cid[:]) {
		t.Fatalf("cid tag = %q", tagValue(ev.Tags, "cid"))
	}
	if tagValue(ev.Tags, "exp") == "" {
		t.Fatal("no exp tag: relays cannot honour advisory expiry")
	}
	raw, err := base64.StdEncoding.DecodeString(ev.Content)
	if err != nil || string(raw) != string(body) {
		t.Fatalf("event content is not base64(body): %v", err)
	}
	// Signed, and the signature verifies.
	if ok, err := ev.CheckSignature(); err != nil || !ok {
		t.Fatalf("published event is not validly signed: ok=%v err=%v", ok, err)
	}
}

func TestNostrStoreInterface(t *testing.T) {
	var _ store.Store = (*NostrStore)(nil)
}

func TestNostrStorePutRejectsWrongCID(t *testing.T) {
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	// A body that does not hash to the given CID must be refused: publishing
	// it would create a body nobody can ever fetch (Get rejects on hash).
	if err := s.Put(cidOf([]byte("other")), []byte("body"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("put with mismatched cid accepted")
	}
	if len(pool.published()) != 0 {
		t.Fatal("mismatched body was published")
	}
}

func TestNostrStorePutRejectsOversize(t *testing.T) {
	pool := &fakePool{}
	cfg := NostrStoreConfig{PrivateKey: testKey, Pool: pool, MaxBody: 64, Timeout: 5 * time.Second}
	s, err := NewNostrStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("x", 65))
	if err := s.Put(cidOf(body), body, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("oversize body accepted")
	} else if !strings.Contains(err.Error(), "mailbox") {
		t.Fatalf("error should steer to the mailbox for large bodies: %v", err)
	}
	if len(pool.published()) != 0 {
		t.Fatal("oversize body was published")
	}
}

func TestNostrStorePutRejectsExpiredDeadline(t *testing.T) {
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	body := []byte("x")
	if err := s.Put(cidOf(body), body, time.Now().Add(-time.Minute)); err == nil {
		t.Fatal("already-expired deadline accepted")
	}
	if err := s.Put(cidOf(body), body, time.Time{}); err == nil {
		t.Fatal("zero deadline accepted")
	}
	if err := s.Put(cidOf(body), nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("empty body accepted")
	}
}

func TestNostrStoreGetRejectsTamperedContentWithOriginalSignature(t *testing.T) {
	body := []byte("genuine ciphertext")
	cid := cidOf(body)

	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// The REALISTIC hostile relay: it swaps the content but cannot forge a
	// signature, so the event carries the original (now invalid) sig. The
	// signature check rejects it before anything else is trusted.
	pool.serveForged = func(ev nostr.Event) nostr.Event {
		out := ev
		out.Content = base64.StdEncoding.EncodeToString([]byte("attacker body"))
		return out
	}
	if _, err := s.Get(cid); err != store.ErrNotFound {
		t.Fatalf("tampered+invalid-sig err = %v, want ErrNotFound (signature rejected)", err)
	}
}

func TestNostrStoreGetRejectsHostileRelay(t *testing.T) {
	body := []byte("genuine ciphertext")
	cid := cidOf(body)

	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// DEFENSE IN DEPTH: suppose an adversary could produce a validly-signed
	// event with swapped bytes under our CID (e.g. they hold a signing key).
	// Content addressing still stops them: the served bytes must hash to the
	// requested CID, and attacker-chosen bytes do not.
	pool.serveForged = func(ev nostr.Event) nostr.Event {
		out := ev
		out.Content = base64.StdEncoding.EncodeToString([]byte("attacker body"))
		out.Tags = ev.Tags
		if err := out.Sign(testKey); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if _, err := s.Get(cid); err != ErrCIDMismatch {
		t.Fatalf("hostile body err = %v, want ErrCIDMismatch", err)
	}
}

func TestNostrStoreGetRejectsUnsignedOrForeignEvent(t *testing.T) {
	body := []byte("genuine ciphertext")
	cid := cidOf(body)
	cidHex := hex.EncodeToString(cid[:])

	pool := &fakePool{}
	s := newTestStore(t, pool, "")

	// An unsigned/badly-signed event tagged with our CID must be ignored —
	// a rogue relay cannot forge a body just by matching the tag.
	pool.mu.Lock()
	pool.events = append(pool.events, nostr.Event{
		Kind:      BodyKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{nostr.Tag{"cid", cidHex}},
		Content:   base64.StdEncoding.EncodeToString(body),
		PubKey:    strings.Repeat("ab", 32),
		// no Sig
	})
	pool.mu.Unlock()

	if _, err := s.Get(cid); err != store.ErrNotFound {
		t.Fatalf("forged unsigned event err = %v, want ErrNotFound", err)
	}
}

func TestNostrStoreGetHonoursExpiry(t *testing.T) {
	body := []byte("expiring body")
	cid := cidOf(body)
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Rewind the exp tag into the past, re-signing so it is otherwise valid:
	// simulates the body ageing out while still sitting on the relay.
	pool.mu.Lock()
	ev := pool.events[0]
	expired := nostr.Event{
		Kind:      ev.Kind,
		CreatedAt: ev.CreatedAt,
		Tags:      nostr.Tags{nostr.Tag{"cid", hex.EncodeToString(cid[:])}, nostr.Tag{"exp", "1"}},
		Content:   ev.Content,
	}
	if err := expired.Sign(testKey); err != nil {
		t.Fatal(err)
	}
	pool.events = []nostr.Event{expired}
	pool.mu.Unlock()

	if _, err := s.Get(cid); err != store.ErrExpired {
		t.Fatalf("expired body err = %v, want ErrExpired", err)
	}
}

func TestNostrStoreGetUnknownIsNotFound(t *testing.T) {
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if _, err := s.Get(cidOf([]byte("never stored"))); err != store.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestNostrStoreAllRelaysDownIsAnError(t *testing.T) {
	pool := &fakePool{failQuery: true, failPublish: true}
	s := newTestStore(t, pool, "")
	body := []byte("x")
	if err := s.Put(cidOf(body), body, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("put succeeded with no reachable relay")
	}
	// A network outage must NOT masquerade as "not found" — that would make
	// the user think the body was reaped when it is still out there.
	if _, err := s.Get(cidOf(body)); err == nil || err == store.ErrNotFound {
		t.Fatalf("relay outage reported as %v; must be a distinct error", err)
	}
}

func TestNostrStoreDeleteIssuesNIP09(t *testing.T) {
	pool := &fakePool{}
	indexPath := filepath.Join(t.TempDir(), "index.json")
	s := newTestStore(t, pool, indexPath)

	body := []byte("delete me")
	cid := cidOf(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}
	if err := s.Delete(cid); err != nil {
		t.Fatal(err)
	}
	// A kind-5 deletion request referencing the body event must exist.
	evs := pool.published()
	var deletion *nostr.Event
	for i := range evs {
		if evs[i].Kind == deletionKind {
			deletion = &evs[i]
		}
	}
	if deletion == nil {
		t.Fatal("no NIP-09 deletion request published")
	}
	if tagValue(deletion.Tags, "e") == "" {
		t.Fatal("deletion request has no e tag")
	}
	if ok, err := deletion.CheckSignature(); err != nil || !ok {
		t.Fatalf("deletion request not validly signed: %v %v", ok, err)
	}
	// Locally it is gone from the index.
	if s.Len() != 0 {
		t.Fatalf("len after delete = %d, want 0", s.Len())
	}
}

func TestNostrStoreDeleteUnknownIsNotFound(t *testing.T) {
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if err := s.Delete(cidOf([]byte("nope"))); err != store.ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestNostrStoreReapOnlyExpired(t *testing.T) {
	pool := &fakePool{}
	indexPath := filepath.Join(t.TempDir(), "index.json")
	s := newTestStore(t, pool, indexPath)

	old := []byte("old body")
	live := []byte("live body")
	if err := s.Put(cidOf(old), old, time.Now().Add(-time.Minute)); err == nil {
		t.Fatal("put of already-expired body should fail")
	}
	// Put a body with a deadline just past, then reap.
	if err := s.Put(cidOf(live), live, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Artificially age the index entry so Reap has something due.
	s.mu.Lock()
	for cid, e := range s.index {
		e.Deadline = time.Now().Add(-time.Minute).Unix()
		s.index[cid] = e
	}
	s.mu.Unlock()

	if n := s.Reap(time.Now()); n != 1 {
		t.Fatalf("reap = %d, want 1", n)
	}
	if s.Len() != 0 {
		t.Fatalf("len after reap = %d, want 0", s.Len())
	}
}

func TestNostrStoreIndexPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	pool := &fakePool{}
	s := newTestStore(t, pool, indexPath)

	body := []byte("persisted body")
	cid := cidOf(body)
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Restart: a new store over the same index + the same pool.
	s2 := newTestStore(t, pool, indexPath)
	if s2.Len() != 1 {
		t.Fatalf("index not restored: len = %d", s2.Len())
	}
	// Delete after restart still finds the event id from the index (no relay
	// query needed) and issues the deletion.
	before := len(pool.published())
	if err := s2.Delete(cid); err != nil {
		t.Fatal(err)
	}
	if len(pool.published()) != before+1 {
		t.Fatal("delete after restart did not publish a deletion request")
	}
	if s2.Len() != 0 {
		t.Fatalf("len after delete = %d", s2.Len())
	}

	// Index file perms: 0600 on POSIX (Windows reports 0666).
	fi, err := os.Stat(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if p := fi.Mode().Perm(); p != 0o600 && p != 0o666 {
		t.Fatalf("index perms = %o", p)
	}
}

func TestNostrStoreIndexSurvivesCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	// One valid entry + one with a non-hex key: the load must skip the bad
	// entry rather than failing the whole store.
	valid := map[string]indexEntry{
		strings.Repeat("ab", 32): {EventID: "ev1", Deadline: 123},
		"not-hex!!":              {EventID: "ev2"},
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t, &fakePool{}, indexPath)
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1 (corrupt entry skipped)", s.Len())
	}
}

func TestNostrStoreMalformedIndexIsError(t *testing.T) {
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	if err := os.WriteFile(indexPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNostrStore(NostrStoreConfig{PrivateKey: testKey, Pool: &fakePool{}, IndexPath: indexPath}); err == nil {
		t.Fatal("malformed index silently ignored")
	}
}

func TestNostrStoreGetDeduplicatesAcrossRelays(t *testing.T) {
	body := []byte("dedup body")
	cid := cidOf(body)
	pool := &fakePool{}
	s := newTestStore(t, pool, "")
	if err := s.Put(cid, body, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Two relays both hold the same event: Query merges by ID, so Get must
	// still return exactly one correct body.
	pool.mu.Lock()
	pool.events = append(pool.events, pool.events[0])
	pool.mu.Unlock()

	got, err := s.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("get = %q", got)
	}
}
