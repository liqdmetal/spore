package main

// Drain-union tests (F3; AUDIT-RELAYFABRIC.md R-N1): the recipient's
// consumed-CID store must dedupe N-relay redundancy BEFORE the body fetch,
// must keep a failed ingest eligible for redelivery, and must survive a
// restart. These exercise the loop-level pieces (the same Observe/Forget/
// ingest sequence fabricSubscribe's drainOnce runs) against the real
// ingestor and the real SeenCIDs file format.

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/fabric"
	"github.com/liqdmetal/spore/internal/maildb"
	"github.com/liqdmetal/spore/internal/ratchetwire"
	"github.com/liqdmetal/spore/internal/store"
)

// Kit globals shared with fabriccmd_test.go: the drain-union tests need the
// SENDER side (to mint a second, distinct pointer on the live session).
var (
	fabricKitSender  *ratchetwire.DurableEndpoint
	fabricKitSession [8]byte
)

// ingestWithUnion mirrors drainOnce's per-pointer sequence: union gate,
// ingest, un-mark on failure. Returns whether the pointer ingested.
func ingestWithUnion(ing *e2Ingestor, seen *fabric.SeenCIDs, raw []byte) bool {
	if !seen.Observe(raw) {
		return false // duplicate: skipped before the fetch
	}
	if _, ok := ing.ingestPointer(raw, time.Now()); !ok {
		seen.Forget(raw)
		return false
	}
	return true
}

// TestDrainUnionDedupesAcrossRelays: the same pointer "delivered" by two
// relays must ingest exactly once — one decrypt, one maildb record — and
// the second relay's copy must be skipped BEFORE the body fetch (pinned by
// the union's decision, observable as a single maildb row and a second
// Observe returning false).
func TestDrainUnionDedupesAcrossRelays(t *testing.T) {
	shared, ep, _, raw := fabricDrainKit(t)
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ing := &e2Ingestor{st: shared, ep: ep, mdb: db}
	seen := fabric.NewSeenCIDs("") // memory-only for the loop-level test

	// Relay A delivers the pointer.
	if !ingestWithUnion(ing, seen, raw) {
		t.Fatal("relay A's copy must ingest")
	}
	// Relay B delivers the SAME pointer (identical CID — that is what
	// -route-fabric redundancy means).
	if ingestWithUnion(ing, seen, raw) {
		t.Fatal("relay B's duplicate must be skipped by the union")
	}
	// Exactly one message in maildb.
	if msgs := db.SearchSimple("via fabric"); len(msgs) != 1 {
		t.Fatalf("N-relay redundancy must yield ONE ingest, got %d maildb rows", len(msgs))
	}
	// A different pointer (different CID) from relay B still ingests — the
	// union dedupes by CID, it does not collapse distinct messages.
	raw2 := fabricNextMessage()
	if !ingestWithUnion(ing, seen, raw2) {
		t.Fatal("a distinct pointer must ingest even after dedupe of the first")
	}
}

// TestDrainUnionKeepsFailedIngestEligible: when the body fetch fails (the
// sender's store is not yet reachable — the reason redundancy exists), the
// union must NOT consume the CID: a later delivery from another relay stays
// eligible and succeeds. This is the CONSUMED-set contract.
func TestDrainUnionKeepsFailedIngestEligible(t *testing.T) {
	shared, ep, _, raw := fabricDrainKit(t)
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ing := &e2Ingestor{st: shared, ep: ep, mdb: db}
	seen := fabric.NewSeenCIDs("")

	// Starve the first delivery: an ingestor whose body store cannot fetch
	// (the sender's store is unreachable — the exact case redundancy exists
	// for). Same ratchet state, so the RouteKey binding still holds.
	blocked := &e2Ingestor{st: starvingStore{Store: shared}, ep: ep, mdb: db}
	if ingestWithUnion(blocked, seen, raw) {
		t.Fatal("the starved first delivery must fail")
	}
	// The union must have FORGOTTEN the failed CID: eligible again.
	if seen.Seen(cidHexOf(raw)) {
		t.Fatal("a failed ingest must not stay marked in the union")
	}
	// The second delivery (relay B, store healthy) succeeds.
	if !ingestWithUnion(ing, seen, raw) {
		t.Fatal("the redundant delivery must ingest after the failed first")
	}
	if msgs := db.SearchSimple("via fabric"); len(msgs) != 1 {
		t.Fatalf("exactly one ingest expected, got %d", len(msgs))
	}
}

// TestDrainUnionSurvivesRestart: the persisted union stops a restarted
// recipient from re-draining still-queued copies on every relay.
func TestDrainUnionSurvivesRestart(t *testing.T) {
	shared, ep, _, raw := fabricDrainKit(t)
	dbPath := filepath.Join(t.TempDir(), "mail.json")
	db, err := maildb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ing := &e2Ingestor{st: shared, ep: ep, mdb: db}
	stateDir := t.TempDir()
	seen := fabric.NewSeenCIDs(filepath.Join(stateDir, "fabric-seen.txt"))

	if !ingestWithUnion(ing, seen, raw) {
		t.Fatal("first delivery must ingest")
	}
	// "Restart": a fresh union store over the same file — plus a fresh
	// ingestor/maildb pair the way a restarted process would see them.
	seen2 := fabric.NewSeenCIDs(filepath.Join(stateDir, "fabric-seen.txt"))
	if ingestWithUnion(ing, seen2, raw) {
		t.Fatal("after restart the still-queued copy must be skipped by the persisted union")
	}
	if msgs := db.SearchSimple("via fabric"); len(msgs) != 1 {
		t.Fatalf("restart must not re-ingest, got %d maildb rows", len(msgs))
	}
}

func cidHexOf(raw []byte) string {
	return hex.EncodeToString(raw[34:66])
}

// fabricNextMessage sends one more message on the kit's live session and
// returns the raw pointer (a "next distinct delivery" from another relay).
// Depends on fabricDrainKit having run in the same test (it holds the
// sender endpoint in fabricKitSender).
func fabricNextMessage() []byte {
	_, raw, err := fabricKitSender.SendNext(fabricKitSession, []byte("second via fabric"), time.Now().Add(time.Hour))
	if err != nil {
		panic(err)
	}
	return raw
}

// starvingStore serves Get failures for every CID (simulates an unreachable
// sender body store) while embedding the real store for everything else.
type starvingStore struct {
	store.Store
}

var errStarved = errors.New("starved: sender store unreachable (simulated)")

func (s starvingStore) Get(cid [32]byte) ([]byte, error) {
	return nil, errStarved
}
