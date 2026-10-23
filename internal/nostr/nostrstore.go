package nostr

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"

	"github.com/liqdmetal/spore/internal/store"
)

// NostrStore is a store.Store backed by public Nostr relays: the no-servers
// body store. Instead of an HTTP mailbox you (or a paid operator) run, bodies
// are published as signed events to a set of relays and fetched back by
// content address. Nobody operates a server for you; the relays are a shared
// commons and any subset of them can serve the body.
//
//	Kind:      BodyKind (a REGULAR NIP-01 kind — relays SHOULD store it, and
//	           regular kinds are not replaceable, so many CIDs coexist)
//	Tags:      ["cid", <64-hex>]  content address, the retrieval key
//	           ["exp", <unix>]    the burn deadline, advisory to relays
//	Content:   base64(ratchet ciphertext)
//
// HONEST LIMITS — read before relying on this:
//
//  1. Bodies are PUBLIC-BY-CID. Anyone who learns the CID can fetch the
//     ciphertext from any relay; there is no auth layer on a commons. The CID
//     is sha256(ciphertext) and is revealed only inside the ratchet-encrypted
//     pointer, so it is unguessable — the same trust model as the mailbox's
//     content-addressed /body/<cid> route, minus the operator. Ciphertext on a
//     public relay is inert without the per-message ratchet key.
//  2. Deletion is BEST-EFFORT. NIP-09 deletion requests are advisory: a relay
//     MAY ignore them, and relays you never published to may hold copies. The
//     real compost guarantee is the ratchet — consumed message keys are erased,
//     so a lingering ciphertext cannot be decrypted. Reap/Delete here shrink
//     the footprint; they do not promise global erasure.
//  3. SIZE CAP. Relays commonly reject large events, so bodies are capped
//     (DefaultMaxBody). Big attachments belong on the HTTP mailbox, not here.
//  4. Reap/Delete only work for bodies WE signed (we hold the key). A
//     recipient can Get a body it never Put, but cannot delete it — correct,
//     since deleting someone else's body would be a censorship vector.
//  5. Len reports the LOCAL published count, not a global relay census: a
//     commons has no authoritative index.

// BodyKind is the event kind for stored bodies. It sits in the NIP-01
// REGULAR range (1..3999): relays store regular events and do not treat them
// as replaceable, so distinct CIDs coexist instead of overwriting. Addressable
// (3xxxx) or replaceable (1xxxx) kinds would silently drop earlier bodies.
const BodyKind = 1977

// (deletionKind, the NIP-09 event-deletion kind, is already declared in
// nostr.go for the carrier's Burn; this store reuses it.)

// DefaultMaxBody caps a single stored body. base64 inflates by 4/3 and relays
// vary widely in their event-size limits, so this stays deliberately modest:
// it covers messages and small files, not media.
const DefaultMaxBody = 256 * 1024

var (
	// ErrBodyTooLarge means the body exceeds the configured cap.
	ErrBodyTooLarge = errors.New("nostrstore: body exceeds relay size cap")
	// ErrNoRelay means no relay was reachable for the operation.
	ErrNoRelay = errors.New("nostrstore: no relay available")
	// ErrCIDMismatch means a relay served bytes that do not hash to the
	// requested CID (faulty or hostile relay). Always rejected.
	ErrCIDMismatch = errors.New("nostrstore: served body does not hash to cid")
)

// Pool is the relay seam. Production code builds one over configured relay
// URLs; tests inject an in-memory fake so no network is needed.
type Pool interface {
	// Publish signs-and-sends ev to the pool (best-effort across relays).
	Publish(ctx context.Context, ev nostr.Event) error
	// Query returns events matching f, merged and de-duplicated across relays.
	Query(ctx context.Context, f nostr.Filter) ([]*nostr.Event, error)
}

// NostrStoreConfig configures a NostrStore.
type NostrStoreConfig struct {
	// PrivateKey signs body events (hex). Use a DEDICATED key for body
	// storage, NOT your ratchet identity or chain key: publishing bodies is
	// linkable by pubkey, and keeping it separate stops a relay from tying
	// your storage activity to your messaging identity.
	PrivateKey string
	// Relays are the wss:// URLs to publish to and query.
	Relays []string
	// IndexPath is the local cid -> event-id/deadline index that makes
	// Delete/Reap/Len work. Optional: without it, Put/Get still work but
	// Delete must rediscover the event id by querying relays, and Reap/Len
	// have nothing to iterate.
	IndexPath string
	// MaxBody caps stored body bytes (0 = DefaultMaxBody).
	MaxBody int
	// MaxIndexBytes caps bytes read from the durable local index (0 = 1 MiB).
	MaxIndexBytes int64
	// MaxIndexItems caps entries loaded from and written to the local index (0 = 4096).
	MaxIndexItems int
	// Timeout bounds each relay round trip (0 = 20s).
	Timeout time.Duration
	// Pool overrides relay dialling (tests). When nil, a pool is built from
	// Relays.
	Pool Pool
}

// NostrStore implements store.Store over Nostr relays.
type NostrStore struct {
	cfg           NostrStoreConfig
	pool          Pool
	maxBody       int
	maxIndexBytes int64
	maxIndexItems int
	timeout       time.Duration

	mu    sync.Mutex
	index map[[32]byte]indexEntry
}

type indexEntry struct {
	EventID  string `json:"event_id"`
	Deadline int64  `json:"deadline"` // unix seconds; 0 = none
}

var _ store.Store = (*NostrStore)(nil)

// NewNostrStore validates cfg and opens the store. It does not dial relays
// (connections are per-operation), so construction is offline-safe.
func NewNostrStore(cfg NostrStoreConfig) (*NostrStore, error) {
	if strings.TrimSpace(cfg.PrivateKey) == "" {
		return nil, errors.New("nostrstore: PrivateKey is required (use a dedicated body-store key)")
	}
	if _, err := nostr.GetPublicKey(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("nostrstore: bad private key: %w", err)
	}
	if cfg.Pool == nil {
		if len(cfg.Relays) == 0 {
			return nil, errors.New("nostrstore: Relays required (or inject a Pool)")
		}
		for _, u := range cfg.Relays {
			if strings.TrimSpace(u) == "" {
				return nil, errors.New("nostrstore: empty relay URL")
			}
		}
		cfg.Pool = &relayPool{relays: cfg.Relays}
	}
	maxBody := cfg.MaxBody
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	maxIndexBytes := cfg.MaxIndexBytes
	if maxIndexBytes <= 0 {
		maxIndexBytes = 1 << 20
	}
	maxIndexItems := cfg.MaxIndexItems
	if maxIndexItems <= 0 {
		maxIndexItems = 4096
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	s := &NostrStore{
		cfg:           cfg,
		pool:          cfg.Pool,
		maxBody:       maxBody,
		maxIndexBytes: maxIndexBytes,
		maxIndexItems: maxIndexItems,
		timeout:       timeout,
		index:         map[[32]byte]indexEntry{},
	}
	if cfg.IndexPath != "" {
		if err := s.loadIndex(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Put publishes body under cid, retained until deadline.
func (s *NostrStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	if s.cfg.IndexPath != "" {
		s.mu.Lock()
		_, exists := s.index[cid]
		tooMany := !exists && len(s.index) >= s.maxIndexItems
		s.mu.Unlock()
		if tooMany {
			return fmt.Errorf("nostrstore: local index at %d entries; delete or reap old bodies before publishing", s.maxIndexItems)
		}
	}
	if len(body) == 0 {
		return errors.New("nostrstore: empty body")
	}
	if len(body) > s.maxBody {
		return fmt.Errorf("%w: %d > %d (use the HTTP mailbox for large attachments)", ErrBodyTooLarge, len(body), s.maxBody)
	}
	// Defense in depth: the caller derives cid from the body, but a mismatch
	// here would publish an unretrievable body (Get rejects on hash).
	if sha256.Sum256(body) != cid {
		return errors.New("nostrstore: body does not hash to cid")
	}
	deadline = time.Unix(deadline.Unix(), 0)
	if deadline.IsZero() || !deadline.After(time.Now()) {
		return store.ErrExpired
	}

	tags := nostr.Tags{
		nostr.Tag{"cid", hex.EncodeToString(cid[:])},
		nostr.Tag{"exp", strconv.FormatInt(deadline.Unix(), 10)},
	}
	ev := nostr.Event{
		Kind:      BodyKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      tags,
		Content:   base64.StdEncoding.EncodeToString(body),
	}
	if err := ev.Sign(s.cfg.PrivateKey); err != nil {
		return fmt.Errorf("nostrstore: sign: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	if err := s.pool.Publish(ctx, ev); err != nil {
		return err
	}
	if err := s.recordIndex(cid, indexEntry{EventID: ev.ID, Deadline: deadline.Unix()}); err != nil {
		return fmt.Errorf("nostrstore: publish succeeded but local index update failed (body retained until deadline): %w", err)
	}
	return nil
}

// Get fetches a body by CID from the relays, rejecting anything that does not
// hash to cid or is past its advertised deadline.
func (s *NostrStore) Get(cid [32]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	cidHex := hex.EncodeToString(cid[:])
	evs, err := s.pool.Query(ctx, nostr.Filter{
		Kinds: []int{BodyKind},
		Tags:  nostr.TagMap{"cid": []string{cidHex}},
		Limit: 4,
	})
	if err != nil {
		return nil, err
	}
	var sawExpired bool
	for _, ev := range evs {
		if ev == nil || ev.Kind != BodyKind {
			continue
		}
		eventCID, ok := uniqueTagValue(ev.Tags, "cid")
		if !ok || eventCID != cidHex {
			continue // a relay returned an unrelated or ambiguous event
		}
		// Verify the publisher's signature: a rogue relay must not be able
		// to forge a body under a CID we asked for. (The hash check below
		// also binds content to cid; the sig additionally binds authorship.)
		if ok, verr := ev.CheckSignature(); verr != nil || !ok {
			continue
		}
		exp, expOK := uniqueTagValue(ev.Tags, "exp")
		if !expOK {
			continue
		}
		sec, perr := strconv.ParseInt(exp, 10, 64)
		if perr != nil || sec <= 0 {
			continue
		}
		if time.Now().Unix() >= sec {
			sawExpired = true
			continue
		}
		body, derr := base64.StdEncoding.DecodeString(ev.Content)
		if derr != nil || len(body) == 0 || len(body) > s.maxBody {
			continue
		}
		if sha256.Sum256(body) != cid {
			// Hostile/faulty relay serving different bytes under our CID.
			return nil, ErrCIDMismatch
		}
		return body, nil
	}
	if sawExpired {
		return nil, store.ErrExpired
	}
	return nil, store.ErrNotFound
}

// Delete requests removal (NIP-09) of the event carrying cid. Best-effort:
// relays MAY ignore the request, and copies on relays we never published to
// are out of reach. The ratchet's erased keys are the real guarantee.
func (s *NostrStore) Delete(cid [32]byte) error {
	eventID := s.indexEventID(cid)
	if eventID == "" {
		// Not in our index (e.g. we never Put it, or the index is absent):
		// rediscover from the relays so the delete still has a target.
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		evs, err := s.pool.Query(ctx, nostr.Filter{
			Kinds: []int{BodyKind},
			Tags:  nostr.TagMap{"cid": []string{hex.EncodeToString(cid[:])}},
			Limit: 4,
		})
		if err != nil {
			return err
		}
		for _, ev := range evs {
			if ev != nil && tagValue(ev.Tags, "cid") == hex.EncodeToString(cid[:]) {
				eventID = ev.ID
				break
			}
		}
	}
	if eventID == "" {
		if err := s.removeIndex(cid); err != nil {
			return fmt.Errorf("nostrstore: body absent but local index cleanup failed: %w", err)
		}
		return store.ErrNotFound
	}
	if err := s.requestDeletion(eventID); err != nil {
		return err
	}
	if err := s.removeIndex(cid); err != nil {
		return fmt.Errorf("nostrstore: deletion requested but local index cleanup failed: %w", err)
	}
	return nil
}

// Reap requests deletion of every locally-indexed body past its deadline.
// Only bodies WE published are reachable (we hold the signing key).
func (s *NostrStore) Reap(now time.Time) int {
	s.mu.Lock()
	var due [][32]byte
	for cid, e := range s.index {
		if e.Deadline != 0 && now.Unix() >= e.Deadline {
			due = append(due, cid)
		}
	}
	s.mu.Unlock()
	n := 0
	for _, cid := range due {
		if err := s.Delete(cid); err == nil {
			n++
		}
	}
	return n
}

// Len reports how many bodies this endpoint has published and still indexes.
func (s *NostrStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

func (s *NostrStore) requestDeletion(eventID string) error {
	ev := nostr.Event{
		Kind:      deletionKind,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{nostr.Tag{"e", eventID}},
		Content:   "expired",
	}
	if err := ev.Sign(s.cfg.PrivateKey); err != nil {
		return fmt.Errorf("nostrstore: sign deletion: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.pool.Publish(ctx, ev)
}

func tagValue(tags nostr.Tags, key string) string {
	value, _ := uniqueTagValue(tags, key)
	return value
}

// uniqueTagValue rejects duplicate or malformed matching tags. NIP-01 tags
// are attacker-controlled input; a verifier must not silently choose one of
// several conflicting values for an authorization/content-address field.
func uniqueTagValue(tags nostr.Tags, key string) (string, bool) {
	value := ""
	found := false
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != key {
			continue
		}
		if len(tag) != 2 || found {
			return "", false
		}
		value = tag[1]
		found = true
	}
	return value, found
}

func (s *NostrStore) recordIndex(cid [32]byte, e indexEntry) error {
	if s.cfg.IndexPath == "" {
		return nil
	}
	s.mu.Lock()
	if _, exists := s.index[cid]; !exists && len(s.index) >= s.maxIndexItems {
		s.mu.Unlock()
		return fmt.Errorf("nostrstore: local index at %d entries; delete or reap old bodies before publishing", s.maxIndexItems)
	}
	previous, existed := s.index[cid]
	s.index[cid] = e
	snapshot := s.snapshotLocked()
	s.mu.Unlock()
	if err := writeIndexBounded(s.cfg.IndexPath, snapshot, s.maxIndexBytes, s.maxIndexItems); err != nil {
		s.mu.Lock()
		if existed {
			s.index[cid] = previous
		} else {
			delete(s.index, cid)
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *NostrStore) removeIndex(cid [32]byte) error {
	if s.cfg.IndexPath == "" {
		return nil
	}
	s.mu.Lock()
	previous, existed := s.index[cid]
	delete(s.index, cid)
	snapshot := s.snapshotLocked()
	s.mu.Unlock()
	if err := writeIndexBounded(s.cfg.IndexPath, snapshot, s.maxIndexBytes, s.maxIndexItems); err != nil {
		if existed {
			s.mu.Lock()
			s.index[cid] = previous
			s.mu.Unlock()
		}
		return err
	}
	return nil
}

func (s *NostrStore) indexEventID(cid [32]byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.index[cid].EventID
}

func (s *NostrStore) snapshotLocked() map[string]indexEntry {
	out := make(map[string]indexEntry, len(s.index))
	for cid, e := range s.index {
		out[hex.EncodeToString(cid[:])] = e
	}
	return out
}

func (s *NostrStore) loadIndex() error {
	f, err := os.Open(s.cfg.IndexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > s.maxIndexBytes {
		return fmt.Errorf("nostrstore: local index is %d bytes; cap is %d", stat.Size(), s.maxIndexBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(f, s.maxIndexBytes+1))
	var m map[string]indexEntry
	if err := decoder.Decode(&m); err != nil {
		return fmt.Errorf("nostrstore: malformed index: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("nostrstore: malformed index has trailing JSON data")
	}
	if len(m) > s.maxIndexItems {
		return fmt.Errorf("nostrstore: index has %d entries; cap is %d", len(m), s.maxIndexItems)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range m {
		b, derr := hex.DecodeString(k)
		if derr != nil || len(b) != 32 || k != strings.ToLower(k) || !validIndexEntry(e) {
			continue // skip corrupt or non-canonical entries rather than failing the whole load
		}
		var cid [32]byte
		copy(cid[:], b)
		s.index[cid] = e
	}
	return nil
}

func validIndexEntry(entry indexEntry) bool {
	if entry.Deadline <= 0 || len(entry.EventID) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(entry.EventID)
	return err == nil && entry.EventID == strings.ToLower(entry.EventID) && len(decoded) == 32
}

func writeIndex(path string, m map[string]indexEntry) error {
	return writeIndexBounded(path, m, 1<<20, 4096)
}

func writeIndexBounded(path string, m map[string]indexEntry, maxBytes int64, maxItems int) error {
	if maxBytes <= 0 || maxItems <= 0 {
		return errors.New("nostrstore: invalid index size limit")
	}
	if len(m) > maxItems {
		return fmt.Errorf("nostrstore: index has %d entries; cap is %d", len(m), maxItems)
	}
	for cid, entry := range m {
		decoded, err := hex.DecodeString(cid)
		if err != nil || len(decoded) != 32 || cid != strings.ToLower(cid) || !validIndexEntry(entry) {
			return errors.New("nostrstore: refusing to persist malformed index entry")
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("nostrstore: index would be %d bytes; cap is %d", len(raw), maxBytes)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return e
	}
	if _, err := tmp.Write(raw); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	_ = os.Chmod(name, 0o600)
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Chmod(path, 0o600)
}

// relayPool is the production Pool: dial each configured relay per operation,
// publish to all (best-effort: one reachable relay is enough), query all and
// merge de-duplicated by event ID.
type relayPool struct {
	relays []string
}

func (p *relayPool) Publish(ctx context.Context, ev nostr.Event) error {
	var lastErr error
	ok := 0
	for _, url := range p.relays {
		r, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		perr := r.Publish(ctx, ev)
		_ = r.Close()
		if perr != nil {
			lastErr = perr
			continue
		}
		ok++
	}
	if ok == 0 {
		if lastErr == nil {
			lastErr = ErrNoRelay
		}
		return fmt.Errorf("nostrstore: no relay accepted the event: %w", lastErr)
	}
	return nil
}

func (p *relayPool) Query(ctx context.Context, f nostr.Filter) ([]*nostr.Event, error) {
	var lastErr error
	seen := map[string]bool{}
	out := []*nostr.Event{}
	for _, url := range p.relays {
		r, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		evs, qerr := r.QuerySync(ctx, f)
		_ = r.Close()
		if qerr != nil {
			lastErr = qerr
			continue
		}
		for _, ev := range evs {
			if ev == nil || seen[ev.ID] {
				continue
			}
			seen[ev.ID] = true
			out = append(out, ev)
		}
	}
	if len(out) == 0 && lastErr != nil && len(seen) == 0 {
		// Every relay failed: surface it rather than masquerading as
		// "not found" (which would make a network outage look like an
		// expired/missing body).
		return nil, fmt.Errorf("nostrstore: all relays failed: %w", lastErr)
	}
	return out, nil
}
