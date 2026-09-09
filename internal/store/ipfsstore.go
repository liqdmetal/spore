package store

// IPFSStore is a real Kubo (go-ipfs) HTTP API client implementing Store.
//
// WHY THIS EXISTS
//
// The other body stores each have a single point of failure: a disk store dies
// with its machine, an HTTP mailbox dies with its operator, nostr relays cap
// bodies at ~192 KB after base64 inflation, and spore-peer requires the sender
// to stay reachable. For an ARCHIVE — a newsletter back-catalogue that must
// still be there in a year — none of those is sufficient alone.
//
// IPFS gives content-addressed storage where the address IS the hash, which is
// exactly spore's existing CID model, so no new trust assumption is added: a
// fetched body is verified against the CID we asked for, and a lying node is
// caught immediately.
//
// HOW CID MAPPING WORKS (the part that is easy to get wrong)
//
// Spore CIDs are raw SHA-256 of the ciphertext. IPFS CIDv1 is a multihash
// wrapper around the same digest. Rather than parse or construct CIDv1 (which
// would mean depending on the multiformats stack and getting chunking exactly
// right), this store keeps its own cid -> ipfs-path index on disk and verifies
// the SHA-256 of every fetched body itself.
//
// That is deliberate: the integrity guarantee comes from OUR hash check, not
// from trusting the daemon's addressing. A malicious or buggy gateway that
// returns different bytes fails the check.
//
// HONEST LIMITS
//
//  1. PINNING IS NOT PERMANENCE. `pin=true` keeps a body on the node YOU pin
//     it to. If that node dies and nobody else pinned it, the body is gone.
//     Real durability needs multiple pinning nodes or a paid pinning service —
//     which is why MultiStore exists and why this is one substrate, not the
//     answer.
//  2. DELETION IS BEST-EFFORT AND PUBLIC. Unpinning removes YOUR copy; any
//     node that fetched the body may keep it forever. IPFS is the wrong
//     substrate for anything that must compost, so use it for the archive tier
//     and keep ratcheted message bodies on TTL stores. The real compost
//     guarantee remains the ratchet: erased message keys make lingering
//     ciphertext undecryptable.
//  3. Bodies are PUBLIC ciphertext. Anyone who learns a CID can fetch the
//     bytes. They are inert without the issue key, exactly as with the nostr
//     commons.
//  4. Reap only unpins what THIS store put. It cannot garbage-collect the
//     network.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// IPFSConfig configures an IPFSStore.
type IPFSConfig struct {
	// APIURL is the Kubo HTTP API root, e.g. http://127.0.0.1:5001.
	APIURL string
	// IndexPath is where the cid -> ipfs path index is persisted. Without it
	// the store cannot find its own bodies after a restart.
	IndexPath string
	// Timeout bounds every HTTP call. A hung daemon must never wedge a
	// publish or a receive loop, so this is always set to something finite.
	Timeout time.Duration
	// Pin requests that the daemon pin added bodies (default true).
	Pin *bool
	// HTTP lets a caller inject a client (tests, proxies, Tor).
	HTTP *http.Client
}

type ipfsEntry struct {
	Path     string `json:"path"`
	Deadline int64  `json:"deadline"`
	Size     int    `json:"size"`
}

// IPFSStore implements Store against a Kubo daemon.
type IPFSStore struct {
	api     string
	pin     bool
	http    *http.Client
	idxPath string

	mu    sync.Mutex
	index map[string]ipfsEntry // hex cid -> entry
}

// NewIPFSStore opens (or creates) an IPFS-backed store.
func NewIPFSStore(cfg IPFSConfig) (*IPFSStore, error) {
	if cfg.APIURL == "" {
		return nil, errors.New("ipfsstore: APIURL is required (e.g. http://127.0.0.1:5001)")
	}
	if _, err := url.Parse(cfg.APIURL); err != nil {
		return nil, fmt.Errorf("ipfsstore: bad APIURL: %w", err)
	}
	// An empty IndexPath is not a harmless default. This store maps spore CIDs
	// to IPFS paths in its own index; without a persisted index, every body
	// added before a restart becomes unfindable even though it is still pinned
	// on the daemon. Silently accepting that would turn "archive" into
	// "archive until the process exits", so it is refused outright.
	if cfg.IndexPath == "" {
		return nil, errors.New("ipfsstore: IndexPath is required — without a persisted cid->path index, bodies added before a restart cannot be found again")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	pin := true
	if cfg.Pin != nil {
		pin = *cfg.Pin
	}
	hc := cfg.HTTP
	if hc == nil {
		// Never http.DefaultClient: it has no timeout, so a hung daemon would
		// block a publish forever.
		hc = &http.Client{Timeout: timeout}
	}
	s := &IPFSStore{
		api:     trimSlash(cfg.APIURL),
		pin:     pin,
		http:    hc,
		idxPath: cfg.IndexPath,
		index:   map[string]ipfsEntry{},
	}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func (s *IPFSStore) loadIndex() error {
	if s.idxPath == "" {
		return nil
	}
	raw, err := os.ReadFile(s.idxPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &s.index); err != nil {
		return fmt.Errorf("ipfsstore: index %s is corrupt: %w", s.idxPath, err)
	}
	return nil
}

// saveIndexLocked persists atomically. A truncated index orphans bodies that
// are still pinned and costing space, so the write is temp-then-rename.
func (s *IPFSStore) saveIndexLocked() error {
	if s.idxPath == "" {
		return nil
	}
	blob, err := json.Marshal(s.index)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.idxPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := s.idxPath + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.idxPath)
}

// call POSTs to a Kubo API endpoint and returns the raw response body.
func (s *IPFSStore) call(path string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, s.api+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ipfsstore: %s returned %s: %s", path, resp.Status, snippet(raw))
	}
	return raw, nil
}

func snippet(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}

// Health reports whether the daemon is reachable. Callers should use this
// before relying on the store, so a dead daemon is a clear error rather than a
// mysterious publish failure.
func (s *IPFSStore) Health() error {
	if _, err := s.call("/api/v0/id", nil, ""); err != nil {
		return fmt.Errorf("ipfsstore: daemon at %s unreachable: %w", s.api, err)
	}
	return nil
}

// Put adds a body to IPFS and records its path.
//
// The deadline is retained in the local index for Reap. IPFS itself has no
// concept of expiry, so retention is enforced by unpinning on our side.
func (s *IPFSStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	// Verify the caller's CID actually matches the bytes. A mismatch here
	// would store a body nobody could ever look up.
	if got := sha256.Sum256(body); got != cid {
		return fmt.Errorf("ipfsstore: body does not match cid %s", hex.EncodeToString(cid[:]))
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", hex.EncodeToString(cid[:])+".body")
	if err != nil {
		return err
	}
	if _, err := fw.Write(body); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	q := "/api/v0/add?cid-version=1&raw-leaves=true"
	if s.pin {
		q += "&pin=true"
	} else {
		q += "&pin=false"
	}
	raw, err := s.call(q, &buf, mw.FormDataContentType())
	if err != nil {
		return err
	}
	// Kubo streams newline-delimited JSON; the final line is the root object.
	var last struct {
		Hash string `json:"Hash"`
		Name string `json:"Name"`
	}
	if err := decodeLastJSONLine(raw, &last); err != nil {
		return fmt.Errorf("ipfsstore: could not parse add response: %w", err)
	}
	if last.Hash == "" {
		return fmt.Errorf("ipfsstore: add returned no hash: %s", snippet(raw))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.index[hex.EncodeToString(cid[:])] = ipfsEntry{
		Path:     last.Hash,
		Deadline: deadline.Unix(),
		Size:     len(body),
	}
	return s.saveIndexLocked()
}

func decodeLastJSONLine(raw []byte, v any) error {
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		return json.Unmarshal(line, v)
	}
	return errors.New("empty response")
}

// Get fetches a body and VERIFIES it against the requested CID.
//
// The hash check is the whole security story: it means a hostile gateway, a
// buggy daemon, or a corrupted block cannot feed us the wrong bytes.
func (s *IPFSStore) Get(cid [32]byte) ([]byte, error) {
	key := hex.EncodeToString(cid[:])

	s.mu.Lock()
	entry, ok := s.index[key]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if entry.Deadline > 0 && time.Now().Unix() >= entry.Deadline {
		return nil, ErrExpired
	}

	raw, err := s.call("/api/v0/cat?arg="+url.QueryEscape(entry.Path), nil, "")
	if err != nil {
		return nil, err
	}
	if got := sha256.Sum256(raw); got != cid {
		return nil, fmt.Errorf("ipfsstore: INTEGRITY FAILURE for %s: fetched bytes hash to %s (the node returned different content than we stored)",
			key, hex.EncodeToString(got[:]))
	}
	return raw, nil
}

// Delete unpins a body and drops it from the index.
//
// This does NOT erase the body from the network — see limit 2 in the package
// notes. It removes our copy and stops us paying for it.
func (s *IPFSStore) Delete(cid [32]byte) error {
	key := hex.EncodeToString(cid[:])
	s.mu.Lock()
	entry, ok := s.index[key]
	if ok {
		delete(s.index, key)
	}
	err := s.saveIndexLocked()
	s.mu.Unlock()
	if !ok {
		return nil
	}
	if s.pin {
		// Best effort: an unpin failure must not leave the index inconsistent,
		// which is why the index write already happened.
		_, _ = s.call("/api/v0/pin/rm?arg="+url.QueryEscape(entry.Path), nil, "")
	}
	return err
}

// Reap unpins every body whose deadline has passed and returns the count.
func (s *IPFSStore) Reap(now time.Time) int {
	s.mu.Lock()
	var expired []string
	var paths []string
	for k, e := range s.index {
		if e.Deadline > 0 && now.Unix() >= e.Deadline {
			expired = append(expired, k)
			paths = append(paths, e.Path)
		}
	}
	for _, k := range expired {
		delete(s.index, k)
	}
	if len(expired) > 0 {
		_ = s.saveIndexLocked()
	}
	s.mu.Unlock()

	if s.pin {
		for _, p := range paths {
			_, _ = s.call("/api/v0/pin/rm?arg="+url.QueryEscape(p), nil, "")
		}
	}
	return len(expired)
}

// Len reports how many bodies this store is tracking.
func (s *IPFSStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// PathOf returns the IPFS path recorded for a CID, for operators who want to
// share an ipfs:// locator or verify pinning by hand.
func (s *IPFSStore) PathOf(cid [32]byte) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.index[hex.EncodeToString(cid[:])]
	return e.Path, ok
}

// CIDs lists the tracked spore CIDs, sorted.
func (s *IPFSStore) CIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.index))
	for k := range s.index {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ Store = (*IPFSStore)(nil)
