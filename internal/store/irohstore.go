package store

// IrohStore is a Store backed by iroh-blobs, the content-addressed blob layer
// of iroh (the P2P data network). It gives spore bodies a second, IPFS-
// independent substrate: iroh is a different network with different operators,
// so a body mirrored across IPFS + iroh survives either network failing, and
// neither operator can unilaterally censor an archive.
//
// WHY AN INDEX (same story as ipfsstore)
//
// iroh-blobs addresses a blob by an *iroh* content hash (a BLAKE3 multihash
// over the blob's DAG), which is NOT spore's sha256 body CID. So this store
// keeps a durable local index mapping our sha256 CID -> the iroh content hash,
// and re-verifies sha256 on every read. The iroh hash alone cannot look up a
// spore CID, and vice versa.
//
// THIS IS A BINARY-SIDE INTERFACE to an iroh CLI (`iroh blob add`, `iroh blob
// get`). It does not embed the iroh library, keeping spore's dependency surface
// small and letting the operator run any iroh distribution / version. The exact
// CLI surface differs across iroh versions, so the command is configurable and
// probed at construction — a wrong binary fails loudly, not silently.
//
// HONEST LIMITS (mirrors ipfsstore):
//   - A blob survives only as long as some node on the iroh network keeps it.
//     Pinning is not permanence; garbage collection is the default.
//   - iroh has no delete that reaches other nodes. Removing our local copy is
//     the honest limit of what Delete can promise.
//   - The network is the substrate; this is a client to it, not a guarantee.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IrohConfig configures an IrohStore.
type IrohConfig struct {
	// Cmd is the iroh binary to shell out to (default "iroh"). It is probed
	// at construction so a missing or wrong binary fails loudly.
	Cmd string
	// IndexPath is where the cid -> iroh-hash index is persisted. Without it
	// the store cannot find its own bodies after a restart, so it is
	// required (same reasoning as ipfsstore).
	IndexPath string
}

type irohEntry struct {
	IrohHash string `json:"iroh_hash"`
	Deadline int64  `json:"deadline"`
	Size     int    `json:"size"`
}

// IrohStore implements Store against an iroh CLI.
type IrohStore struct {
	cmd     string
	idxPath string

	mu    sync.Mutex
	index map[string]irohEntry // hex spore cid -> entry
}

// NewIrohStore opens (or creates) an iroh-backed store.
func NewIrohStore(cfg IrohConfig) (*IrohStore, error) {
	cmd := cfg.Cmd
	if cmd == "" {
		cmd = "iroh"
	}
	if cfg.IndexPath == "" {
		return nil, errors.New("irohstore: IndexPath is required — without a persisted cid->iroh-hash index, bodies added before a restart cannot be found again")
	}
	// Probe the binary. A wrong command line would otherwise surface only on
	// the first Put, which is exactly when nobody wants to discover it.
	if err := probeIroh(cmd); err != nil {
		return nil, err
	}
	s := &IrohStore{cmd: cmd, idxPath: cfg.IndexPath, index: map[string]irohEntry{}}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

func probeIroh(cmd string) error {
	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("irohstore: binary %q not found on PATH — install iroh (https://iroh.computer) or set Cmd to the right binary", cmd)
	}
	// `iroh --version` is the least version-dependent probe.
	out, err := exec.Command(cmd, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("irohstore: %q failed to run: %w: %s", cmd, err, trim(out))
	}
	return nil
}

func trim(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// Health verifies the iroh binary is present and runnable.
func (s *IrohStore) Health() error {
	if err := probeIroh(s.cmd); err != nil {
		return err
	}
	return nil
}

// Put adds the body to iroh-blobs and records the mapping.
func (s *IrohStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	tmp, err := os.CreateTemp("", "spore-iroh-*.blob")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	out, err := exec.Command(s.cmd, "blob", "add", tmpName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("irohstore: blob add: %w: %s", err, trim(out))
	}
	ih := strings.TrimSpace(string(out))
	if ih == "" {
		return errors.New("irohstore: blob add returned no hash")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.index[irohHex(cid)] = irohEntry{IrohHash: ih, Deadline: deadline.Unix(), Size: len(body)}
	return s.saveIndexLocked()
}

// Get fetches the body and re-verifies sha256. The network's word is never
// trusted: if the bytes do not hash to the requested CID, that is corruption.
func (s *IrohStore) Get(cid [32]byte) ([]byte, error) {
	s.mu.Lock()
	e, ok := s.index[irohHex(cid)]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if e.Deadline > 0 && time.Now().Unix() >= e.Deadline {
		return nil, ErrExpired
	}

	out, err := exec.Command(s.cmd, "blob", "get", e.IrohHash).Output()
	if err != nil {
		return nil, fmt.Errorf("irohstore: blob get %s: %w: %s", e.IrohHash, err, trim(out))
	}
	if got := sha256.Sum256(out); got != cid {
		return nil, fmt.Errorf("irohstore: INTEGRITY FAILURE for %x: fetched bytes hash to %x", cid, got)
	}
	return out, nil
}

// Delete removes the local index entry. It cannot erase blobs other nodes have
// already fetched; that limit is stated rather than hidden.
func (s *IrohStore) Delete(cid [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.index[irohHex(cid)]; !ok {
		return ErrNotFound
	}
	delete(s.index, irohHex(cid))
	return s.saveIndexLocked()
}

// Reap evicts index entries whose deadline has passed.
func (s *IrohStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, e := range s.index {
		if e.Deadline > 0 && now.Unix() >= e.Deadline {
			delete(s.index, k)
			n++
		}
	}
	if n > 0 {
		_ = s.saveIndexLocked()
	}
	return n
}

// Len reports the number of indexed bodies.
func (s *IrohStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

func irohHex(cid [32]byte) string {
	return fmt.Sprintf("%x", cid[:])
}

// --- persisted index (same crash-safe pattern as ipfsstore) ---

func (s *IrohStore) loadIndex() error {
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
		return fmt.Errorf("irohstore: index %s is corrupt: %w", s.idxPath, err)
	}
	return nil
}

func (s *IrohStore) saveIndexLocked() error {
	if dir := filepath.Dir(s.idxPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := s.idxPath + ".tmp"
	blob, err := json.Marshal(s.index)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.idxPath)
}

var _ Store = (*IrohStore)(nil)
