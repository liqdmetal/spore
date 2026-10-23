package store

// IrohStore is a Store backed by the Spore Iroh sidecar. It is an alternate
// content-addressed transport, not automatic replication: a body survives only
// while at least one configured Iroh provider retains it.
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
// small. The command is configurable, but construction requires the sidecar's
// E2-locator-v2 + Minimal-network marker; stock or stale Iroh binaries fail closed.
//
// HONEST LIMITS (mirrors ipfsstore):
//   - A blob survives only as long as some node on the iroh network keeps it.
//     Pinning is not permanence; garbage collection is the default.
//   - iroh has no delete that reaches other nodes. Removing our local copy is
//     the honest limit of what Delete can promise.
//   - The network is the substrate; this is a client to it, not a guarantee.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IrohConfig configures an IrohStore.
type IrohConfig struct {
	// Cmd is the compatible spore-iroh sidecar to shell out to (default "spore-iroh").
	// Construction rejects binaries without the E2-locator-v2/Minimal capability marker.
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

type irohCommandRunner interface {
	add(path string) ([]byte, error)
	get(hash string) ([]byte, error)
}

const (
	maxIrohBodyBytes         = 20 << 20
	maxIrohIndexBytes        = 16 << 20
	maxIrohCommandStderrSize = 4 << 10
	irohProbeTimeout         = 5 * time.Second
	irohAddTimeout           = 30 * time.Second
	// Covers queue admission, eight serial 25-second provider attempts, and startup margin.
	irohGetTimeout = 5 * time.Minute
)

var errIrohOutputTooLarge = errors.New("irohstore: sidecar output exceeded limit")

type cliIrohRunner struct{ cmd string }

func (r cliIrohRunner) add(path string) ([]byte, error) {
	return runIrohCommand(r.cmd, irohAddTimeout, 128, "blob", "add", path)
}

func (r cliIrohRunner) get(hash string) ([]byte, error) {
	return runIrohCommand(r.cmd, irohGetTimeout, maxIrohBodyBytes, "blob", "get", hash)
}

type limitedCommandOutput struct {
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	discard  bool
	overflow bool
}

func (b *limitedCommandOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *limitedCommandOutput) Write(p []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining < 0 {
		remaining = 0
	}
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.buffer.Write(p[:remaining])
		}
		b.overflow = true
		if b.cancel != nil {
			b.cancel()
		}
		if b.discard {
			return len(p), nil
		}
		return remaining, errIrohOutputTooLarge
	}
	return b.buffer.Write(p)
}

func runIrohCommand(binary string, timeout time.Duration, stdoutLimit int, args ...string) ([]byte, error) {
	return runIrohCommandWithEnv(binary, timeout, stdoutLimit, nil, args...)
}

func runIrohCommandWithEnv(binary string, timeout time.Duration, stdoutLimit int, env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	if env != nil {
		cmd.Env = env
	}
	stdout := &limitedCommandOutput{limit: stdoutLimit, cancel: cancel}
	stderr := &limitedCommandOutput{limit: maxIrohCommandStderrSize, discard: true}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.overflow {
		return nil, errIrohOutputTooLarge
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("irohstore: sidecar command timed out")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("irohstore: sidecar command exited with status %d", exitErr.ExitCode())
		}
		return nil, fmt.Errorf("irohstore: could not run sidecar %q", filepath.Base(binary))
	}
	return stdout.Bytes(), nil
}

// IrohStore implements Store against an iroh CLI.
type IrohStore struct {
	cmd     string
	idxPath string
	runner  irohCommandRunner

	mu    sync.Mutex
	index map[string]irohEntry // hex spore cid -> entry
}

// NewIrohStore opens (or creates) an iroh-backed store.
func NewIrohStore(cfg IrohConfig) (*IrohStore, error) {
	cmd := cfg.Cmd
	if cmd == "" {
		cmd = "spore-iroh"
	}
	if cfg.IndexPath == "" {
		return nil, errors.New("irohstore: IndexPath is required — without a persisted cid->iroh-hash index, bodies added before a restart cannot be found again")
	}
	// Probe the binary. A wrong command line would otherwise surface only on
	// the first Put, which is exactly when nobody wants to discover it.
	if err := probeIroh(cmd); err != nil {
		return nil, err
	}
	s := &IrohStore{cmd: cmd, idxPath: cfg.IndexPath, runner: cliIrohRunner{cmd: cmd}, index: map[string]irohEntry{}}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

const requiredIrohCapabilities = "capabilities=e2-locator-v2,endpoint-minimal"

func probeIroh(cmd string) error {
	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("irohstore: compatible sidecar %q not found; build spore-iroh or set Cmd", filepath.Base(cmd))
	}
	out, err := runIrohCommand(cmd, irohProbeTimeout, 1024, "--version")
	if err != nil {
		return fmt.Errorf("irohstore: sidecar version check failed: %w", err)
	}
	if err := validateIrohVersion(out); err != nil {
		return fmt.Errorf("irohstore: incompatible sidecar: %w", err)
	}
	return nil
}

func validateIrohVersion(out []byte) error {
	if !strings.Contains(string(out), requiredIrohCapabilities) {
		return fmt.Errorf("expected capability marker %q", requiredIrohCapabilities)
	}
	return nil
}

// Health verifies the iroh binary is present and runnable.
func (s *IrohStore) Health() error {
	if err := probeIroh(s.cmd); err != nil {
		return err
	}
	return nil
}

// Put adds the body to iroh-blobs and records the local mapping.
func (s *IrohStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	_, err := s.PutWithLocator(cid, body, deadline)
	return err
}

// PutWithLocator stores the body and returns the portable Iroh BLAKE3 locator.
// Spore's SHA-256 CID remains the integrity commitment and is checked first.
func (s *IrohStore) PutWithLocator(cid [32]byte, body []byte, deadline time.Time) ([32]byte, error) {
	if len(body) > maxIrohBodyBytes {
		return [32]byte{}, fmt.Errorf("irohstore: body exceeds the %d-byte limit", maxIrohBodyBytes)
	}
	if sha256.Sum256(body) != cid {
		return [32]byte{}, errors.New("irohstore: supplied Spore CID does not match body")
	}
	deadlineUnix := int64(0)
	if !deadline.IsZero() {
		deadlineUnix = deadline.Unix()
		if deadlineUnix <= 0 {
			return [32]byte{}, errors.New("irohstore: deadline must be after the Unix epoch")
		}
	}
	if s.runner == nil {
		return [32]byte{}, errors.New("irohstore: command runner is unavailable")
	}
	tmp, err := os.CreateTemp("", "spore-iroh-*.blob")
	if err != nil {
		return [32]byte{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return [32]byte{}, err
	}
	if err := tmp.Close(); err != nil {
		return [32]byte{}, err
	}

	out, err := s.runner.add(tmpName)
	if err != nil {
		return [32]byte{}, fmt.Errorf("irohstore: blob add failed: %w", err)
	}
	locator, err := parseIrohHash(string(out))
	if err != nil {
		return [32]byte{}, errors.New("irohstore: sidecar returned an invalid locator")
	}

	key := irohHex(cid)
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, hadPrevious := s.index[key]
	s.index[key] = irohEntry{IrohHash: irohHex(locator), Deadline: deadlineUnix, Size: len(body)}
	if err := s.saveIndexLocked(); err != nil {
		if hadPrevious {
			s.index[key] = previous
		} else {
			delete(s.index, key)
		}
		return [32]byte{}, err
	}
	return locator, nil
}

// Get fetches through the persisted local CID->Iroh map.
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
	locator, err := parseIrohHash(e.IrohHash)
	if err != nil {
		return nil, err
	}
	return s.GetWithLocator(cid, locator)
}

// GetWithLocator lets a different receiver fetch by the portable Iroh hash in
// the E2 pointer. SHA-256 remains authoritative even if the provider lies.
func (s *IrohStore) GetWithLocator(cid [32]byte, locator [32]byte) ([]byte, error) {
	if s.runner == nil {
		return nil, errors.New("irohstore: command runner is unavailable")
	}
	key := irohHex(cid)
	s.mu.Lock()
	entry, known := s.index[key]
	s.mu.Unlock()
	locatorHex := irohHex(locator)
	if known {
		if entry.Deadline > 0 && time.Now().Unix() >= entry.Deadline {
			return nil, ErrExpired
		}
		knownLocator, err := parseIrohHash(entry.IrohHash)
		if err != nil {
			return nil, err
		}
		if knownLocator != locator {
			return nil, errors.New("irohstore: portable locator conflicts with local index")
		}
	}
	out, err := s.runner.get(locatorHex)
	if err != nil {
		return nil, fmt.Errorf("irohstore: blob get failed: %w", err)
	}
	if len(out) > maxIrohBodyBytes {
		return nil, fmt.Errorf("irohstore: fetched body exceeds the %d-byte limit", maxIrohBodyBytes)
	}
	if known && len(out) != entry.Size {
		return nil, errors.New("irohstore: fetched body size does not match local index")
	}
	if sha256.Sum256(out) != cid {
		return nil, errors.New("irohstore: INTEGRITY FAILURE: fetched body digest mismatch")
	}
	return out, nil
}

func parseIrohHash(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != len(out) {
		return out, errors.New("irohstore: Iroh locator must be exactly 32 bytes of hex")
	}
	copy(out[:], raw)
	return out, nil
}

// Delete removes the local index entry. It cannot erase blobs other nodes have
// already fetched; that limit is stated rather than hidden.
func (s *IrohStore) Delete(cid [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := irohHex(cid)
	previous, ok := s.index[key]
	if !ok {
		return ErrNotFound
	}
	delete(s.index, key)
	if err := s.saveIndexLocked(); err != nil {
		s.index[key] = previous
		return err
	}
	return nil
}

// Reap evicts index entries whose deadline has passed.
func (s *IrohStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	expired := make(map[string]irohEntry)
	for k, e := range s.index {
		if e.Deadline > 0 && now.Unix() >= e.Deadline {
			expired[k] = e
			delete(s.index, k)
		}
	}
	if len(expired) == 0 {
		return 0
	}
	if err := s.saveIndexLocked(); err != nil {
		for key, entry := range expired {
			s.index[key] = entry
		}
		return 0
	}
	return len(expired)
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
	f, err := os.Open(s.idxPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("irohstore: open index: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxIrohIndexBytes+1))
	if err != nil {
		return fmt.Errorf("irohstore: read index: %w", err)
	}
	if len(raw) > maxIrohIndexBytes {
		return fmt.Errorf("irohstore: index exceeds the %d-byte limit", maxIrohIndexBytes)
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &s.index); err != nil {
		return fmt.Errorf("irohstore: index is corrupt: %w", err)
	}
	if s.index == nil {
		return errors.New("irohstore: index is corrupt: null map")
	}
	legacyNoDeadline := time.Time{}.Unix()
	for cid, entry := range s.index {
		decoded, err := hex.DecodeString(cid)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != cid {
			return errors.New("irohstore: index contains an invalid Spore CID key")
		}
		if entry.Deadline == legacyNoDeadline {
			entry.Deadline = 0
			s.index[cid] = entry
		}
		if _, err := parseIrohHash(entry.IrohHash); err != nil || entry.Size < 0 || entry.Size > maxIrohBodyBytes || entry.Deadline < 0 {
			return errors.New("irohstore: index contains an invalid entry")
		}
	}
	return nil
}

func (s *IrohStore) saveIndexLocked() error {
	blob, err := json.Marshal(s.index)
	if err != nil {
		return fmt.Errorf("irohstore: encode index: %w", err)
	}
	if len(blob) > maxIrohIndexBytes {
		return fmt.Errorf("irohstore: index exceeds the %d-byte limit", maxIrohIndexBytes)
	}
	dir := filepath.Dir(s.idxPath)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("irohstore: create index directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.idxPath)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("irohstore: create temporary index: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("irohstore: write temporary index: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("irohstore: sync temporary index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("irohstore: close temporary index: %w", err)
	}
	if err := os.Rename(tmpName, s.idxPath); err != nil {
		return fmt.Errorf("irohstore: replace index: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

var _ Store = (*IrohStore)(nil)
var _ LocatorStore = (*IrohStore)(nil)
