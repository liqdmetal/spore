package ratchetwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
)

var ErrNoOPK = errors.New("ratchetwire: no one-time prekey available")

// countFlushInterval bounds how often rejection counts alone force a rewrite
// of the pool file. A flood of junk frames therefore costs at most one count
// write per interval; the rest are coalesced into a trailing write. It is a
// variable so tests can shorten it.
var countFlushInterval = time.Second

// OPKPool owns responder-side one-time prekeys. When path is non-empty, the
// pool is backed by an endpoint-local file. The file is replaced atomically;
// importantly, Take commits the removal before returning the key, so a
// process restart can never resurrect a successfully consumed OPK.
//
// Key removals are always persisted before they take effect. Rejection counts
// are persisted on a throttle, so a count written in the last interval before
// an exit may be lost unless Flush is called first.
type OPKPool struct {
	mu    sync.Mutex
	items map[uint32][32]byte
	path  string

	rejects     rejectCounts
	countsDirty bool        // counts changed since the file was last written
	lastWrite   time.Time   // when the file was last written successfully
	flushTimer  *time.Timer // pending trailing count write, if any
	flushErr    error       // error from the last trailing write, if it failed
}

// Stages at which a prekey handshake can be rejected. Each name appears in
// PrekeyRejectedError.Stage and as a key in RejectedCounts.
const (
	StageLookup       = "lookup"       // OPK unknown or already spent
	StageValidate     = "validate"     // handshake did not verify against the prekey
	StageAuthenticate = "authenticate" // first message failed authentication
	StageCommit       = "commit"       // prekey consumed concurrently, or removal not persisted
)

type rejectCounts struct {
	lookup       atomic.Uint64
	validate     atomic.Uint64
	authenticate atomic.Uint64
	commit       atomic.Uint64
}

func (c *rejectCounts) bump(stage string) {
	switch stage {
	case StageLookup:
		c.lookup.Add(1)
	case StageValidate:
		c.validate.Add(1)
	case StageAuthenticate:
		c.authenticate.Add(1)
	case StageCommit:
		c.commit.Add(1)
	}
}

func (c *rejectCounts) snapshot() map[string]uint64 {
	return map[string]uint64{
		StageLookup:       c.lookup.Load(),
		StageValidate:     c.validate.Load(),
		StageAuthenticate: c.authenticate.Load(),
		StageCommit:       c.commit.Load(),
	}
}

func (c *rejectCounts) restore(m map[string]uint64) {
	c.lookup.Store(m[StageLookup])
	c.validate.Store(m[StageValidate])
	c.authenticate.Store(m[StageAuthenticate])
	c.commit.Store(m[StageCommit])
}

// PrekeyRejectedError reports a prekey handshake that did not complete. It
// carries the stage, the public OPK id, and the cause. It never carries key
// material, so it is safe to log. CountErr is set when the rejection count
// could not be written to the pool file; the rejection itself still stands.
type PrekeyRejectedError struct {
	Stage    string
	OPKID    uint32
	Err      error
	CountErr error
}

func (e *PrekeyRejectedError) Error() string {
	msg := fmt.Sprintf("ratchetwire: prekey handshake rejected at %s (opk %d): %v", e.Stage, e.OPKID, e.Err)
	if e.CountErr != nil {
		msg += fmt.Sprintf("; rejection count not persisted: %v", e.CountErr)
	}
	return msg
}

func (e *PrekeyRejectedError) Unwrap() error { return e.Err }

// fail counts a rejection at stage, persists the count for path-backed pools,
// and wraps the cause. A nil pool (the non-pool init path) returns err
// unchanged, so that path's errors are not altered.
func (p *OPKPool) fail(stage string, id uint32, err error) error {
	if p == nil || err == nil {
		return err
	}
	p.mu.Lock()
	p.rejects.bump(stage)
	var countErr error
	if p.path != "" {
		countErr = p.noteCountLocked()
	}
	p.mu.Unlock()
	return &PrekeyRejectedError{Stage: stage, OPKID: id, Err: err, CountErr: countErr}
}

// noteCountLocked persists a changed rejection count, at most once per
// countFlushInterval. A count that falls inside the interval is marked dirty
// and written by a trailing timer. The caller must hold p.mu.
func (p *OPKPool) noteCountLocked() error {
	if !p.countsDirty && time.Since(p.lastWrite) >= countFlushInterval {
		return p.persist(p.items)
	}
	p.countsDirty = true
	if p.flushTimer == nil {
		wait := countFlushInterval - time.Since(p.lastWrite)
		if wait < 0 {
			wait = 0
		}
		p.flushTimer = time.AfterFunc(wait, p.flushFromTimer)
	}
	return p.flushErr
}

// flushFromTimer writes the pending counts from the trailing timer. On failure
// the counts stay dirty and are retried by the next rejection or Flush.
func (p *OPKPool) flushFromTimer() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.flushTimer = nil
	p.flushErr = p.flushLocked()
}

// flushLocked writes the pool file if rejection counts are pending. The caller
// must hold p.mu.
func (p *OPKPool) flushLocked() error {
	if p.path == "" || !p.countsDirty {
		return nil
	}
	return p.persist(p.items)
}

// Flush writes any pending rejection counts now. Call it before a process
// exits so that counts still inside the throttle window are not lost.
func (p *OPKPool) Flush() error {
	if p == nil {
		return nil // no pool, so nothing can be pending
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flushTimer != nil {
		p.flushTimer.Stop()
		p.flushTimer = nil
	}
	return p.flushLocked()
}

// RejectedCounts reports how many prekey handshakes were rejected, per stage.
// Path-backed pools persist these counts with the pool file, so they survive
// restarts; see ReadOnlyPrekeyRejections.
func (p *OPKPool) RejectedCounts() map[string]uint64 {
	return p.rejects.snapshot()
}

// ReadOnlyPrekeyRejections returns the persisted per-stage rejection counts for
// the OPK pool file at path. It does not load or modify the pool, and it never
// returns key material. A missing file is reported as an os.IsNotExist error.
func ReadOnlyPrekeyRejections(path string) (map[string]uint64, error) {
	if path == "" {
		return nil, errors.New("ratchetwire: empty OPK pool path")
	}
	data, err := bounds.ReadBound(path, 64<<10) // 64 KiB OPK pool cap
	if err != nil {
		return nil, err
	}
	var stored struct {
		Rejected map[string]uint64 `json:"rejected"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("ratchetwire: decode OPK pool: %w", err)
	}
	return map[string]uint64{
		StageLookup:       stored.Rejected[StageLookup],
		StageValidate:     stored.Rejected[StageValidate],
		StageAuthenticate: stored.Rejected[StageAuthenticate],
		StageCommit:       stored.Rejected[StageCommit],
	}, nil
}

// opkPoolFile is the on-disk pool. Rejected carries the per-stage rejection
// counts so that `spore status` can report them from a separate process.
type opkPoolFile struct {
	Items    map[uint32][32]byte `json:"items"`
	Rejected map[string]uint64   `json:"rejected"`
}

func NewOPKPool() *OPKPool { return &OPKPool{items: make(map[uint32][32]byte)} }

// NewPersistentOPKPool opens or creates an endpoint-local OPK pool. The file
// is private to the current OS user (0600) and is loaded before the pool is
// made available to callers.
func NewPersistentOPKPool(path string) (*OPKPool, error) {
	if path == "" {
		return nil, errors.New("ratchetwire: empty OPK pool path")
	}
	p := &OPKPool{items: make(map[uint32][32]byte), path: path}
	data, err := bounds.ReadBound(path, 64<<10) // 64 KiB OPK pool cap
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	var stored opkPoolFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("ratchetwire: decode OPK pool: %w", err)
	}
	for id, key := range stored.Items {
		p.items[id] = key
	}
	p.rejects.restore(stored.Rejected)
	return p, nil
}

func (p *OPKPool) Add(id uint32, priv [32]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.items[id]; exists {
		return errors.New("ratchetwire: duplicate OPK id")
	}
	next := cloneOPKs(p.items)
	next[id] = priv
	if err := p.persist(next); err != nil {
		return err
	}
	p.items = next
	return nil
}

func (p *OPKPool) Take(id uint32) ([32]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	priv, ok := p.items[id]
	if !ok {
		return [32]byte{}, ErrNoOPK
	}
	next := cloneOPKs(p.items)
	delete(next, id)
	// Persist before changing memory or returning the key. If this fails the
	// OPK remains available and the caller can safely retry.
	if err := p.persist(next); err != nil {
		return [32]byte{}, err
	}
	p.items = next
	return priv, nil
}

func (p *OPKPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

// MaxID reports the highest OPK id currently held (0 when empty). Callers
// generating MORE one-time prekeys start above this so new ids can never
// collide with — and be rejected as duplicates of — keys already in the pool.
func (p *OPKPool) MaxID() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var max uint32
	for id := range p.items {
		if id > max {
			max = id
		}
	}
	return max
}

func cloneOPKs(src map[uint32][32]byte) map[uint32][32]byte {
	dst := make(map[uint32][32]byte, len(src))
	for id, key := range src {
		dst[id] = key
	}
	return dst
}

func (p *OPKPool) persist(items map[uint32][32]byte) error {
	if p.path == "" {
		return nil
	}
	data, err := json.Marshal(opkPoolFile{Items: items, Rejected: p.rejects.snapshot()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".opk-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error { _ = tmp.Close(); _ = os.Remove(name); return e }
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, p.path); err != nil {
		_ = os.Remove(name)
		return err
	}
	p.countsDirty = false
	p.lastWrite = time.Now()
	p.flushErr = nil
	return nil
}

// Peek returns the one-time prekey for id WITHOUT consuming it. Handshake
// validation uses Peek; the key is consumed only after the handshake and its
// first message have authenticated (see TakeMatching). A frame that fails
// validation therefore cannot use up a prekey.
func (p *OPKPool) Peek(id uint32) ([32]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	priv, ok := p.items[id]
	if !ok {
		return [32]byte{}, ErrNoOPK
	}
	return priv, nil
}

// TakeMatching consumes id only if the stored key still equals want. It is the
// commit step after validation, and it persists the removal before returning.
// If a concurrent handshake already consumed the key, it gets ErrNoOPK.
func (p *OPKPool) TakeMatching(id uint32, want [32]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	priv, ok := p.items[id]
	if !ok {
		return ErrNoOPK
	}
	if priv != want {
		return errors.New("ratchetwire: OPK no longer matches the validated key")
	}
	next := cloneOPKs(p.items)
	delete(next, id)
	if err := p.persist(next); err != nil {
		return err
	}
	p.items = next
	return nil
}
