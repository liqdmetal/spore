package ratchetwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/liqdmetal/spore/internal/ratchet"
)

var ErrNoOPK = errors.New("ratchetwire: no one-time prekey available")

// OPKPool owns responder-side one-time prekeys. When path is non-empty, the
// pool is backed by an endpoint-local file. The file is replaced atomically;
// importantly, Take commits the removal before returning the key, so a
// process restart can never resurrect a successfully consumed OPK.
type OPKPool struct {
	mu    sync.Mutex
	items map[uint32][32]byte
	path  string
}

type opkPoolFile struct {
	Items map[uint32][32]byte `json:"items"`
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
	data, err := os.ReadFile(path)
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
	data, err := json.Marshal(opkPoolFile{Items: items})
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
	return nil
}

// EstablishResponder consumes the referenced OPK exactly once, then builds the
// responder session. If validation fails, the caller must not reinsert it.
func (p *OPKPool) EstablishResponder(identity, spk []byte, hs *ratchet.HandshakeMessage) (*ratchet.Session, error) {
	if hs == nil {
		return nil, errors.New("ratchetwire: nil handshake")
	}
	var opk *[32]byte
	if !hs.Degraded {
		priv, err := p.Take(hs.OPKID)
		if err != nil {
			return nil, err
		}
		opk = &priv
	}
	return ratchet.EstablishResponder(identity, spk, opk, hs)
}
