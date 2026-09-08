package ratchetwire

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// FileStateStore persists protected ratchet sessions in one endpoint-local
// directory. It never writes plaintext session state; StateProtector provides
// authenticated encryption and the record sequence detects accidental rollback.
type FileStateStore struct {
	mu        sync.Mutex
	dir       string
	protector *StateProtector
	sequence  map[[8]byte]uint64
}

func NewFileStateStore(dir string, key []byte) (*FileStateStore, error) {
	if dir == "" {
		return nil, errors.New("ratchetwire: empty keystore directory")
	}
	p, err := NewStateProtector(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStateStore{dir: dir, protector: p, sequence: make(map[[8]byte]uint64)}, nil
}

func (s *FileStateStore) path(id [8]byte) string {
	return filepath.Join(s.dir, "session-"+hexID(id)+".state")
}

func hexID(id [8]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i, b := range id {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&15]
	}
	return string(out)
}

// parseHexID decodes a 16-character lowercase hex string into an 8-byte ID.
// ok is false on any malformed input; it is a real boolean, not a sentinel
// byte value, so a legitimately decoded 0xff byte is never mistaken for a
// parse failure (that bug once caused ~3% of session IDs — any ID with a
// 0xff byte — to be silently dropped from IDs() and never restored).
func parseHexID(s string) (id [8]byte, ok bool) {
	if len(s) != 16 {
		return id, false
	}
	for i := 0; i < 8; i++ {
		hi, ok1 := hexNibble(s[i*2])
		lo, ok2 := hexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return id, false
		}
		id[i] = hi<<4 | lo
	}
	return id, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

func (s *FileStateStore) Save(id [8]byte, state []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.sequence[id]
	if seq == 0 {
		// Recover the durable counter after a process restart. Without this,
		// the first post-restart save reuses sequence 1 and defeats rollback
		// detection for snapshots copied over the live file.
		if record, err := os.ReadFile(s.path(id)); err == nil {
			storedSeq, _, err := UnprotectSession(s.protector, id, record)
			if err != nil {
				return err
			}
			seq = storedSeq
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	seq++
	record, err := ProtectSession(s.protector, id, seq, state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "state-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return e
	}
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(record); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, s.path(id)); err != nil {
		_ = os.Remove(name)
		return err
	}
	s.sequence[id] = seq
	return nil
}

func (s *FileStateStore) IDs() ([][8]byte, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	ids := make([][8]byte, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != len("session-")+16+len(".state") || entry.IsDir() || name[:8] != "session-" || name[len(name)-6:] != ".state" {
			continue
		}
		id, ok := parseHexID(name[8:24])
		if !ok {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *FileStateStore) Load(id [8]byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	seq, state, err := UnprotectSession(s.protector, id, record)
	if err != nil {
		return nil, err
	}
	if prior := s.sequence[id]; prior != 0 && seq < prior {
		return nil, errors.New("ratchetwire: state rollback detected")
	}
	s.sequence[id] = seq
	return state, nil
}

func (s *FileStateStore) Delete(id [8]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sequence, id)
	if err := os.Remove(s.path(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
