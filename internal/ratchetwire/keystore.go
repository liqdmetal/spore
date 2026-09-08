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
		var id [8]byte
		for i := range id {
			var v byte
			for _, c := range []byte(name[8+i*2 : 10+i*2]) {
				v <<= 4
				if c >= '0' && c <= '9' {
					v += c - '0'
				} else if c >= 'a' && c <= 'f' {
					v += c - 'a' + 10
				} else {
					v = 0xff
					break
				}
			}
			if v == 0xff {
				goto skip
			}
			id[i] = v
		}
		ids = append(ids, id)
	skip:
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
