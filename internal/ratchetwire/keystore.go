package ratchetwire

import (
	"encoding/binary"
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

// logPath is the append-only high-water-mark ledger for id. It is never
// truncated or rewritten in place — only appended to — so that even if the
// mutable head file at path(id) is later replaced with an older, otherwise
// valid, authenticated snapshot (e.g. an attacker with filesystem write
// access restoring a backup), Load can still detect that a higher sequence
// was previously durable and refuse the rollback. This does not defend
// against an attacker able to also truncate or rewrite the log file itself
// (unrestricted read-write access to the whole state directory defeats any
// purely local anti-rollback mechanism; closing that requires an external
// anchor such as a monotonic hardware counter or a remote checkpoint, which
// this package does not have). It raises the bar from "any restore trivially
// succeeds" to "restore succeeds only if the log is also edited."
func (s *FileStateStore) logPath(id [8]byte) string {
	return filepath.Join(s.dir, "session-"+hexID(id)+".log")
}

const logRecordSize = 8 + 32 // sequence (LE uint64) + digest

// appendLog durably records that seq/digest was written for id. Called while
// s.mu is held.
func (s *FileStateStore) appendLog(id [8]byte, seq uint64, digest [32]byte) error {
	f, err := os.OpenFile(s.logPath(id), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var rec [logRecordSize]byte
	binary.LittleEndian.PutUint64(rec[:8], seq)
	copy(rec[8:], digest[:])
	if _, err := f.Write(rec[:]); err != nil {
		return err
	}
	return f.Sync()
}

// maxLoggedSequence returns the highest sequence ever durably recorded for
// id, or 0 if the log does not exist or is empty. A log length that is not a
// multiple of logRecordSize indicates a torn/partial append (e.g. a crash
// mid-write); only complete records are trusted, and the truncated tail is
// ignored rather than treated as an error, since a torn write is expected
// crash behavior and must never itself become a denial-of-service vector.
func (s *FileStateStore) maxLoggedSequence(id [8]byte) (uint64, error) {
	data, err := os.ReadFile(s.logPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var max uint64
	for off := 0; off+logRecordSize <= len(data); off += logRecordSize {
		if seq := binary.LittleEndian.Uint64(data[off : off+8]); seq > max {
			max = seq
		}
	}
	return max, nil
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
	// The append-only log is the durable high-water mark: it can only grow,
	// so it survives a head-file swap that the in-memory counter above
	// cannot detect on a fresh process. Take the max of both sources before
	// incrementing.
	logged, err := s.maxLoggedSequence(id)
	if err != nil {
		return err
	}
	if logged > seq {
		seq = logged
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
	// Append to the durable log BEFORE the rename that makes this the new
	// head: if the process dies between the two, the log may record a
	// sequence with no matching head file, which is safe (maxLoggedSequence
	// only ever pushes future Saves' sequence higher); the reverse order
	// would let a head file exist whose sequence was never logged, which is
	// exactly the gap this mechanism exists to close.
	if err := s.appendLog(id, seq, StateDigest(record)); err != nil {
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
	// Check against BOTH the in-memory high-water mark (same-process reuse)
	// and the durable append-only log (fresh-process restart). The log is
	// the one that actually closes the gap: on a fresh process s.sequence
	// is empty, so without this check a head file swapped for an older,
	// still-validly-authenticated snapshot would be silently accepted.
	logged, err := s.maxLoggedSequence(id)
	if err != nil {
		return nil, err
	}
	prior := s.sequence[id]
	if logged > prior {
		prior = logged
	}
	if prior != 0 && seq < prior {
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
