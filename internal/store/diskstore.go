package store

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DiskStore is a Store that persists bodies as files in a directory. It is
// the durable local backend for a mailbox daemon: bodies survive restarts and
// are reaped once their deadline passes. Files are content-addressed, so a
// body's on-disk name is its CID hex.
//
// Layout under dir:
//
//	<cid hex>.body   raw ciphertext
//	<cid hex>.exp    unix-seconds deadline as decimal text
type DiskStore struct {
	dir string
}

// NewDiskStore opens (creating if needed) a body store rooted at dir.
func NewDiskStore(dir string) (*DiskStore, error) {
	if dir == "" {
		return nil, errors.New("store: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &DiskStore{dir: dir}, nil
}

func (s *DiskStore) bodyPath(cid [32]byte) string {
	return filepath.Join(s.dir, hex.EncodeToString(cid[:])+".body")
}
func (s *DiskStore) expPath(cid [32]byte) string {
	return filepath.Join(s.dir, hex.EncodeToString(cid[:])+".exp")
}

func (s *DiskStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	// Write body to a temp file then rename, so a crash never leaves a
	// half-written body under the final name.
	tmp, err := os.CreateTemp(s.dir, "put-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.bodyPath(cid)); err != nil {
		os.Remove(tmpName)
		return err
	}

	var exp string
	if deadline.IsZero() {
		exp = "0"
	} else {
		exp = strconv.FormatInt(deadline.Unix(), 10)
	}
	return os.WriteFile(s.expPath(cid), []byte(exp), 0o600)
}

func (s *DiskStore) Get(cid [32]byte) ([]byte, error) {
	body, err := os.ReadFile(s.bodyPath(cid))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if s.expired(cid) {
		return nil, ErrExpired
	}
	return body, nil
}

func (s *DiskStore) Delete(cid [32]byte) error {
	rm := func(p string) {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			// best-effort; caller sees the primary error below
		}
	}
	if _, err := os.Stat(s.bodyPath(cid)); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	rm(s.bodyPath(cid))
	rm(s.expPath(cid))
	return nil
}

// Reap removes every body whose deadline has passed. Returns count removed.
func (s *DiskStore) Reap(now time.Time) int {
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*.exp"))
	n := 0
	for _, expFile := range matches {
		raw, err := os.ReadFile(expFile)
		if err != nil {
			continue
		}
		sec, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || sec == 0 {
			continue // no deadline (0): never reap; malformed: leave it
		}
		if now.Unix() > sec {
			base := expFile[:len(expFile)-len(".exp")]
			os.Remove(base + ".body")
			os.Remove(expFile)
			n++
		}
	}
	return n
}

func (s *DiskStore) expired(cid [32]byte) bool {
	raw, err := os.ReadFile(s.expPath(cid))
	if err != nil {
		return false
	}
	sec, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || sec == 0 {
		return false
	}
	return time.Now().Unix() > sec
}

// Len reports the number of stored bodies by counting .body files.
func (s *DiskStore) Len() int {
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*.body"))
	return len(matches)
}
