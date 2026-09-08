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
	// Write the deadline BEFORE the body, both via temp+rename so each half
	// is atomic on its own. This ordering matters: expired() treats a
	// missing .exp file as "never expires" (see below), so if a crash lands
	// between the two writes, the dangerous outcome is a .body with no .exp
	// (ciphertext that can never be reaped — a permanent-retention failure
	// that breaks the entire compost guarantee this store exists to
	// provide). Writing .exp first means a crash mid-sequence can only leave
	// a dangling .exp with no .body, which is harmless: Get still returns
	// ErrNotFound, and Reap silently removes the orphaned .exp file.
	var exp string
	if deadline.IsZero() {
		exp = "0"
	} else {
		exp = strconv.FormatInt(deadline.Unix(), 10)
	}
	expTmp, err := os.CreateTemp(s.dir, "putexp-*")
	if err != nil {
		return err
	}
	expTmpName := expTmp.Name()
	if _, err := expTmp.Write([]byte(exp)); err != nil {
		expTmp.Close()
		os.Remove(expTmpName)
		return err
	}
	if err := expTmp.Close(); err != nil {
		os.Remove(expTmpName)
		return err
	}
	if err := os.Chmod(expTmpName, 0o600); err != nil {
		os.Remove(expTmpName)
		return err
	}
	if err := os.Rename(expTmpName, s.expPath(cid)); err != nil {
		os.Remove(expTmpName)
		return err
	}

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
	return nil
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
