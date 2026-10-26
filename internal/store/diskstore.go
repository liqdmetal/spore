package store

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
//	<cid hex>.exp    unix-seconds deadline as decimal text (the floor of the
//	                 true deadline; the old-format record every version reads)
//	<cid hex>.expms  unix-millis deadline as decimal text (optional
//	                 refinement written by current versions so mid-second
//	                 deadlines are enforced and reaped promptly; older
//	                 binaries ignore the file entirely and keep working off
//	                 the seconds floor — the conservative direction)
type DiskStore struct {
	dir string

	// mu serializes the multi-file sequences against each other. Put writes
	// the deadline records and THEN the body; Reap and Delete remove the
	// body and then the records — the two orders are safe on their own but
	// not against each other. A reap pass that lands in the window between
	// Put's record write and its body rename deletes the records, and the
	// body is then renamed into place with NO .exp beside it; deadlineFor
	// reads a missing .exp as "no deadline = never expires", so that body
	// can never be reaped again. That is silent permanent retention of
	// ciphertext — the exact failure this store exists to prevent — and it
	// was observed for real (peerstore's reap test intermittently saw a
	// body with no .exp, once per few hundred Puts under a 25 ms ticker).
	// Holding mu across each sequence makes the interleave impossible.
	//
	// This is a per-process lock: a single writer per dir is the design (a
	// node holds the bodies it serves). Two processes sharing one dir would
	// still need filesystem-level locking. Reads (Get, Len) deliberately do
	// not take it — they see whole files either way, thanks to the
	// temp+rename discipline, and holding it there would let a large read
	// stall the ticker.
	mu sync.Mutex
}

// NewDiskStoreFromURL opens a local body store from a disk:// URL. It accepts
// disk:///absolute/path on Unix and disk://C:/absolute/path on Windows.
func NewDiskStoreFromURL(uri string) (*DiskStore, error) {
	dir, ok := strings.CutPrefix(uri, "disk://")
	if !ok || strings.TrimSpace(dir) == "" {
		return nil, errors.New("store: disk URL must be disk:// followed by a directory")
	}
	return NewDiskStore(filepath.FromSlash(dir))
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

func (s *DiskStore) expPathMS(cid [32]byte) string {
	return filepath.Join(s.dir, hex.EncodeToString(cid[:])+".expms")
}

func (s *DiskStore) Put(cid [32]byte, body []byte, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

	// Sub-second refinement, same temp+rename discipline, still BEFORE the
	// body so a crash can only leave dangling expiry files (harmless), never
	// a body without them. .expms carries the exact millisecond deadline so
	// mid-second TTLs are enforced at read time and reaped on the tick that
	// crosses them, not on the second rollover. Zero deadlines write no
	// .expms: absent falls back to the seconds record ("0" = never).
	if !deadline.IsZero() {
		msTmp, err := os.CreateTemp(s.dir, "putexpms-*")
		if err != nil {
			return err
		}
		msTmpName := msTmp.Name()
		if _, err := msTmp.Write([]byte(strconv.FormatInt(deadline.UnixMilli(), 10))); err != nil {
			msTmp.Close()
			os.Remove(msTmpName)
			return err
		}
		if err := msTmp.Close(); err != nil {
			os.Remove(msTmpName)
			return err
		}
		if err := os.Chmod(msTmpName, 0o600); err != nil {
			os.Remove(msTmpName)
			return err
		}
		if err := os.Rename(msTmpName, s.expPathMS(cid)); err != nil {
			os.Remove(msTmpName)
			return err
		}
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
	// E2 frames may be up to 16 MiB plus framing; keep a hard bound on reads
	// to prevent allocation DoS via a crafted store file.
	const maxBodyBytes = 20 << 20
	f, err := os.Open(s.bodyPath(cid))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(maxBodyBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("diskstore: read body %x: %w", cid, err)
	}
	if len(raw) > maxBodyBytes {
		return nil, fmt.Errorf("diskstore: body %x exceeds %d bytes", cid, maxBodyBytes)
	}
	if s.expired(cid) {
		return nil, ErrExpired
	}
	return raw, nil
}

func (s *DiskStore) Delete(cid [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	rm(s.expPathMS(cid))
	return nil
}

// Reap removes every body whose deadline has passed. Returns count removed.
// Resolves deadlines exactly like expired() (ms refinement over the seconds
// floor), so a body is reaped on the first pass after its true deadline —
// including mid-second deadlines — and never earlier than it would be
// refused at read.
func (s *DiskStore) Reap(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*.exp"))
	n := 0
	for _, expFile := range matches {
		base := expFile[:len(expFile)-len(".exp")]
		raw, err := hex.DecodeString(filepath.Base(base))
		if err != nil || len(raw) != 32 {
			continue
		}
		var cid [32]byte
		copy(cid[:], raw)
		d, ok := s.deadlineFor(cid)
		if !ok || !now.After(d) {
			continue
		}
		// The .exp marker is the commit point: remove the payload first and
		// the marker last, and only count (and only drop the marker) when the
		// payload is truly gone. A failed payload remove — Windows AV/indexer
		// sharing violations are the observed case — must leave the marker in
		// place so the next pass retries the whole hold; removing the marker
		// anyway orphans the .body forever (no *.exp left to ever find it,
		// seen on Windows CI 2026-09-18 as "expired body not composted").
		if err := os.Remove(base + ".body"); err != nil && !os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(base + ".expms"); err != nil && !os.IsNotExist(err) {
			continue
		}
		if err := os.Remove(expFile); err != nil && !os.IsNotExist(err) {
			continue
		}
		n++
	}
	return n
}

// deadlineFor resolves the effective burn deadline for cid: the millisecond
// .expms file is authoritative when present and parseable; otherwise the
// seconds floor in .exp applies. ok=false means "no deadline" (never
// expires): missing .exp, a "0" in either file, or a malformed record with
// no usable refinement. expired() and Reap BOTH go through this, so a body
// is never served past its deadline while its bytes remain on disk and is
// never reaped while it would still be served — the two can no longer
// disagree about a mid-second boundary.
func (s *DiskStore) deadlineFor(cid [32]byte) (time.Time, bool) {
	if raw, err := os.ReadFile(s.expPathMS(cid)); err == nil {
		if ms, perr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); perr == nil {
			if ms == 0 {
				return time.Time{}, false
			}
			return time.UnixMilli(ms), true
		}
		// malformed .expms: fall through to the seconds record
	}
	raw, err := os.ReadFile(s.expPath(cid))
	if err != nil {
		return time.Time{}, false // missing .exp: never expires (crash ordering)
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || sec == 0 {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

func (s *DiskStore) expired(cid [32]byte) bool {
	d, ok := s.deadlineFor(cid)
	return ok && time.Now().After(d)
}

// Len reports the number of stored bodies by counting .body files.
func (s *DiskStore) Len() int {
	matches, _ := filepath.Glob(filepath.Join(s.dir, "*.body"))
	return len(matches)
}
