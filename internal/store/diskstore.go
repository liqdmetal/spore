package store

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

// Orphan is a stored body with no deadline record beside it: a <cid>.body
// whose .exp and .expms are both absent.
//
// This state is not part of the layout's contract — Put always writes .exp
// first, and a deliberate never-expires body carries a record holding "0",
// not a missing one — so an orphan is always an artifact: the concurrency
// window Reap+Put used to share, or records removed from outside the store.
// It is also the one state Reap cannot fix: reap discovers candidates by
// globbing *.exp, so a body with no record is never even considered, while
// deadlineFor reads the absent record as "never expires" and serves it
// forever. That combination — served forever, never reclaimed — is silent
// permanent retention of ciphertext, which is what this type exists to
// surface instead.
type Orphan struct {
	CID     [32]byte
	Path    string
	Size    int64
	ModTime time.Time
}

// Age is how long the body has been on disk. A body is renamed into place
// when it is stored, so mtime is the closest honest stand-in for its put
// time — the deadline itself is exactly what the missing record took away.
func (o Orphan) Age(now time.Time) time.Duration { return now.Sub(o.ModTime) }

// OrphanSweep is the outcome of SweepOrphans. Removed and Retained are both
// reported: a body younger than the age guard is deliberately kept, and the
// operator needs to see it rather than infer silence.
type OrphanSweep struct {
	Removed  []Orphan
	Retained []Orphan
	Bytes    int64 // bytes reclaimed by Removed
}

// Orphans lists bodies that have no deadline record. It holds the same lock as
// Put/Reap/Delete, because a sweep removes bodies and so falls under the
// store's ordering invariant: the multi-file sequences must not interleave.
//
// A first Put is safe by construction — it renames the records in before the
// body, so a body it is writing never reads as recordless. The window the lock
// closes is a RE-send of a cid whose records are gone, which is exactly the
// recovery a missing record invites: its records and body can land between
// this function's "no record" check and the removal, and the removal would
// then take a body Put has just stored. Classifying and removing under one
// hold makes that decision atomic.
func (s *DiskStore) Orphans() ([]Orphan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.orphansLocked()
}

func (s *DiskStore) orphansLocked() ([]Orphan, error) {
	matches, err := filepath.Glob(filepath.Join(s.dir, "*.body"))
	if err != nil {
		return nil, err
	}
	out := make([]Orphan, 0)
	for _, bodyFile := range matches {
		base := strings.TrimSuffix(bodyFile, ".body")
		raw, err := hex.DecodeString(filepath.Base(base))
		if err != nil || len(raw) != 32 {
			continue // not a store file; leave anything else alone
		}
		// A record that exists, or that cannot be ruled out, means "not an
		// orphan". Only a confirmed absence on BOTH files qualifies, because
		// the decision here leads to deleting ciphertext.
		covered := false
		for _, ext := range []string{".exp", ".expms"} {
			if _, err := os.Stat(base + ext); err == nil || !os.IsNotExist(err) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		fi, err := os.Stat(bodyFile)
		if err != nil {
			continue // vanished between glob and stat
		}
		var cid [32]byte
		copy(cid[:], raw)
		out = append(out, Orphan{CID: cid, Path: bodyFile, Size: fi.Size(), ModTime: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// partitionOrphans applies the age guard: a body at least minAge old is due
// for removal, anything younger is kept. minAge <= 0 means "everything is
// due". Both the plan and the sweep go through this one function, so a dry
// run can never disagree with a real one about what the guard lets through.
func partitionOrphans(all []Orphan, now time.Time, minAge time.Duration) OrphanSweep {
	res := OrphanSweep{Removed: make([]Orphan, 0), Retained: make([]Orphan, 0)}
	for _, o := range all {
		if minAge > 0 && o.Age(now) < minAge {
			res.Retained = append(res.Retained, o)
			continue
		}
		res.Removed = append(res.Removed, o)
		res.Bytes += o.Size
	}
	return res
}

// OrphanPlan reports what SweepOrphans would reclaim, without removing
// anything — the dry run an operator wants before a destructive pass.
func (s *DiskStore) OrphanPlan(now time.Time, minAge time.Duration) (OrphanSweep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.orphansLocked()
	if err != nil {
		return OrphanSweep{}, err
	}
	return partitionOrphans(all, now, minAge), nil
}

// SweepOrphans reclaims orphan bodies at least minAge old, and reports the
// ones it kept. The age guard exists because the deadline is unknowable: a
// body whose records vanished may still be inside the TTL its sender asked
// for, and deleting it then would lose a message the sender was entitled to
// have served. Anything older than the guard has outlived any TTL worth
// honouring, so reclaiming it restores the compost guarantee instead of
// breaking it.
//
// minAge <= 0 reclaims every orphan regardless of age. A body that cannot be
// removed (a sharing violation on Windows is the observed case) is reported
// in the error and left in place for the next run; the rest of the sweep
// still proceeds.
func (s *DiskStore) SweepOrphans(now time.Time, minAge time.Duration) (OrphanSweep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.orphansLocked()
	if err != nil {
		return OrphanSweep{}, err
	}
	plan := partitionOrphans(all, now, minAge)
	res := OrphanSweep{Removed: make([]Orphan, 0), Retained: plan.Retained}
	var errs []error
	for _, o := range plan.Removed {
		if err := os.Remove(o.Path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("diskstore: reclaim orphan %x: %w", o.CID, err))
			continue
		}
		res.Removed = append(res.Removed, o)
		res.Bytes += o.Size
	}
	return res, errors.Join(errs...)
}
