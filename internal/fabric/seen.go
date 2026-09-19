package fabric

// SeenCIDs — the drain-union dedupe store (F3; AUDIT-RELAYFABRIC.md R-N1).
//
// With N-relay redundancy the sender fput's the same pointer to every relay
// on the contact card. Each relay dutifully holds its own copy, so a
// recipient draining M relays receives the same CID M times. The drain loop
// must therefore keep ONE union of consumed CIDs across relays and passes:
// the first copy that reaches the ingest pipeline consumes the CID, and
// every later copy — from any relay, on any later tick — is skipped before
// it can burn a body fetch or re-enter the decrypt path.
//
// Dedupe is by CID (bytes 34:66 of the 74-byte pointer payload) — the
// content address of the encrypted body, and the same key ingestPointer and
// the relay's own fput-dedupe use. The same frame re-published through two
// relays carries the identical CID by construction.
//
// Semantics — the "drain union" is a CONSUMED set, not a seen set:
//
//   - A CID is recorded only when its ingest SUCCEEDED (frame fetched and
//     decrypted through the shared pipeline). A copy whose body fetch
//     failed transiently (sender offline, store unreachable) must NOT be
//     marked: the recipient's redundancy depends on a second relay still
//     delivering that pointer on a later tick. The drain loop therefore
//     calls Observe only on the success path, and tracks failed-fetch
//     retries in its own bounded retry list as before.
//   - Entries carry the pointer's burn deadline and are pruned when expired.
//     After the deadline the relay composts its copy and the body is gone —
//     a redelivery is impossible, so the entry is pure bookkeeping.
//   - Persistence survives restarts: drain-union knowledge older than the
//     process is exactly what stops a restarted recipient from re-draining
//     every still-queued copy on every relay. File format: one line per
//     CID ("<hexcid> <deadline>", deadline optional); temp+rename atomic,
//     0600, beside the ratchet state it protects. A corrupt file starts
//     empty and is overwritten on the next save — the store is an
//     optimization with a correctness net (the ratchet fails replays
//     closed), never a dependency.
//
// Not a security boundary: the ratchet is the filter (design law 4). This
// is capacity hygiene — the explicit, pre-ingest half of the dedupe the F2
// loop previously got only implicitly from per-relay in-memory maps.

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// seenCap bounds memory and the persisted file. The relay's per-handle
// queue cap (32) times a realistic relay fan-out bounds the live duplicate
// population; 64k entries (~6 MB at 64-char lines) is orders of magnitude
// beyond anything N-relay redundancy legitimately produces, and deadline
// pruning keeps steady-state far below it.
const seenCap = 65536

// SeenCIDs is the cross-relay, cross-tick union of consumed CIDs.
type SeenCIDs struct {
	mu        sync.Mutex
	entries   map[string]uint64 // hex CID -> burn deadline (unix seconds; 0 = unknown)
	path      string            // "" = memory only (tests)
	cap       int
	lastSave  time.Time
	everSaved bool
}

// NewSeenCIDs loads (or starts) the union store. path == "" keeps the store
// in memory (tests); a nonempty path loads any existing file and persists
// on mutation.
func NewSeenCIDs(path string) *SeenCIDs {
	s := &SeenCIDs{entries: make(map[string]uint64), path: path, cap: seenCap}
	if path != "" {
		s.load()
	}
	return s
}

// load reads the persisted union. Malformed lines are skipped, not fatal.
func (s *SeenCIDs) load() {
	f, err := os.Open(s.path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cid, deadline, hasDeadline := strings.Cut(line, " ")
		if !isHexCID(cid) {
			continue
		}
		var dl uint64
		if hasDeadline {
			if _, err := fmt.Sscanf(deadline, "%d", &dl); err != nil {
				dl = 0
			}
		}
		s.entries[cid] = dl
	}
}

// Observe records the CID of a 74-byte pointer payload and returns true
// when the caller MUST ingest: true means this call is the first
// union-wide sighting (this caller won the race to consume the pointer);
// false means some relay or earlier tick already delivered it. The burn
// deadline (bytes 66:74) is recorded with the entry so Prune can age it
// out; pointers too short to carry a deadline are keyed deadline-less.
func (s *SeenCIDs) Observe(raw []byte) bool {
	if len(raw) < 66 {
		return true // not keyable: let the ingest path refuse it
	}
	cidHex := hex.EncodeToString(raw[34:66])
	var dl uint64
	if len(raw) >= 74 {
		dl = binary.LittleEndian.Uint64(raw[66:74])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.entries[cidHex]; dup {
		return false
	}
	s.entries[cidHex] = dl
	s.persistLocked()
	return true
}

// Forget un-marks a CID: the ingest of the first copy FAILED, so the union
// must go back to treating this pointer as undelivered — another relay's
// copy (or a later tick's retry) must stay eligible to consume it. No-op
// for unknown CIDs. Caller pairs this with Observe on the failure path
// exactly once, so the save gate keeps persistence honest.
func (s *SeenCIDs) Forget(raw []byte) {
	if len(raw) < 66 {
		return
	}
	cidHex := hex.EncodeToString(raw[34:66])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[cidHex]; !ok {
		return
	}
	delete(s.entries, cidHex)
	s.persistLocked()
}

// Seen reports whether the CID hex is already in the union (tests, diagnostics).
func (s *SeenCIDs) Seen(cidHex string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[cidHex]
	return ok
}

// Len reports the current union size (tests, diagnostics).
func (s *SeenCIDs) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Prune drops entries whose burn deadline has passed. The cap is enforced
// only for OVER-cap growth (dropping soonest-expired first); under the cap
// unexpired entries are never evicted, keeping the dedupe guarantee for any
// redelivery that races the cap.
func (s *SeenCIDs) Prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nowU := uint64(now.Unix())
	for cid, dl := range s.entries {
		if dl != 0 && dl <= nowU {
			delete(s.entries, cid)
		}
	}
	if len(s.entries) > s.cap {
		type seenKV struct {
			cid string
			dl  uint64
		}
		all := make([]seenKV, 0, len(s.entries))
		for cid, dl := range s.entries {
			all = append(all, seenKV{cid, dl})
		}
		// Soonest-expired first; deadline-less entries (dl == 0) sort last —
		// they are the least safely forgettable.
		sort.Slice(all, func(i, j int) bool {
			a, b := all[i], all[j]
			if (a.dl == 0) != (b.dl == 0) {
				return b.dl == 0
			}
			return a.dl < b.dl
		})
		for i := 0; i < len(all)-s.cap; i++ {
			delete(s.entries, all[i].cid)
		}
	}
	s.persistLocked()
}

// persistLocked writes the union atomically (temp+rename, 0600) beside the
// ratchet state. Save-gated to once per second: the drain loop can mark
// dozens of CIDs per tick and each write is a full-file rewrite — the last
// write of a second carries every mutation of that second, and a crash
// loses at most one second of dedupe knowledge (the ratchet net holds).
// Caller holds s.mu.
func (s *SeenCIDs) persistLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	if s.everSaved && s.lastSave.Add(time.Second).After(now) {
		return
	}
	s.lastSave = now
	s.everSaved = true

	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	fmt.Fprintf(w, "# spore fabric drain-union (consumed CIDs); regenerated, safe to delete\n")
	for cid, dl := range s.entries {
		if dl != 0 {
			fmt.Fprintf(w, "%s %d\n", cid, dl)
		} else {
			fmt.Fprintln(w, cid)
		}
	}
	if err := w.Flush(); err == nil {
		if err = f.Sync(); err == nil {
			_ = f.Close()
			_ = os.Rename(tmp, s.path)
			return
		}
	}
	_ = f.Close()
	_ = os.Remove(tmp) // never leave a partial file beside the state
}

// isHexCID: exactly 64 hex chars — the drain loop keys on
// hex.EncodeToString(p.CID[:]) (lowercase).
func isHexCID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
