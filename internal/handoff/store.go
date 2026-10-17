package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

var ErrNotFound = errors.New("handoff: not found (or expired and pruned)")

// Delivery persists intent before ratchet advancement. Preparing without a
// Pointer is a deliberately blocked crash window, never permission to reencrypt.
type Delivery struct {
	EventHash           string `json:"event_hash"`
	Preparing           bool   `json:"preparing,omitempty"`
	Pointer             []byte `json:"pointer,omitempty"`
	Accounted           bool   `json:"accounted,omitempty"`
	Sent                bool   `json:"sent,omitempty"`
	ApplicationReceived bool   `json:"application_received,omitempty"`
}

type Record struct {
	Local    Peer            `json:"local"`
	Session  string          `json:"session"`
	Events   []Envelope      `json:"events"`
	Outbox   []Delivery      `json:"outbox,omitempty"`
	Receipts []SignedReceipt `json:"receipts,omitempty"`
}

func (r Record) Latest() Message { return r.Events[len(r.Events)-1].Message }
func (r Record) Status() string  { return r.Latest().Kind }

type document struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

type Store struct {
	mu        sync.Mutex
	path      string
	protector *ratchetwire.StateProtector
}

var storeID = [8]byte{'h', 'a', 'n', 'd', 'o', 'f', 'f', '1'}

func Open(path string, key []byte) (*Store, error) {
	p, err := ratchetwire.NewStateProtector(key)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("handoff: empty store path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{path: path, protector: p}
	// Validate existing state without rewriting it or creating an empty file.
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// lockFile never auto-breaks a lock on a timeout: a slow live process must not
// lose ownership. After a crash, remove it only after confirming no writer lives.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("handoff: store busy or lock unavailable (%s): %w", path, err)
	}
	if _, err := fmt.Fprintf(f, "pid=%d\n", os.Getpid()); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

// LockDelivery serializes flushers, not receivers. All commands sharing a
// ratchet directory must still use one sending process, as for normal E2 sends.
func (s *Store) LockDelivery() (func(), error) { return lockFile(s.path + ".send-lock") }

func (s *Store) load() (document, error) {
	d := document{Version: 1, Records: []Record{}}
	raw, err := bounds.ReadBound(s.path, MaxStore)
	if os.IsNotExist(err) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	plain, err := s.protector.Open(storeID, raw)
	if err != nil {
		return d, fmt.Errorf("handoff: decrypt store: %w", err)
	}
	defer clear(plain)
	if err := DecodeJSON(plain, &d, MaxStore); err != nil {
		return d, err
	}
	if d.Version != 1 || len(d.Records) > 128 {
		return d, errors.New("handoff: invalid store version or record count")
	}
	seen := map[string]bool{}
	for _, r := range d.Records {
		if err := validateRecord(r); err != nil {
			return d, err
		}
		id := r.Latest().Terms.ID
		if seen[id] {
			return d, errors.New("handoff: duplicate record ID")
		}
		seen[id] = true
	}
	return d, nil
}

func validateRecord(r Record) error {
	if err := r.Local.Validate(); err != nil {
		return err
	}
	if !validHex(r.Session, 8) || len(r.Events) < 1 || len(r.Events) > 3 || len(r.Outbox) > 3 || len(r.Receipts) > 3 {
		return errors.New("handoff: invalid record shape")
	}
	for i, e := range r.Events {
		if err := e.Verify(); err != nil {
			return err
		}
		if e.Message.Sequence != i+1 {
			return errors.New("handoff: invalid event sequence")
		}
		if i > 0 {
			if err := follows(r.Events[i-1], e); err != nil {
				return err
			}
		}
	}
	t := r.Latest().Terms
	if r.Local != t.Buyer && r.Local != t.Provider {
		return errors.New("handoff: local identity not a participant")
	}
	receiptSeen := map[string]bool{}
	for _, receipt := range r.Receipts {
		if err := receipt.Verify(); err != nil {
			return err
		}
		matched := false
		for _, event := range r.Events {
			if receipt.Matches(event, r.Session) {
				matched = true
			}
		}
		if !matched || receiptSeen[receipt.Receipt.EventHash] {
			return errors.New("handoff: invalid or duplicate stored receipt")
		}
		receiptSeen[receipt.Receipt.EventHash] = true
	}
	seen := map[string]bool{}
	for _, entry := range r.Outbox {
		found := false
		for _, e := range r.Events {
			if e.Hash() == entry.EventHash && e.Message.Sender() == r.Local {
				found = true
			}
		}
		isReceipt := false
		for _, receipt := range r.Receipts {
			if receipt.Hash() == entry.EventHash && receipt.Receipt.Sender == r.Local {
				found = true
				isReceipt = true
			}
		}
		if entry.ApplicationReceived && (isReceipt || !receiptSeen[entry.EventHash]) {
			return errors.New("handoff: delivery lacks a verified application receipt")
		}
		if !found || seen[entry.EventHash] || (entry.Preparing && len(entry.Pointer) != 0) || ((entry.Accounted || entry.Sent) && len(entry.Pointer) == 0) || (entry.Sent && !entry.Accounted) {
			return errors.New("handoff: invalid delivery state")
		}
		seen[entry.EventHash] = true
		if len(entry.Pointer) != 0 {
			p, err := ratchetwire.ParsePointerPayload(entry.Pointer)
			if err != nil || int64(p.BurnDeadline) != t.ExpiresAt {
				return errors.New("handoff: invalid prepared pointer")
			}
		}
	}
	return nil
}

func follows(previous, next Envelope) error {
	p, n := previous.Message, next.Message
	if p.Terms != n.Terms || n.Sequence != p.Sequence+1 || n.Previous != previous.Hash() || p.EventID == n.EventID {
		return errors.New("handoff: conflicting terms, event ID, sequence, or previous-event hash")
	}
	if n.Sequence == 3 && n.ResultHash != p.ResultHash {
		return errors.New("handoff: decision does not bind the exact deliverable")
	}
	return nil
}

func (s *Store) transaction(now time.Time, fn func(*document) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := lockFile(s.path + ".lock")
	if err != nil {
		return err
	}
	defer release()
	d, err := s.load()
	if err != nil {
		return err
	}
	live := make([]Record, 0, len(d.Records))
	for _, r := range d.Records {
		if now.Unix() < r.Latest().Terms.ExpiresAt {
			live = append(live, r)
		}
	}
	d.Records = live
	if err := fn(&d); err != nil {
		return err
	}
	if len(d.Records) > 128 {
		return errors.New("handoff: store record limit reached")
	}
	for _, r := range d.Records {
		if err := validateRecord(r); err != nil {
			return err
		}
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	defer clear(plain)
	if len(plain)+128 > MaxStore {
		return errors.New("handoff: encrypted store exceeds limit")
	}
	raw, err := s.protector.Seal(storeID, plain)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".handoff-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func clone(r Record) Record {
	raw, _ := json.Marshal(r)
	var out Record
	_ = json.Unmarshal(raw, &out)
	return out
}

// Apply verifies every signature and the exact local/session binding, then
// atomically appends the event and (for outbound events) durable delivery intent.
// Repeating the identical event is idempotent; a conflicting retry is rejected.
func (s *Store) Apply(e Envelope, local Peer, session string, outbound bool, now time.Time) error {
	if err := validateApply(e, local, session, outbound, now); err != nil {
		return err
	}
	return s.transaction(now, func(d *document) error { return applyEvent(d, e, local, session, outbound) })
}

func validateApply(e Envelope, local Peer, session string, outbound bool, now time.Time) error {
	if err := e.Verify(); err != nil {
		return err
	}
	m := e.Message
	if now.Unix() >= m.Terms.ExpiresAt || m.Terms.ExpiresAt > now.Add(30*24*time.Hour).Unix() {
		return errors.New("handoff: expired or expiry exceeds 30 days")
	}
	if !validHex(session, 8) {
		return errors.New("handoff: invalid session")
	}
	if (outbound && m.Sender() != local) || (!outbound && m.Recipient() != local) {
		return errors.New("handoff: wrong local participant for event")
	}
	return nil
}

// ApplyBatch atomically queues a whole fixed reviewer roster, avoiding partial
// invitations if any local validation or encrypted-store write fails.
func (s *Store) ApplyBatch(events []Envelope, local Peer, sessions []string, now time.Time) error {
	if len(events) == 0 || len(events) != len(sessions) || len(events) > 16 {
		return errors.New("handoff: invalid outbound batch")
	}
	for i, e := range events {
		if err := validateApply(e, local, sessions[i], true, now); err != nil {
			return err
		}
	}
	return s.transaction(now, func(d *document) error {
		for i, e := range events {
			if err := applyEvent(d, e, local, sessions[i], true); err != nil {
				return err
			}
		}
		return nil
	})
}

func applyEvent(d *document, e Envelope, local Peer, session string, outbound bool) error {
	m := e.Message
	for i := range d.Records {
		r := &d.Records[i]
		if r.Latest().Terms.ID != m.Terms.ID {
			continue
		}
		if r.Local != local || r.Session != session {
			return errors.New("handoff: local identity or session changed")
		}
		for _, prior := range r.Events {
			if prior.Hash() == e.Hash() {
				return nil
			}
			if prior.Message.EventID == m.EventID {
				return errors.New("handoff: event ID reused with different content")
			}
		}
		if err := follows(r.Events[len(r.Events)-1], e); err != nil {
			return err
		}
		r.Events = append(r.Events, e)
		if outbound {
			r.Outbox = append(r.Outbox, Delivery{EventHash: e.Hash()})
		}
		return nil
	}
	if m.Kind != "brief" {
		return errors.New("handoff: unknown brief; refusing out-of-order event")
	}
	r := Record{Local: local, Session: session, Events: []Envelope{e}}
	if outbound {
		r.Outbox = []Delivery{{EventHash: e.Hash()}}
	}
	d.Records = append(d.Records, r)
	return nil
}

func (s *Store) List(now time.Time) ([]Record, error) {
	var rows []Record
	err := s.transaction(now, func(d *document) error {
		rows = make([]Record, 0, len(d.Records))
		for _, r := range d.Records {
			rows = append(rows, clone(r))
		}
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].Latest().Terms.ID < rows[j].Latest().Terms.ID })
	return rows, err
}

// ReadOnlyListIncludingExpired reads and validates existing handoff state
// without creating directories, pruning expired records, taking a lock file,
// or rewriting data. It is intended for diagnostics whose read-only contract
// includes expired state that normal List retention would prune.
func ReadOnlyListIncludingExpired(path string, key []byte) ([]Record, error) {
	if path == "" {
		return nil, errors.New("handoff: empty store path")
	}
	protector, err := ratchetwire.NewStateProtector(key)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, protector: protector}
	d, err := s.load()
	if err != nil {
		return nil, err
	}
	rows := make([]Record, 0, len(d.Records))
	for _, r := range d.Records {
		rows = append(rows, clone(r))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Latest().Terms.ID < rows[j].Latest().Terms.ID })
	return rows, nil
}

func (s *Store) Get(id string, now time.Time) (Record, error) {
	rows, err := s.List(now)
	if err != nil {
		return Record{}, err
	}
	for _, r := range rows {
		if r.Latest().Terms.ID == id {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}

// UpdateDelivery is monotonic: saved pointers cannot be replaced, and a
// preparation marker cannot be cleared to bypass an interrupted send.
func (s *Store) UpdateDelivery(id, hash string, stage string, pointer []byte, now time.Time) error {
	return s.transaction(now, func(d *document) error {
		for i := range d.Records {
			r := &d.Records[i]
			if r.Latest().Terms.ID != id {
				continue
			}
			for j := range r.Outbox {
				o := &r.Outbox[j]
				if o.EventHash != hash {
					continue
				}
				switch stage {
				case "begin":
					if o.Preparing || len(o.Pointer) != 0 {
						return errors.New("handoff: preparation already started")
					}
					o.Preparing = true
				case "pointer":
					if len(o.Pointer) != 0 {
						if bytes.Equal(o.Pointer, pointer) {
							return nil
						}
						return errors.New("handoff: prepared pointer is immutable")
					}
					if !o.Preparing || len(pointer) == 0 {
						return errors.New("handoff: preparation not started")
					}
					o.Pointer = append([]byte(nil), pointer...)
					o.Preparing = false
				case "account":
					if len(o.Pointer) == 0 {
						return errors.New("handoff: no prepared pointer")
					}
					o.Accounted = true
				case "sent":
					if !o.Accounted {
						return errors.New("handoff: send not accounted")
					}
					o.Sent = true
				default:
					return errors.New("handoff: invalid delivery stage")
				}
				return nil
			}
		}
		return ErrNotFound
	})
}
