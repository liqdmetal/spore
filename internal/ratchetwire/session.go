package ratchetwire

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// ErrSessionExists prevents a replayed X3DH init from resetting a live
// conversation. A new conversation must use a new session id and fresh keys.
var ErrSessionExists = errors.New("ratchetwire: session already exists")

// SessionTable serializes endpoint-local ratchet transitions. It is never
// serialized into a mailbox, chain payload, or shared body store.
type SessionTable struct {
	mu       sync.Mutex
	sessions map[[8]byte]*ratchet.Session
	seenInit map[[8]byte][32]byte
}

func NewSessionTable() *SessionTable {
	return &SessionTable{
		sessions: make(map[[8]byte]*ratchet.Session),
		seenInit: make(map[[8]byte][32]byte),
	}
}

// withSession runs a session transition and its side effect atomically with
// respect to all other transitions for the same table. On callback failure,
// the ratchet is restored before releasing the lock.
func (t *SessionTable) withSession(id [8]byte, fn func(*ratchet.Session) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil {
		return fmt.Errorf("ratchetwire: unknown session")
	}
	prior, err := s.Export()
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		restored, restoreErr := ratchet.ImportState(prior)
		if restoreErr == nil {
			t.sessions[id] = restored
		}
		if restoreErr != nil {
			return fmt.Errorf("%w (rollback: %v)", err, restoreErr)
		}
		return err
	}
	return nil
}

func (t *SessionTable) Get(id [8]byte) *ratchet.Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[id]
}

// AcceptInit atomically inserts a new responder session and records the exact
// init frame digest. The caller must validate the signed-prekey bundle and OPK
// allocation before calling.
func (t *SessionTable) AcceptInit(hs *ratchet.HandshakeMessage, session *ratchet.Session, frame []byte) error {
	if hs == nil || session == nil || hs.SessionID == [8]byte{} {
		return fmt.Errorf("ratchetwire: invalid session init")
	}
	id := hs.SessionID
	digest := BodyCID(frame)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[id]; ok {
		return ErrSessionExists
	}
	if prior, ok := t.seenInit[id]; ok && prior == digest {
		return ErrSessionExists
	}
	t.sessions[id] = session
	t.seenInit[id] = digest
	return nil
}

// Decrypt performs one receive transition while holding the endpoint lock.
func (t *SessionTable) Decrypt(id [8]byte, msg ratchet.Message, deadline time.Time) ([]byte, error) {
	if deadline.IsZero() || !deadline.After(time.Now()) {
		return nil, ErrExpired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil {
		return nil, fmt.Errorf("ratchetwire: unknown session")
	}
	return s.DecryptWithDeadline(msg, deadline)
}

func (t *SessionTable) Erase(id [8]byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[id]
	if ok {
		s.Erase()
		delete(t.sessions, id)
		delete(t.seenInit, id)
	}
	return ok
}

func (t *SessionTable) Sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, s := range t.sessions {
		n += s.SweepSkipped(now)
	}
	return n
}

// Export returns session material for the caller's protected endpoint store.
// This package deliberately does not write it to a mailbox or body store.
func (t *SessionTable) Export(id [8]byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil {
		return nil, fmt.Errorf("ratchetwire: unknown session")
	}
	return s.Export()
}

func (t *SessionTable) IDs() [][8]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([][8]byte, 0, len(t.sessions))
	for id := range t.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (t *SessionTable) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// Replace restores an existing session to a previously exported state. It is
// used to roll back a transition when the corresponding body cannot be stored.
func (t *SessionTable) Replace(id [8]byte, state []byte) error {
	s, err := ratchet.ImportState(state)
	if err != nil {
		return err
	}
	if s.ID() != id {
		return fmt.Errorf("ratchetwire: restored session id mismatch")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[id]; !ok {
		return fmt.Errorf("ratchetwire: unknown session")
	}
	t.sessions[id] = s
	return nil
}

func (t *SessionTable) Restore(id [8]byte, state []byte) error {
	s, err := ratchet.ImportState(state)
	if err != nil {
		return err
	}
	if s.ID() != id {
		return fmt.Errorf("ratchetwire: restored session id mismatch")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.sessions[id]; ok {
		return ErrSessionExists
	}
	t.sessions[id] = s
	return nil
}
