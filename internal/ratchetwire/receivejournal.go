package ratchetwire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/liqdmetal/spore/internal/bounds"
	"github.com/liqdmetal/spore/internal/ratchet"
)

const receiveJournalFile = "receive-pending.enc"
const maxReceiveJournal = 512 << 10

var receiveJournalID = [8]byte{'r', 'e', 'c', 'v', 'j', 'n', 'l', '1'}

// ReceivePending contains plaintext only in memory; its on-disk journal is
// authenticated/encrypted. Record is the EXACT prepared next keystore head.
// Keeping it, rather than saving State again, closes log-before-head crashes.
type ReceivePending struct {
	Version  int      `json:"version"`
	Session  [8]byte  `json:"session"`
	CID      [32]byte `json:"cid"`
	Deadline int64    `json:"deadline"`
	Before   []byte   `json:"before"`
	Record   []byte   `json:"record"`
	Payload  []byte   `json:"payload"`
}

func (s *FileStateStore) journalPath() string { return filepath.Join(s.dir, receiveJournalFile) }

func privateAtomic(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".receive-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (s *FileStateStore) readReceive() (*ReceivePending, error) {
	raw, err := bounds.ReadBound(s.journalPath(), maxReceiveJournal)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.protector.Open(receiveJournalID, raw)
	if err != nil {
		return nil, fmt.Errorf("ratchetwire: decrypt receive journal: %w", err)
	}
	defer clear(plain)
	var p ReceivePending
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("ratchetwire: trailing receive journal data")
	}
	if p.Version != 1 || p.Session == ([8]byte{}) || p.CID == ([32]byte{}) || p.Deadline <= 0 || len(p.Payload) == 0 || len(p.Payload) > 96<<10 || len(p.Record) > 64<<10 || len(p.Before) != 32 {
		return nil, errors.New("ratchetwire: invalid receive journal")
	}
	_, state, err := UnprotectSession(s.protector, p.Session, p.Record)
	if err != nil {
		return nil, err
	}
	defer clear(state)
	session, err := ratchet.ImportState(state)
	if err != nil {
		return nil, err
	}
	defer session.Erase()
	if session.ID() != p.Session {
		return nil, errors.New("ratchetwire: journal session mismatch")
	}
	return &p, nil
}

func (s *FileStateStore) prepareReceive(id [8]byte, cid [32]byte, deadline int64, state, payload []byte) (*ReceivePending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pending, err := s.readReceive(); err != nil {
		return nil, err
	} else if pending != nil {
		return nil, errors.New("ratchetwire: application receive pending; recover first")
	}
	head, err := bounds.ReadBound(s.path(id), 64<<10)
	if err != nil {
		return nil, err
	}
	seq, _, err := UnprotectSession(s.protector, id, head)
	if err != nil {
		return nil, err
	}
	logged, err := s.maxLoggedSequence(id)
	if err != nil {
		return nil, err
	}
	if logged > seq || seq == ^uint64(0) {
		return nil, errors.New("ratchetwire: rollback or sequence exhaustion before journal preparation")
	}
	record, err := ProtectSession(s.protector, id, seq+1, state)
	if err != nil {
		return nil, err
	}
	if len(record) > 64<<10 || len(payload) > 96<<10 {
		return nil, bounds.ErrTooLarge
	}
	digest := StateDigest(head)
	p := &ReceivePending{Version: 1, Session: id, CID: cid, Deadline: deadline, Before: append([]byte(nil), digest[:]...), Record: record, Payload: append([]byte(nil), payload...)}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	raw, err := s.protector.Seal(receiveJournalID, plain)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxReceiveJournal {
		return nil, bounds.ErrTooLarge
	}
	if err := privateAtomic(s.journalPath(), raw); err != nil {
		return nil, err
	}
	return p, nil
}

// commitReceive permits only the original head or the exact next head; it
// NEVER restores over a newer/different session state. Log-ahead-of-head is
// recoverable only at the exact journaled sequence and record digest.
func (s *FileStateStore) commitReceive(p *ReceivePending) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, state, err := UnprotectSession(s.protector, p.Session, p.Record)
	if err != nil {
		return nil, err
	}
	head, err := bounds.ReadBound(s.path(p.Session), 64<<10)
	if err != nil {
		return nil, err
	}
	digest := StateDigest(head)
	if !bytes.Equal(head, p.Record) && !bytes.Equal(digest[:], p.Before) {
		return nil, errors.New("ratchetwire: receive journal conflicts with current state; refusing rollback")
	}
	logged, err := s.maxLoggedSequence(p.Session)
	if err != nil {
		return nil, err
	}
	if logged > seq {
		return nil, errors.New("ratchetwire: receive journal sequence is stale")
	}
	if logged == seq {
		log, err := bounds.ReadBound(s.logPath(p.Session), 1<<16)
		if err != nil {
			return nil, err
		}
		want := StateDigest(p.Record)
		found := false
		for off := 0; off+logRecordSize <= len(log); off += logRecordSize {
			if binary.LittleEndian.Uint64(log[off:off+8]) == seq && bytes.Equal(log[off+8:off+logRecordSize], want[:]) {
				found = true
			}
		}
		if !found {
			return nil, errors.New("ratchetwire: receive journal conflicts with sequence log")
		}
	} else {
		// A killed append can leave a partial trailing record. Remove only
		// that untrusted tail before retrying, otherwise appending a whole
		// record would misalign the ledger and make the recovered head unreadable.
		log, err := bounds.ReadBound(s.logPath(p.Session), 1<<16)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if len(log)-len(log)%logRecordSize+logRecordSize > 1<<16 {
			return nil, bounds.ErrTooLarge
		}
		if tail := len(log) % logRecordSize; tail != 0 {
			if err := os.Truncate(s.logPath(p.Session), int64(len(log)-tail)); err != nil {
				return nil, err
			}
		}
		if err := s.appendLog(p.Session, seq, StateDigest(p.Record)); err != nil {
			return nil, err
		}
	}
	if !bytes.Equal(head, p.Record) {
		if err := privateAtomic(s.path(p.Session), p.Record); err != nil {
			return nil, err
		}
	}
	s.sequence[p.Session] = seq
	return state, nil
}

// recoverReceiveState runs BEFORE ordinary head restoration/expiry. An
// unfinished application write retains its payload even after frame TTL expiry;
// expiry never prevents completing the ratchet transition already journaled.
func (s *FileStateStore) recoverReceiveState() error {
	p, err := s.readReceive()
	if err != nil || p == nil {
		return err
	}
	state, err := s.commitReceive(p)
	clear(state)
	return err
}

func (e *DurableEndpoint) PendingReceive() (*ReceivePending, error)           { return e.states.readReceive() }
func (s *FileStateStore) PendingApplicationReceive() (*ReceivePending, error) { return s.readReceive() }

// DiscardReceive requires the exact inspected CID. It completes the ratchet
// commit but intentionally performs no application write and issues no receipt.
func (e *DurableEndpoint) DiscardReceive(cid string) error {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	p, err := e.PendingReceive()
	if err != nil {
		return err
	}
	if p == nil || hex.EncodeToString(p.CID[:]) != cid {
		return errors.New("ratchetwire: discard requires exact pending CID")
	}
	state, err := e.states.commitReceive(p)
	if err != nil {
		clear(state)
		return err
	}
	defer clear(state)
	if err := e.Sessions.Replace(p.Session, state); err != nil {
		return err
	}
	return os.Remove(e.states.journalPath())
}

func (e *DurableEndpoint) requireNoPendingReceive() error {
	p, err := e.PendingReceive()
	if err != nil {
		return err
	}
	if p != nil {
		return errors.New("ratchetwire: application receive pending; recover before other session transitions")
	}
	return nil
}

// RecoverReceive retries only application persistence. commitReceive completes
// the exact journaled head (or confirms it), never decrypting/re-encrypting.
// The callback must persist idempotently; journal deletion comes LAST.
func (e *DurableEndpoint) RecoverReceive(apply func(*ReceivePending) error) error {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	p, err := e.PendingReceive()
	if err != nil || p == nil {
		return err
	}
	if apply == nil {
		return errors.New("ratchetwire: receive recovery callback required")
	}
	state, err := e.states.commitReceive(p)
	if err != nil {
		return err
	}
	defer clear(state)
	if err := e.Sessions.Replace(p.Session, state); err != nil {
		return err
	}
	if err := apply(p); err != nil {
		return err
	}
	if err := os.Remove(e.states.journalPath()); err != nil {
		return err
	}
	return nil
}

// ReceiveNextJournaled decrypts on a disposable clone. For selected application
// payloads, journal -> exact keystore commit -> live replacement -> application
// commit -> journal delete. A failed journal write leaves the live/disk ratchet
// unchanged. Errors after journaling block all later transitions until recovery.
func (e *DurableEndpoint) ReceiveNextJournaled(p Pointer, now time.Time, selectPayload func([]byte) bool, apply func(*ReceivePending) error) ([]byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return nil, err
	}
	frame, err := FetchFrame(e.Store, p, now)
	if err != nil {
		return nil, err
	}
	if frame.Kind != FrameMessage {
		return nil, errors.New("ratchetwire: expected continuation")
	}
	before, err := e.Sessions.Export(frame.SessionID)
	if err != nil {
		return nil, err
	}
	defer clear(before)
	copySession, err := ratchet.ImportState(before)
	if err != nil {
		return nil, err
	}
	defer copySession.Erase()
	plain, err := copySession.DecryptWithDeadline(frame.Message, frame.DeadlineTime())
	if err != nil {
		return nil, err
	}
	next, err := copySession.Export()
	if err != nil {
		return nil, err
	}
	defer clear(next)
	if selectPayload == nil || !selectPayload(plain) {
		if err := e.states.Save(frame.SessionID, next); err != nil {
			return nil, err
		}
		if err := e.Sessions.Replace(frame.SessionID, next); err != nil {
			return nil, err
		}
		return plain, nil
	}
	pending, err := e.states.prepareReceive(frame.SessionID, p.CID, int64(p.BurnDeadline), next, plain)
	if err != nil {
		return nil, err
	}
	state, err := e.states.commitReceive(pending)
	if err != nil {
		return nil, err
	}
	defer clear(state)
	if err := e.Sessions.Replace(frame.SessionID, state); err != nil {
		return nil, err
	}
	if apply == nil {
		return nil, errors.New("ratchetwire: application callback required")
	}
	if err := apply(pending); err != nil {
		return nil, err
	}
	if err := os.Remove(e.states.journalPath()); err != nil {
		return nil, err
	}
	return plain, nil
}
