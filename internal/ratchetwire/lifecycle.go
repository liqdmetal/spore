package ratchetwire

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// DurableEndpoint couples an endpoint-local session table to an encrypted
// FileStateStore. It does not add a transport: frame bodies still use the
// Endpoint's existing BodyStore and callers still exchange pointers.
type DurableEndpoint struct {
	*Endpoint
	states        *FileStateStore
	SessionExpiry time.Duration
	// Serialize the clone/journal/head/application transition with sends on
	// this endpoint. Independent processes still require exclusive ownership.
	transitionMu sync.Mutex

	// lossMu guards the confirmed-loss ledger. It is a leaf lock: taken only
	// after Sessions' own lock has been released, never held across it.
	lossMu              sync.Mutex
	lostTotal           uint64
	lostTrunc           bool
	lostGaps            []MessageGap
	lossPersistenceErr  string
	lossSessionsPending map[[8]byte]bool
}

// NewDurableEndpoint opens the endpoint-local state directory and restores all
// sessions already present there. Files that are expired or absent are removed.
func NewDurableEndpoint(body BodyStore, states *FileStateStore, now time.Time) (*DurableEndpoint, error) {
	return newDurableEndpoint(body, states, 0, now)
}

// NewDurableEndpointWithExpiry restores endpoint-local state and applies the
// inactivity policy before the endpoint can process a frame.
func NewDurableEndpointWithExpiry(body BodyStore, states *FileStateStore, expiry time.Duration, now time.Time) (*DurableEndpoint, error) {
	return newDurableEndpoint(body, states, expiry, now)
}

func newDurableEndpoint(body BodyStore, states *FileStateStore, expiry time.Duration, now time.Time) (*DurableEndpoint, error) {
	if states == nil {
		return nil, errors.New("ratchetwire: nil file state store")
	}
	if err := states.recoverReceiveState(); err != nil {
		return nil, fmt.Errorf("ratchetwire: recover receive state: %w", err)
	}
	pending, err := states.readReceive()
	if err != nil {
		return nil, err
	}
	ep := NewEndpoint(body)
	e := &DurableEndpoint{Endpoint: ep, states: states, SessionExpiry: expiry, lossSessionsPending: make(map[[8]byte]bool)}
	ids, err := states.IDs()
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := e.loadGapLedger(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		state, err := states.Load(id)
		if err != nil {
			return nil, fmt.Errorf("ratchetwire: restore session %x: %w", id, err)
		}
		s, err := ratchet.ImportState(state)
		if err != nil {
			return nil, fmt.Errorf("ratchetwire: restore session %x: %w", id, err)
		}
		if expiry > 0 && (pending == nil || pending.Session != id) && s.InactiveBefore(now.Add(-expiry)) {
			if err := states.Delete(id); err != nil {
				return nil, fmt.Errorf("ratchetwire: delete expired session %x: %w", id, err)
			}
			continue
		}
		if err := e.Sessions.Restore(id, state); err != nil {
			return nil, fmt.Errorf("ratchetwire: install restored session %x: %w", id, err)
		}
	}
	if e.SessionExpiry > 0 {
		if _, err := e.ExpireChecked(now); err != nil {
			return nil, fmt.Errorf("ratchetwire: expire restored endpoint state: %w", err)
		}
	}
	return e, nil
}

// StateDir returns the endpoint's protected state directory for adjacent
// endpoint-local metadata such as the send-collision ledger.
func (e *DurableEndpoint) StateDir() string {
	if e == nil || e.states == nil {
		return ""
	}
	return e.states.StateDir()
}

func (e *DurableEndpoint) save(id [8]byte) error {
	state, err := e.Sessions.Export(id)
	if err != nil {
		return err
	}
	return e.states.Save(id, state)
}

func (e *DurableEndpoint) expired(id [8]byte) {
	e.Sessions.Erase(id)
	_ = e.states.Delete(id)
}

// SendFirst performs the existing X3DH send and durably saves the resulting
// session only after the frame has been stored successfully.
func (e *DurableEndpoint) SendFirst(identity []byte, bundle *ratchet.SPKBundle, pinnedSig []byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	p, raw, _, err := e.SendFirstSession(identity, bundle, pinnedSig, plaintext, deadline)
	return p, raw, err
}

// SendFirstSession is SendFirst that also reports the new session id.
//
// It exists because DurableEndpoint embeds *Endpoint, so calling
// Endpoint.SendFirstSession directly COMPILES but silently skips the durable
// save — the session then exists only in memory, and a later reply fails with
// "unknown session" while the send looked successful. Any caller that needs the
// id must come through here.
func (e *DurableEndpoint) SendFirstSession(identity []byte, bundle *ratchet.SPKBundle, pinnedSig []byte, plaintext []byte, deadline time.Time) (Pointer, []byte, [8]byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}
	// The session id comes back from the handshake directly. It used to be
	// recovered by re-fetching the just-stored frame with a synthesised "now"
	// of deadline-1ns, which silently failed for any deadline carrying
	// nanoseconds (i.e. every real CLI call) — see Endpoint.SendFirstSession.
	p, raw, id, err := e.Endpoint.SendFirstSession(identity, bundle, pinnedSig, plaintext, deadline)
	if err != nil {
		return Pointer{}, nil, [8]byte{}, err
	}
	if id == ([8]byte{}) {
		return Pointer{}, nil, [8]byte{}, errors.New("ratchetwire: initial session not installed")
	}
	if err := e.save(id); err != nil {
		e.expired(id)
		return Pointer{}, nil, [8]byte{}, fmt.Errorf("ratchetwire: persist initial session: %w", err)
	}
	return p, raw, id, nil
}

// SendNext saves state after the body store accepts the continuation.
func (e *DurableEndpoint) SendNext(id [8]byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return Pointer{}, nil, err
	}
	p, raw, err := e.Endpoint.SendNext(id, plaintext, deadline)
	if err != nil {
		return Pointer{}, nil, err
	}
	if err := e.save(id); err != nil {
		return Pointer{}, nil, fmt.Errorf("ratchetwire: persist send transition: %w", err)
	}
	return p, raw, nil
}

// ReceiveFirst saves state after successful decryption.
func (e *DurableEndpoint) ReceiveFirst(identity, spk []byte, opk *[32]byte, frame Frame, rawFrame []byte) ([]byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return nil, err
	}
	plaintext, err := e.Endpoint.ReceiveFirst(identity, spk, opk, frame, rawFrame)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			e.expired(frame.SessionID)
		}
		return nil, err
	}
	if err := e.save(frame.SessionID); err != nil {
		return nil, fmt.Errorf("ratchetwire: persist receive transition: %w", err)
	}
	return plaintext, nil
}

// ReceiveFirstFromOPKPool consumes the referenced OPK durably before accepting the session.
func (e *DurableEndpoint) ReceiveFirstFromOPKPool(identity, spk []byte, pool *OPKPool, frame Frame, rawFrame []byte) ([]byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, errors.New("ratchetwire: nil OPK pool")
	}
	if frame.Kind != FrameInit {
		return nil, errors.New("ratchetwire: not an init frame")
	}
	hs, err := frame.HandshakeMessage()
	if err != nil {
		return nil, err
	}
	// Validate against a peeked key. The prekey is consumed only after the first
	// message authenticates, so a frame that fails validation leaves it usable.
	var opk *[32]byte
	if !hs.Degraded {
		priv, err := pool.Peek(hs.OPKID)
		if err != nil {
			return nil, pool.fail(StageLookup, hs.OPKID, err)
		}
		opk = &priv
	}
	s, err := ratchet.EstablishResponder(identity, spk, opk, hs)
	if err != nil {
		return nil, pool.fail(StageValidate, hs.OPKID, err)
	}
	if err := e.Sessions.AcceptInit(hs, s, rawFrame); err != nil {
		return nil, pool.fail(StageValidate, hs.OPKID, err)
	}
	plaintext, err := s.DecryptWithDeadline(frame.Message, frame.DeadlineTime())
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return nil, pool.fail(StageAuthenticate, hs.OPKID, err)
	}
	if opk != nil {
		if err := pool.TakeMatching(hs.OPKID, *opk); err != nil {
			e.Sessions.Erase(hs.SessionID)
			return nil, pool.fail(StageCommit, hs.OPKID, err)
		}
	}
	if err := e.save(frame.SessionID); err != nil {
		return nil, fmt.Errorf("ratchetwire: persist receive transition: %w", err)
	}
	return plaintext, nil
}

func (e *DurableEndpoint) ReceiveNext(p Pointer, now time.Time) ([]byte, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return nil, err
	}
	// Fetch exactly once. Body stores may implement one-shot/off-chain reads
	// that reap the body after returning it; fetching again after decryption
	// would turn a successful receive into a false failure.
	frame, err := FetchFrame(e.Store, p, now)
	if err != nil {
		// An expired frame is not evidence that the ratchet session itself
		// expired. Session state has no session deadline, so retain it.
		return nil, err
	}
	if frame.Kind != FrameMessage {
		return nil, errors.New("ratchetwire: expected continuation")
	}
	plaintext, err := e.Sessions.Decrypt(frame.SessionID, frame.Message, frame.DeadlineTime())
	if err != nil {
		return nil, err
	}
	if err := e.save(frame.SessionID); err != nil {
		return nil, fmt.Errorf("ratchetwire: persist receive transition: %w", err)
	}
	return plaintext, nil
}

// Expire removes skipped keys past their message deadlines and, when
// SessionExpiry is configured, erases sessions that have been inactive for the
// configured duration. Erasure removes both live key material and its protected
// durable record.
//
// Every swept skipped key is a CONFIRMED LOSS — a message whose ciphertext
// never arrived and whose key is now gone — and is recorded in the endpoint's
// loss ledger (see Gaps).
func (e *DurableEndpoint) Expire(now time.Time) int {
	removed, err := e.ExpireChecked(now)
	if err != nil {
		e.setLossPersistenceError(err)
	}
	return removed
}

// ExpireChecked sweeps expired message keys, durably records confirmed loss,
// and persists each affected session with the swept keys removed. Loss metadata
// is committed first so a crash before the ratchet save can be deduplicated on
// restart; failure leaves the old encrypted session available for retry.
func (e *DurableEndpoint) ExpireChecked(now time.Time) (int, error) {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if err := e.requireNoPendingReceive(); err != nil {
		return 0, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	lost := e.Sessions.SweepGaps(now)
	if len(lost) > 0 {
		e.noteLost(lost)
		for _, gap := range lost {
			e.lossSessionsPending[gap.SessionID] = true
		}
	}
	if len(lost) > 0 || e.hasLossPersistenceError() {
		if err := e.persistGapLedgerIfNeeded(); err != nil {
			e.setLossPersistenceError(err)
			return len(lost), err
		}
	}
	for id := range e.lossSessionsPending {
		if err := e.save(id); err != nil {
			err = fmt.Errorf("ratchetwire: persist swept gap state for session %x: %w", id, err)
			e.setLossPersistenceError(err)
			return len(lost), err
		}
		delete(e.lossSessionsPending, id)
	}
	e.setLossPersistenceError(nil)
	removed := len(lost)
	if e.SessionExpiry <= 0 {
		return removed, nil
	}
	cutoff := now.Add(-e.SessionExpiry)
	for _, id := range e.Sessions.IDs() {
		s := e.Sessions.Get(id)
		if s != nil && s.InactiveBefore(cutoff) {
			e.expired(id)
			removed++
		}
	}
	return removed, nil
}
