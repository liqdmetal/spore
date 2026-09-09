package ratchetwire

import (
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// DurableEndpoint couples an endpoint-local session table to an encrypted
// FileStateStore. It does not add a transport: frame bodies still use the
// Endpoint's existing BodyStore and callers still exchange pointers.
type DurableEndpoint struct {
	*Endpoint
	states *FileStateStore
	// SessionExpiry is an inactivity TTL. Zero disables session expiry.
	SessionExpiry time.Duration
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
	e := &DurableEndpoint{Endpoint: NewEndpoint(body), states: states, SessionExpiry: expiry}
	ids, err := states.IDs()
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
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
		if expiry > 0 && s.InactiveBefore(now.Add(-expiry)) {
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
		e.Expire(now)
	}
	return e, nil
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
	// The session id comes back from the handshake directly. It used to be
	// recovered by re-fetching the just-stored frame with a synthesised "now"
	// of deadline-1ns, which silently failed for any deadline carrying
	// nanoseconds (i.e. every real CLI call) — see SendFirstSession.
	p, raw, id, err := e.Endpoint.SendFirstSession(identity, bundle, pinnedSig, plaintext, deadline)
	if err != nil {
		return Pointer{}, nil, err
	}
	if id == ([8]byte{}) {
		return Pointer{}, nil, errors.New("ratchetwire: initial session not installed")
	}
	if err := e.save(id); err != nil {
		e.expired(id)
		return Pointer{}, nil, fmt.Errorf("ratchetwire: persist initial session: %w", err)
	}
	return p, raw, nil
}

// SendNext saves state after the body store accepts the continuation.
func (e *DurableEndpoint) SendNext(id [8]byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
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

// ReceiveNext saves state after successful decryption and erases expired
// sessions and their local protected records.
// ReceiveFirstFromOPKPool consumes the referenced OPK durably before accepting the session.
func (e *DurableEndpoint) ReceiveFirstFromOPKPool(identity, spk []byte, pool *OPKPool, frame Frame, rawFrame []byte) ([]byte, error) {
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
	s, err := pool.EstablishResponder(identity, spk, hs)
	if err != nil {
		return nil, err
	}
	if err := e.Sessions.AcceptInit(hs, s, rawFrame); err != nil {
		return nil, err
	}
	plaintext, err := s.DecryptWithDeadline(frame.Message, frame.DeadlineTime())
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return nil, err
	}
	if err := e.save(frame.SessionID); err != nil {
		return nil, fmt.Errorf("ratchetwire: persist receive transition: %w", err)
	}
	return plaintext, nil
}

func (e *DurableEndpoint) ReceiveNext(p Pointer, now time.Time) ([]byte, error) {
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
func (e *DurableEndpoint) Expire(now time.Time) int {
	if now.IsZero() {
		now = time.Now()
	}
	removed := e.Sessions.Sweep(now)
	if e.SessionExpiry <= 0 {
		return removed
	}
	cutoff := now.Add(-e.SessionExpiry)
	for _, id := range e.Sessions.IDs() {
		s := e.Sessions.Get(id)
		if s != nil && s.InactiveBefore(cutoff) {
			e.expired(id)
			removed++
		}
	}
	return removed
}
