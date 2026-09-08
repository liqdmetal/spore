package ratchetwire

import (
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// Endpoint is the endpoint-local E2 adapter. It never writes session state to
// a carrier or body store; callers persist ExportState through a protected
// local keystore.
type Endpoint struct {
	Sessions *SessionTable
	Store    BodyStore
}

func NewEndpoint(st BodyStore) *Endpoint {
	return &Endpoint{Sessions: NewSessionTable(), Store: st}
}

func exportSession(s *ratchet.Session) ([]byte, error) {
	if s == nil {
		return nil, errors.New("ratchetwire: nil session")
	}
	return s.Export()
}

func pointerFor(p Pointer) []byte {
	return PointerPayload{Version: PointerV1, Route: p.Route, CID: p.CID, BurnDeadline: p.BurnDeadline}.MarshalBinary()
}

// SendFirst creates an X3DH init frame, stores it off-chain, and returns the
// pointer plus its canonical chain encoding. The caller posts only the pointer.
func (e *Endpoint) SendFirst(identity []byte, bundle *ratchet.SPKBundle, pinnedSig []byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return Pointer{}, nil, errors.New("ratchetwire: incomplete endpoint")
	}
	s, hs, err := ratchet.EstablishInitiator(identity, bundle, pinnedSig)
	if err != nil {
		return Pointer{}, nil, err
	}
	msg, err := s.Encrypt(plaintext)
	if err != nil {
		return Pointer{}, nil, err
	}
	frame, err := NewInitFrame(hs, msg, deadline)
	if err != nil {
		return Pointer{}, nil, err
	}
	state, err := exportSession(s)
	if err != nil {
		return Pointer{}, nil, err
	}
	if err := e.Sessions.Restore(hs.SessionID, state); err != nil {
		return Pointer{}, nil, fmt.Errorf("ratchetwire: install initiator: %w", err)
	}
	ptr, err := PutFrame(e.Store, frame)
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return Pointer{}, nil, err
	}
	return ptr, pointerFor(ptr), nil
}

// ReceiveFirst validates an off-chain init frame before installing endpoint
// state. The caller has already decoded the signed handshake and fetched the body.
func (e *Endpoint) ReceiveFirst(identity, spk []byte, opk *[32]byte, frame Frame, rawFrame []byte) ([]byte, error) {
	if e == nil || e.Sessions == nil {
		return nil, errors.New("ratchetwire: incomplete endpoint")
	}
	if frame.Kind != FrameInit {
		return nil, errors.New("ratchetwire: not an init frame")
	}
	hs, err := frame.HandshakeMessage()
	if err != nil {
		return nil, err
	}
	s, err := ratchet.EstablishResponder(identity, spk, opk, hs)
	if err != nil {
		return nil, err
	}
	if err := e.Sessions.AcceptInit(hs, s, rawFrame); err != nil {
		return nil, err
	}
	// Decrypt after publishing so the session transition is serialized with
	// installation. If authentication fails, remove this just-installed
	// session so a valid retry with the same init cannot be permanently blocked.
	plaintext, err := s.DecryptWithDeadline(frame.Message, time.Unix(int64(frame.Deadline), 0))
	if err != nil {
		e.Sessions.Erase(hs.SessionID)
		return nil, err
	}
	return plaintext, nil
}

// ReceiveFirstFromPool consumes the handshake's OPK durably before accepting.
func (e *Endpoint) ReceiveFirstFromOPKPool(identity, spk []byte, pool *OPKPool, frame Frame, rawFrame []byte) ([]byte, error) {
	if pool == nil {
		return nil, errors.New("ratchetwire: nil OPK pool")
	}
	hs, err := frame.HandshakeMessage()
	if err != nil {
		return nil, err
	}
	if hs.Degraded {
		return e.ReceiveFirst(identity, spk, nil, frame, rawFrame)
	}
	opk, err := pool.Take(hs.OPKID)
	if err != nil {
		return nil, err
	}
	return e.ReceiveFirst(identity, spk, &opk, frame, rawFrame)
}

// SendNext encrypts a continuation, stores it under a fresh CID, and returns
// the opaque chain pointer. State persistence must occur after this returns and
// before the application acknowledges delivery.
func (e *Endpoint) SendNext(id [8]byte, plaintext []byte, deadline time.Time) (Pointer, []byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return Pointer{}, nil, errors.New("ratchetwire: incomplete endpoint")
	}
	var ptr Pointer
	err := e.Sessions.withSession(id, func(s *ratchet.Session) error {
		msg, err := s.Encrypt(plaintext)
		if err != nil {
			return err
		}
		frame, err := NewMessageFrame(id, msg, deadline)
		if err != nil {
			return err
		}
		ptr, err = PutFrame(e.Store, frame)
		return err
	})
	if err != nil {
		return Pointer{}, nil, err
	}
	return ptr, pointerFor(ptr), nil
}

func (e *Endpoint) ReceiveNext(p Pointer, now time.Time) ([]byte, error) {
	if e == nil || e.Store == nil || e.Sessions == nil {
		return nil, errors.New("ratchetwire: incomplete endpoint")
	}
	frame, err := FetchFrame(e.Store, p, now)
	if err != nil {
		return nil, err
	}
	if frame.Kind != FrameMessage {
		return nil, errors.New("ratchetwire: expected continuation")
	}
	return e.Sessions.Decrypt(frame.SessionID, frame.Message, time.Unix(int64(frame.Deadline), 0))
}
