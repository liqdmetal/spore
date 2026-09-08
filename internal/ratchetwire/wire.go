// Package ratchetwire binds the X3DH + Double Ratchet session to Spore's
// chain-agnostic pointer transport. Chains carry only a CID pointer; the
// ratcheted frame stays off-chain and is fetched through spore-peer or a
// mailbox. The carrier never receives a ratchet key.
package ratchetwire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/liqdmetal/spore/internal/ratchet"
	"github.com/liqdmetal/spore/internal/store"
)

const (
	Magic               = "SPR2"
	Version        byte = 1
	FrameInit      byte = 1
	FrameMessage   byte = 2
	frameHeaderLen      = 4 + 1 + 1 + 1 + 1 + 8 + 8 + 2 + 4
	maxHandshake        = 4096
	maxMessage          = 16 << 20
)

var (
	ErrBadFrame = errors.New("ratchetwire: bad frame")
	ErrExpired  = errors.New("ratchetwire: frame expired")
)

type Pointer struct {
	Route        [32]byte
	CID          [32]byte
	BurnDeadline uint64
}

func (p Pointer) Deadline() time.Time {
	if p.BurnDeadline == 0 {
		return time.Time{}
	}
	return time.Unix(int64(p.BurnDeadline), 0)
}

// RouteKey is a non-secret route handle. It is deliberately not a decryption
// key; the frame's CID is the only body lookup token.
func RouteKey(sessionID [8]byte) [32]byte {
	b := make([]byte, 0, len("spore/dr/v1/route")+len(sessionID))
	b = append(b, "spore/dr/v1/route"...)
	b = append(b, sessionID[:]...)
	return sha256.Sum256(b)
}

type Frame struct {
	Kind      byte
	SessionID [8]byte
	Deadline  uint64
	Handshake []byte
	Message   ratchet.Message
}

func NewInitFrame(hs *ratchet.HandshakeMessage, msg ratchet.Message, deadline time.Time) (Frame, error) {
	if hs == nil {
		return Frame{}, fmt.Errorf("%w: missing handshake", ErrBadFrame)
	}
	if deadline.IsZero() || !deadline.After(time.Now()) {
		return Frame{}, fmt.Errorf("%w: deadline must be in the future", ErrBadFrame)
	}
	return Frame{Kind: FrameInit, SessionID: hs.SessionID, Deadline: uint64(deadline.Unix()), Handshake: hs.MarshalBinary(), Message: msg}, nil
}

func NewMessageFrame(sessionID [8]byte, msg ratchet.Message, deadline time.Time) (Frame, error) {
	if deadline.IsZero() || !deadline.After(time.Now()) {
		return Frame{}, fmt.Errorf("%w: deadline must be in the future", ErrBadFrame)
	}
	return Frame{Kind: FrameMessage, SessionID: sessionID, Deadline: uint64(deadline.Unix()), Message: msg}, nil
}

// MarshalBinary layout:
// SPR2 || version || kind || flags || reserved || session_id(8) ||
// deadline(u64 LE) || handshake_len(u16 LE) || message_len(u32 LE) || bodies.
func (f Frame) MarshalBinary() ([]byte, error) {
	if f.Kind != FrameInit && f.Kind != FrameMessage {
		return nil, fmt.Errorf("%w: unknown frame kind %d", ErrBadFrame, f.Kind)
	}
	if f.Deadline == 0 || time.Now().Unix() >= int64(f.Deadline) {
		return nil, fmt.Errorf("%w: expired deadline", ErrBadFrame)
	}
	if f.Kind == FrameInit && len(f.Handshake) == 0 {
		return nil, fmt.Errorf("%w: init frame missing handshake", ErrBadFrame)
	}
	if f.Kind == FrameMessage && len(f.Handshake) != 0 {
		return nil, fmt.Errorf("%w: message frame has handshake", ErrBadFrame)
	}
	if len(f.Handshake) > maxHandshake {
		return nil, fmt.Errorf("%w: handshake too large", ErrBadFrame)
	}
	msg := f.Message.MarshalBinary()
	if len(msg) < 64 || len(msg) > maxMessage {
		return nil, fmt.Errorf("%w: message length %d", ErrBadFrame, len(msg))
	}
	out := make([]byte, frameHeaderLen+len(f.Handshake)+len(msg))
	copy(out, Magic)
	out[4] = Version
	out[5] = f.Kind
	// bytes 6-7 are flags/reserved and intentionally remain zero.
	copy(out[8:16], f.SessionID[:])
	binary.LittleEndian.PutUint64(out[16:24], f.Deadline)
	binary.LittleEndian.PutUint16(out[24:26], uint16(len(f.Handshake)))
	binary.LittleEndian.PutUint32(out[26:30], uint32(len(msg)))
	copy(out[30:], f.Handshake)
	copy(out[30+len(f.Handshake):], msg)
	return out, nil
}

func (f Frame) DeadlineTime() time.Time { return time.Unix(int64(f.Deadline), 0) }

func Parse(b []byte) (Frame, error) {
	if len(b) < frameHeaderLen || string(b[:4]) != Magic || b[4] != Version || b[6] != 0 || b[7] != 0 {
		return Frame{}, fmt.Errorf("%w: header", ErrBadFrame)
	}
	kind := b[5]
	if kind != FrameInit && kind != FrameMessage {
		return Frame{}, fmt.Errorf("%w: kind %d", ErrBadFrame, kind)
	}
	hlen := int(binary.LittleEndian.Uint16(b[24:26]))
	mlen := int(binary.LittleEndian.Uint32(b[26:30]))
	if hlen > maxHandshake || mlen < 64 || mlen > maxMessage || frameHeaderLen+hlen+mlen != len(b) {
		return Frame{}, fmt.Errorf("%w: lengths", ErrBadFrame)
	}
	var sid [8]byte
	copy(sid[:], b[8:16])
	f := Frame{Kind: kind, SessionID: sid, Deadline: binary.LittleEndian.Uint64(b[16:24]), Handshake: append([]byte(nil), b[30:30+hlen]...)}
	if f.Deadline == 0 {
		return Frame{}, fmt.Errorf("%w: deadline", ErrBadFrame)
	}
	if kind == FrameInit {
		if hlen == 0 {
			return Frame{}, fmt.Errorf("%w: init handshake", ErrBadFrame)
		}
		hs, err := ratchet.UnmarshalHandshake(f.Handshake)
		if err != nil || hs.SessionID != sid {
			return Frame{}, fmt.Errorf("%w: handshake/session", ErrBadFrame)
		}
	} else if hlen != 0 {
		return Frame{}, fmt.Errorf("%w: message handshake", ErrBadFrame)
	}
	msg, err := ratchet.UnmarshalMessage(b[30+hlen:])
	if err != nil {
		return Frame{}, fmt.Errorf("%w: message: %v", ErrBadFrame, err)
	}
	f.Message = msg
	return f, nil
}

func (f Frame) HandshakeMessage() (*ratchet.HandshakeMessage, error) {
	if f.Kind != FrameInit {
		return nil, fmt.Errorf("%w: no handshake on message frame", ErrBadFrame)
	}
	return ratchet.UnmarshalHandshake(f.Handshake)
}

func BodyCID(b []byte) [32]byte { return sha256.Sum256(b) }

// PutFrame serializes and stores a frame under its content address.
func PutFrame(st store.Store, f Frame) (Pointer, error) {
	b, err := f.MarshalBinary()
	if err != nil {
		return Pointer{}, err
	}
	cid := BodyCID(b)
	deadline := time.Unix(int64(f.Deadline), 0)
	if err := st.Put(cid, b, deadline); err != nil {
		return Pointer{}, err
	}
	return Pointer{Route: RouteKey(f.SessionID), CID: cid, BurnDeadline: f.Deadline}, nil
}

// FetchFrame retrieves and verifies an off-chain frame; expired ciphertext is
// refused before any session state is touched.
func FetchFrame(st store.Store, p Pointer, now time.Time) (Frame, error) {
	if p.BurnDeadline == 0 || now.Unix() >= int64(p.BurnDeadline) {
		return Frame{}, ErrExpired
	}
	body, err := st.Get(p.CID)
	if err != nil {
		return Frame{}, err
	}
	if BodyCID(body) != p.CID {
		return Frame{}, fmt.Errorf("%w: cid mismatch", ErrBadFrame)
	}
	f, err := Parse(body)
	if err != nil {
		return Frame{}, err
	}
	if f.Deadline != p.BurnDeadline || RouteKey(f.SessionID) != p.Route {
		return Frame{}, fmt.Errorf("%w: pointer binding", ErrBadFrame)
	}
	if f.Deadline > 0 && now.Unix() >= int64(f.Deadline) {
		return Frame{}, ErrExpired
	}
	return f, nil
}
