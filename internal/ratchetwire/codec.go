package ratchetwire

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/liqdmetal/spore/internal/ratchet"
)

// BodyKind is the envelope kind stored inside the off-chain frame body.
const BodyKind byte = 0xE2

// Body is the application payload carried by a ratchet frame. Init contains
// the 81-byte X3DH handshake; continuation messages contain no handshake.
type Body struct {
	Kind      byte
	SessionID [8]byte
	Handshake []byte
	Message   ratchet.Message
}

func (b Body) MarshalBinary() ([]byte, error) {
	if b.Kind != BodyKind {
		return nil, fmt.Errorf("ratchetwire: bad body kind 0x%02x", b.Kind)
	}
	if b.SessionID == [8]byte{} {
		return nil, fmt.Errorf("ratchetwire: empty session id")
	}
	if len(b.Handshake) != 0 && len(b.Handshake) != 81 {
		return nil, fmt.Errorf("ratchetwire: bad handshake length %d", len(b.Handshake))
	}
	if len(b.Handshake) == 0 && b.Message.Header.DHPub == [32]byte{} {
		return nil, fmt.Errorf("ratchetwire: empty message header")
	}
	msg := b.Message.MarshalBinary()
	if len(msg) < 64 {
		return nil, fmt.Errorf("ratchetwire: short message")
	}
	// E2 || flags || session(8) || handshake_len(u16) || msg_len(u32) || data.
	out := make([]byte, 1+1+8+2+4+len(b.Handshake)+len(msg))
	out[0] = BodyKind
	copy(out[2:10], b.SessionID[:])
	binary.LittleEndian.PutUint16(out[10:12], uint16(len(b.Handshake)))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(msg)))
	copy(out[16:], b.Handshake)
	copy(out[16+len(b.Handshake):], msg)
	return out, nil
}

func ParseBody(raw []byte) (Body, error) {
	if len(raw) < 16+64 || raw[0] != BodyKind || raw[1] != 0 {
		return Body{}, fmt.Errorf("ratchetwire: malformed E2 body")
	}
	hlen := int(binary.LittleEndian.Uint16(raw[10:12]))
	mlen := int(binary.LittleEndian.Uint32(raw[12:16]))
	if (hlen != 0 && hlen != 81) || mlen < 64 || 16+hlen+mlen != len(raw) {
		return Body{}, fmt.Errorf("ratchetwire: invalid E2 lengths")
	}
	var sid [8]byte
	copy(sid[:], raw[2:10])
	if sid == [8]byte{} {
		return Body{}, fmt.Errorf("ratchetwire: empty session id")
	}
	var hs []byte
	if hlen != 0 {
		hs = append([]byte(nil), raw[16:16+hlen]...)
		h, err := ratchet.UnmarshalHandshake(hs)
		if err != nil || h.SessionID != sid {
			return Body{}, fmt.Errorf("ratchetwire: invalid handshake")
		}
	}
	msg, err := ratchet.UnmarshalMessage(raw[16+hlen:])
	if err != nil {
		return Body{}, fmt.Errorf("ratchetwire: invalid message: %w", err)
	}
	return Body{Kind: BodyKind, SessionID: sid, Handshake: hs, Message: msg}, nil
}

// ConstantTimeSessionEqual is used at the endpoint seam before touching
// ratchet state. It avoids accidentally accepting a frame for another session.
func ConstantTimeSessionEqual(a, b [8]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func (b Body) IsInit() bool { return len(b.Handshake) != 0 }

func (b Body) HandshakeMessage() (*ratchet.HandshakeMessage, error) {
	if !b.IsInit() {
		return nil, fmt.Errorf("ratchetwire: no handshake")
	}
	return ratchet.UnmarshalHandshake(b.Handshake)
}

// FrameBody converts a parsed frame to the compact E2 body. This is the form
// handed to the body store; the chain pointer never contains it.
func FrameBody(f Frame) (Body, error) {
	return Body{Kind: BodyKind, SessionID: f.SessionID, Handshake: append([]byte(nil), f.Handshake...), Message: f.Message}, nil
}

func (b Body) Frame(deadline uint64) Frame {
	kind := FrameMessage
	if b.IsInit() {
		kind = FrameInit
	}
	return Frame{Kind: kind, SessionID: b.SessionID, Deadline: deadline, Handshake: b.Handshake, Message: b.Message}
}
