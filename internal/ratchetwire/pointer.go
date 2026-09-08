package ratchetwire

import (
	"encoding/binary"
	"fmt"
)

// PointerV1 is the chain-carried ratchet pointer. It contains no plaintext,
// ratchet ciphertext, handshake, or decryption key. The route is a public
// lookup handle; the CID commits to the encrypted off-chain frame.
const PointerV1 byte = 1

const pointerLen = 1 + 1 + 32 + 32 + 8

type PointerPayload struct {
	Version      byte
	Route        [32]byte
	CID          [32]byte
	BurnDeadline uint64
}

func (p PointerPayload) MarshalBinary() []byte {
	out := make([]byte, pointerLen)
	out[0] = PointerV1
	out[1] = 0
	copy(out[2:34], p.Route[:])
	copy(out[34:66], p.CID[:])
	binary.LittleEndian.PutUint64(out[66:74], p.BurnDeadline)
	return out
}

func ParsePointerPayload(b []byte) (PointerPayload, error) {
	if len(b) != pointerLen || b[0] != PointerV1 || b[1] != 0 {
		return PointerPayload{}, fmt.Errorf("ratchetwire: invalid pointer payload")
	}
	var p PointerPayload
	p.Version = b[0]
	copy(p.Route[:], b[2:34])
	copy(p.CID[:], b[34:66])
	p.BurnDeadline = binary.LittleEndian.Uint64(b[66:74])
	if p.BurnDeadline == 0 {
		return PointerPayload{}, fmt.Errorf("ratchetwire: zero pointer deadline")
	}
	return p, nil
}

func (p PointerPayload) Pointer() Pointer {
	return Pointer{Route: p.Route, CID: p.CID, BurnDeadline: p.BurnDeadline}
}
