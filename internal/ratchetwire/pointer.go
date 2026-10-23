package ratchetwire

import (
	"encoding/binary"
	"fmt"
)

// PointerV1 is the original chain-carried ratchet pointer. The CID is the
// SHA-256 commitment to the encrypted off-chain frame. PointerV2 adds a
// transport locator without replacing that integrity commitment.
const (
	PointerV1 byte = 1
	PointerV2 byte = 2
)

const (
	pointerV1Len = 1 + 1 + 32 + 32 + 8
	pointerV2Len = pointerV1Len + 32
	pointerLen   = pointerV1Len // historical name for the V1 shape
)

type PointerPayload struct {
	Version      byte
	Route        [32]byte
	CID          [32]byte
	BurnDeadline uint64
	IrohHash     [32]byte // present only in PointerV2; locator, not integrity proof
	RouteOmitted bool     // set only by compact DERO V2 decode; not on canonical wire
}

func (p PointerPayload) MarshalBinary() []byte {
	if p.RouteOmitted {
		return nil
	}
	var out []byte
	switch p.Version {
	case PointerV1:
		if p.IrohHash != ([32]byte{}) {
			return nil
		}
		out = make([]byte, pointerV1Len)
	case PointerV2:
		out = make([]byte, pointerV2Len)
	default:
		return nil
	}
	out[0] = p.Version
	out[1] = 0
	copy(out[2:34], p.Route[:])
	copy(out[34:66], p.CID[:])
	binary.LittleEndian.PutUint64(out[66:74], p.BurnDeadline)
	if p.Version == PointerV2 {
		copy(out[74:106], p.IrohHash[:])
	}
	return out
}

func ParsePointerPayload(b []byte) (PointerPayload, error) {
	if len(b) < 2 || b[1] != 0 {
		return PointerPayload{}, fmt.Errorf("ratchetwire: invalid pointer payload")
	}
	switch b[0] {
	case PointerV1:
		if len(b) != pointerV1Len {
			return PointerPayload{}, fmt.Errorf("ratchetwire: invalid v1 pointer payload")
		}
	case PointerV2:
		if len(b) != pointerV2Len {
			return PointerPayload{}, fmt.Errorf("ratchetwire: invalid v2 pointer payload")
		}
	default:
		return PointerPayload{}, fmt.Errorf("ratchetwire: invalid pointer version")
	}
	var p PointerPayload
	p.Version = b[0]
	copy(p.Route[:], b[2:34])
	copy(p.CID[:], b[34:66])
	p.BurnDeadline = binary.LittleEndian.Uint64(b[66:74])
	if p.Version == PointerV2 {
		copy(p.IrohHash[:], b[74:106])
	}
	if p.BurnDeadline == 0 {
		return PointerPayload{}, fmt.Errorf("ratchetwire: zero pointer deadline")
	}
	return p, nil
}

func (p PointerPayload) Pointer() Pointer {
	out := Pointer{Route: p.Route, CID: p.CID, BurnDeadline: p.BurnDeadline, RouteOmitted: p.RouteOmitted}
	if p.Version == PointerV2 {
		out.IrohHash = p.IrohHash
		out.HasIrohHash = true
	}
	return out
}

// PayloadForPointer preserves the V1 chain shape unless a portable locator is
// present. V2 carries both the SHA-256 CID and the Iroh BLAKE3 hash.
func PayloadForPointer(p Pointer) PointerPayload {
	version := PointerV1
	if p.HasIrohHash {
		version = PointerV2
	}
	return PointerPayload{
		Version:      version,
		Route:        p.Route,
		CID:          p.CID,
		BurnDeadline: p.BurnDeadline,
		IrohHash:     p.IrohHash,
		RouteOmitted: p.RouteOmitted,
	}
}
