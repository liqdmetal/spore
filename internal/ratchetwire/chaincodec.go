package ratchetwire

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/dero"
)

// ChainPayloadCodec exposes the same opaque E2 pointer on every chain. DERO
// gets typed arguments; EVM/Solana carry canonical bytes; XMR carries only the
// short signal and must use the peer/mailbox lookup separately.
type ChainPayloadCodec interface {
	EncodePointer(PointerPayload) (chain.Payload, error)
	DecodePointer(chain.Payload) (PointerPayload, bool)
}

// ErrCarrierUnsupported is returned when a chain cannot carry the E2 pointer
// itself. The caller must use the off-chain rendezvous signal, never a legacy
// one-shot fallback.
var ErrCarrierUnsupported = fmt.Errorf("ratchetwire: carrier cannot hold E2 pointer")

// XMRChainCodec keeps Monero honest: the current 8-byte payment-id seam
// cannot carry PointerPayload (74 bytes). It deliberately refuses to encode so
// callers select a separate authenticated peer/mailbox rendezvous signal.
type XMRChainCodec struct{}

func (XMRChainCodec) EncodePointer(PointerPayload) (chain.Payload, error) {
	return nil, ErrCarrierUnsupported
}

func (XMRChainCodec) DecodePointer(chain.Payload) (PointerPayload, bool) {
	return PointerPayload{}, false
}

type CanonicalChainCodec struct{}

func (CanonicalChainCodec) EncodePointer(p PointerPayload) (chain.Payload, error) {
	if (p.Version != PointerV1 && p.Version != PointerV2) || p.BurnDeadline == 0 || p.RouteOmitted ||
		(p.Version == PointerV1 && p.IrohHash != ([32]byte{})) {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	wire := p.MarshalBinary()
	if wire == nil {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	return wire, nil
}

func (CanonicalChainCodec) DecodePointer(p chain.Payload) (PointerPayload, bool) {
	got, err := ParsePointerPayload(p)
	return got, err == nil
}

type DeroChainCodec struct{}

// DERO permanently retains payloads. V1 carries R/C/D. V2 uses the distinct
// W=0xE221 marker and substitutes I for R, so V1 readers fail closed and the
// portable BLAKE3 locator fits the same 111-byte budget. The receiver recomputes
// the omitted route from the fetched frame after SHA-256 CID verification.
func (DeroChainCodec) EncodePointer(p PointerPayload) (chain.Payload, error) {
	if (p.Version != PointerV1 && p.Version != PointerV2) || p.BurnDeadline == 0 ||
		(p.Version == PointerV1 && (p.IrohHash != ([32]byte{}) || p.RouteOmitted)) ||
		(p.Version == PointerV2 && p.RouteOmitted && p.Route != ([32]byte{})) {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	kind := uint64(0xE220)
	args := anchor.Arguments{{Name: "W", DataType: anchor.DataUint64, Value: kind}}
	if p.Version == PointerV1 {
		args = append(args, anchor.Argument{Name: "R", DataType: anchor.DataHash, Value: hex.EncodeToString(p.Route[:])})
	} else {
		kind = 0xE221
		args[0].Value = kind
		args = append(args, anchor.Argument{Name: "I", DataType: anchor.DataHash, Value: hex.EncodeToString(p.IrohHash[:])})
	}
	args = append(args,
		anchor.Argument{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(p.CID[:])},
		anchor.Argument{Name: "D", DataType: anchor.DataUint64, Value: p.BurnDeadline},
	)
	packed, err := dero.PackArguments(args)
	if err != nil {
		return nil, err
	}
	if len(packed) > dero.Payload0Limit {
		return nil, fmt.Errorf("ratchetwire: DERO pointer is %d bytes, payload-0 limit is %d", len(packed), dero.Payload0Limit)
	}
	return dero.ArgsToPayload(args)
}

func (DeroChainCodec) DecodePointer(p chain.Payload) (PointerPayload, bool) {
	args, err := dero.PayloadToArgs(p)
	if err != nil {
		return PointerPayload{}, false
	}
	var out PointerPayload
	var kind, deadline uint64
	var haveW, haveR, haveC, haveD, seenI, haveI bool
	for _, a := range args {
		switch a.Name + a.DataType {
		case "W" + anchor.DataUint64:
			kind, err = asUint(a.Value)
			haveW = err == nil
		case "R" + anchor.DataHash:
			out.Route, err = asHash(a.Value)
			haveR = err == nil
		case "C" + anchor.DataHash:
			out.CID, err = asHash(a.Value)
			haveC = err == nil
		case "D" + anchor.DataUint64:
			deadline, err = asUint(a.Value)
			haveD = err == nil
		case "I" + anchor.DataHash:
			seenI = true
			out.IrohHash, err = asHash(a.Value)
			haveI = err == nil
		}
	}
	if !haveW || !haveC || !haveD || deadline == 0 {
		return PointerPayload{}, false
	}
	out.BurnDeadline = deadline
	switch kind {
	case 0xE220:
		if !haveR || seenI {
			return PointerPayload{}, false
		}
		out.Version = PointerV1
	case 0xE221:
		if haveR || !seenI || !haveI {
			return PointerPayload{}, false
		}
		out.Version = PointerV2
		out.RouteOmitted = true
	default:
		return PointerPayload{}, false
	}
	return out, true
}

func asUint(v interface{}) (uint64, error) {
	switch x := v.(type) {
	case uint64:
		return x, nil
	case int64:
		if x < 0 {
			return 0, fmt.Errorf("negative uint")
		}
		return uint64(x), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 || x >= 18446744073709551616.0 || x != math.Trunc(x) {
			return 0, fmt.Errorf("invalid uint")
		}
		return uint64(x), nil
	case string:
		n, err := strconv.ParseUint(x, 10, 64)
		return n, err
	default:
		return 0, fmt.Errorf("unsupported uint %T", v)
	}
}

func asHash(v interface{}) ([32]byte, error) {
	var out [32]byte
	switch x := v.(type) {
	case string:
		b, err := hex.DecodeString(x)
		if err != nil || len(b) != 32 {
			return out, fmt.Errorf("bad hash")
		}
		copy(out[:], b)
	case []byte:
		if len(x) != 32 {
			return out, fmt.Errorf("bad hash")
		}
		copy(out[:], x)
	case [32]byte:
		out = x
	default:
		return out, fmt.Errorf("unsupported hash %T", v)
	}
	return out, nil
}

// JSONCodec is useful for EVM/Solana transports that preserve arbitrary bytes
// as a JSON payload field in tests and mailbox APIs.
type JSONCodec struct{}

func (JSONCodec) EncodePointer(p PointerPayload) (chain.Payload, error) {
	if (p.Version != PointerV1 && p.Version != PointerV2) || p.BurnDeadline == 0 || p.RouteOmitted ||
		(p.Version == PointerV1 && p.IrohHash != ([32]byte{})) {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	irohHash := ""
	if p.Version == PointerV2 {
		irohHash = hex.EncodeToString(p.IrohHash[:])
	}
	return json.Marshal(struct {
		V byte   `json:"v"`
		R string `json:"r"`
		C string `json:"c"`
		D uint64 `json:"d"`
		I string `json:"i,omitempty"`
	}{p.Version, hex.EncodeToString(p.Route[:]), hex.EncodeToString(p.CID[:]), p.BurnDeadline, irohHash})
}

func (JSONCodec) DecodePointer(p chain.Payload) (PointerPayload, bool) {
	var x struct {
		V byte   `json:"v"`
		R string `json:"r"`
		C string `json:"c"`
		D uint64 `json:"d"`
		I string `json:"i"`
	}
	if json.Unmarshal(p, &x) != nil || x.D == 0 {
		return PointerPayload{}, false
	}
	var out PointerPayload
	r, er := hex.DecodeString(x.R)
	c, ec := hex.DecodeString(x.C)
	if er != nil || ec != nil || len(r) != 32 || len(c) != 32 {
		return PointerPayload{}, false
	}
	copy(out.Route[:], r)
	copy(out.CID[:], c)
	out.BurnDeadline = x.D
	switch x.V {
	case PointerV1:
		if x.I != "" {
			return PointerPayload{}, false
		}
	case PointerV2:
		irohHash, err := hex.DecodeString(x.I)
		if err != nil || len(irohHash) != 32 {
			return PointerPayload{}, false
		}
		copy(out.IrohHash[:], irohHash)
	default:
		return PointerPayload{}, false
	}
	out.Version = x.V
	return out, true
}
