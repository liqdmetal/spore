package ratchetwire

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	if p.Version != PointerV1 || p.BurnDeadline == 0 {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	return p.MarshalBinary(), nil
}

func (CanonicalChainCodec) DecodePointer(p chain.Payload) (PointerPayload, bool) {
	got, err := ParsePointerPayload(p)
	return got, err == nil
}

type DeroChainCodec struct{}

// DERO's native transaction payload is permanently retained, so this codec
// carries only the opaque E2 route/CID/deadline pointer and never plaintext.
func (DeroChainCodec) EncodePointer(p PointerPayload) (chain.Payload, error) {
	if p.Version != PointerV1 || p.BurnDeadline == 0 {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	args := anchor.Arguments{
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
		{Name: "R", DataType: anchor.DataHash, Value: hex.EncodeToString(p.Route[:])},
		{Name: "C", DataType: anchor.DataHash, Value: hex.EncodeToString(p.CID[:])},
		{Name: "D", DataType: anchor.DataUint64, Value: p.BurnDeadline},
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
	var haveW, haveR, haveC, haveD bool
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
		}
	}
	out.Version = PointerV1
	out.BurnDeadline = deadline
	return out, haveW && kind == 0xE220 && haveR && haveC && haveD && deadline != 0
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
		if x < 0 || x >= 18446744073709551616.0 || x != float64(uint64(x)) {
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
	if p.Version != PointerV1 || p.BurnDeadline == 0 {
		return nil, fmt.Errorf("ratchetwire: invalid pointer")
	}
	return json.Marshal(struct {
		V byte   `json:"v"`
		R string `json:"r"`
		C string `json:"c"`
		D uint64 `json:"d"`
	}{p.Version, hex.EncodeToString(p.Route[:]), hex.EncodeToString(p.CID[:]), p.BurnDeadline})
}

func (JSONCodec) DecodePointer(p chain.Payload) (PointerPayload, bool) {
	var x struct {
		V byte   `json:"v"`
		R string `json:"r"`
		C string `json:"c"`
		D uint64 `json:"d"`
	}
	if json.Unmarshal(p, &x) != nil || x.V != PointerV1 || x.D == 0 {
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
	out.Version = x.V
	out.BurnDeadline = x.D
	return out, true
}
