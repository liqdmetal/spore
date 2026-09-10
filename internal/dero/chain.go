// Package dero implements the chain.Chain backend for the DERO network.
// It wraps the low-level wallet-RPC client and maps DERO's typed CBOR
// rpc.Arguments payload onto the chain-agnostic chain.Payload. This is the
// seam a future EVM/Monero backend will mirror.
package dero

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/chain"
)

// Backend adapts *Client (low-level RPC) to chain.Chain.
type Backend struct {
	client *Client
}

// NewBackend builds a DERO chain.Chain from a wallet-RPC client.
func NewBackend(client *Client) *Backend { return &Backend{client: client} }

// Name implements chain.Chain.
func (b *Backend) Name() string { return "dero" }

// Address implements chain.Chain.
func (b *Backend) Address(ctx context.Context) (string, error) {
	return b.client.GetAddress(ctx)
}

// Height implements chain.Chain.
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	return b.client.GetHeight(ctx)
}

// PostPayload implements chain.Chain. amountHint is used as transfer value;
// DERO requires >=1 atomic unit or the recipient never sees the transfer.
func (b *Backend) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	args, err := PayloadToArgs(p)
	if err != nil {
		return chain.PostResult{}, err
	}
	amt := amountHint
	if amt == 0 {
		amt = 1 // minimum postage; 0 would make it a ring-member decoy
	}
	txid, err := b.client.PostPayloadAmount(ctx, recipientAddr, args, amt)
	if err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: txid}, nil
}

// ListIncoming implements chain.Chain. It surfaces raw payload bytes; the
// caller decodes with ParsePayload.
func (b *Backend) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	entries, err := b.client.GetTransfers(ctx, GetTransfersParams{In: true, MinHeight: minHeight})
	if err != nil {
		return nil, err
	}
	out := make([]chain.Incoming, 0, len(entries))
	for _, e := range entries {
		// R153's get_transfers min_height is a block-height cursor. Do not
		// advance the generic watcher by topoheight: DAG topoheight can jump
		// past later entries that share a block height.
		inc := chain.Incoming{TxID: e.TXID, TopoHeight: e.TopoHeight, ScanHeight: e.Height, Sender: e.Sender, Amount: e.Amount}
		if len(e.PayloadRPC) > 0 {
			if raw, err := ArgsToPayload(e.PayloadRPC); err == nil {
				inc.Payload = raw
			}
		}
		// Do not reinterpret Entry.Data as typed payload here. The generic
		// backend path is deliberately payload_rpc-only; raw padded data is
		// rejected unless the caller explicitly uses the legacy parser.
		out = append(out, inc)
	}
	return out, nil
}

// --- payload codec: chain.Payload <-> anchor.Arguments ---

// A chain.Payload stores the parsed argument list as JSON so the core can
// round-trip a whisper/pointer without importing DERO's CBOR. A future backend
// may use a different codec; the core only ever calls back into the same
// backend's ParsePayload, so the encoding is backend-private.
type argEnvelope struct {
	Args []argJSON `json:"a"`
}

type argJSON struct {
	N string `json:"n"`
	T string `json:"t"`
	V string `json:"v"`
}

// PayloadToArgs decodes a chain.Payload back to anchor.Arguments.
func PayloadToArgs(p chain.Payload) (anchor.Arguments, error) {
	var env argEnvelope
	if err := json.Unmarshal(p, &env); err != nil {
		return nil, fmt.Errorf("dero: bad payload envelope: %w", err)
	}
	if len(env.Args) == 0 {
		return nil, fmt.Errorf("dero: empty payload envelope")
	}
	out := make(anchor.Arguments, 0, len(env.Args))
	for _, a := range env.Args {
		if a.N == "" {
			return nil, fmt.Errorf("dero: empty argument name")
		}
		if !validDataType(a.T) {
			return nil, fmt.Errorf("dero: unsupported argument datatype %q", a.T)
		}
		arg := anchor.Argument{Name: a.N, DataType: a.T}
		if a.T == anchor.DataUint64 {
			n, err := strconv.ParseUint(strings.TrimSpace(a.V), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("dero: bad uint in payload: %w", err)
			}
			arg.Value = n
		} else {
			arg.Value = a.V
		}
		out = append(out, arg)
	}
	return out, nil
}

// ArgsToPayload encodes anchor.Arguments into a chain.Payload.
func ArgsToPayload(args anchor.Arguments) (chain.Payload, error) {
	env := argEnvelope{}
	for _, a := range args {
		ja := argJSON{N: a.Name, T: string(a.DataType)}
		switch v := a.Value.(type) {
		case uint64:
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(v, 10)
		case uint:
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(uint64(v), 10)
		case uint32:
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(uint64(v), 10)
		case int:
			if v < 0 {
				return nil, fmt.Errorf("dero: negative uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(uint64(v), 10)
		case int64:
			if v < 0 {
				return nil, fmt.Errorf("dero: negative uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(uint64(v), 10)
		case float64:
			if v < 0 || v >= 18446744073709551616.0 || v != float64(uint64(v)) {
				return nil, fmt.Errorf("dero: invalid uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = strconv.FormatUint(uint64(v), 10)
		case string:
			ja.V = v
		case []byte:
			ja.V = string(v)
		default:
			ja.V = fmt.Sprintf("%v", v)
		}
		env.Args = append(env.Args, ja)
	}
	return json.Marshal(env)
}
