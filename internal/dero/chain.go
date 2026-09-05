// Package dero implements the chain.Chain backend for the DERO network.
// It wraps the low-level wallet-RPC client and maps DERO's typed CBOR
// rpc.Arguments payload onto the chain-agnostic chain.Payload. This is the
// seam a future Obscura/Monero/EVM backend will mirror.
package dero

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/liqdmetal/mycelium/internal/anchor"
	"github.com/liqdmetal/mycelium/internal/chain"
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
		inc := chain.Incoming{TxID: e.TXID, TopoHeight: e.TopoHeight, Sender: e.Sender}
		if len(e.PayloadRPC) > 0 {
			if raw, err := ArgsToPayload(e.PayloadRPC); err == nil {
				inc.Payload = raw
			} else if len(e.Data) > 0 {
				inc.Payload = e.Data
			}
		} else if len(e.Data) > 0 {
			inc.Payload = e.Data
		}
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
	out := make(anchor.Arguments, 0, len(env.Args))
	for _, a := range env.Args {
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
