// Package dero implements the chain.Chain backend for the DERO network.
package dero

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/chain"
)

type Backend struct{ client *Client }

func NewBackend(client *Client) *Backend                       { return &Backend{client: client} }
func (b *Backend) Name() string                                { return "dero" }
func (b *Backend) Address(ctx context.Context) (string, error) { return b.client.GetAddress(ctx) }
func (b *Backend) Height(ctx context.Context) (uint64, error)  { return b.client.GetHeight(ctx) }

func (b *Backend) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	args, err := PayloadToArgs(p)
	if err != nil {
		return chain.PostResult{}, err
	}
	if amountHint == 0 {
		amountHint = 1
	}
	txid, err := b.client.PostPayloadAmount(ctx, recipientAddr, args, amountHint)
	if err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: txid}, nil
}

// EntryPayload returns the canonical typed payload from payload_rpc, or
// strictly decodes R153's padded raw data when the wallet did not populate it.
func EntryPayload(e Entry) (chain.Payload, error) {
	if len(e.PayloadRPC) > 0 {
		raw, err := ArgsToPayload(e.PayloadRPC)
		if err == nil {
			if _, decodeErr := PayloadToArgs(raw); decodeErr == nil {
				return raw, nil
			}
		}
		if len(e.Data) == 0 {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("dero: transfer %s has invalid payload_rpc", e.TXID)
		}
	}
	if len(e.Data) > 0 {
		args, err := RawPayloadToArgs(e.Data)
		if err != nil {
			return nil, err
		}
		return ArgsToPayload(args)
	}
	return nil, fmt.Errorf("dero: transfer %s has no payload", e.TXID)
}

func (b *Backend) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	entries, err := b.client.GetTransfers(ctx, GetTransfersParams{In: true, MinHeight: minHeight})
	if err != nil {
		return nil, err
	}
	out := make([]chain.Incoming, 0, len(entries))
	for _, e := range entries {
		if e.TXID == "" {
			continue
		}
		inc := chain.Incoming{TxID: e.TXID, TopoHeight: e.TopoHeight, ScanHeight: e.Height, Sender: e.Sender, Amount: e.Amount}
		if raw, err := EntryPayload(e); err == nil {
			inc.Payload = raw
		}
		out = append(out, inc)
	}
	return out, nil
}

type argEnvelope struct {
	Args []argJSON `json:"a"`
}
type argJSON struct {
	N string          `json:"n"`
	T string          `json:"t"`
	V json.RawMessage `json:"v"`
}

const maxPayloadArgs = 32
const maxPayloadName = 64
const maxPayloadValue = 2048

func PayloadToArgs(p chain.Payload) (anchor.Arguments, error) {
	if len(p) == 0 || len(p) > Payload0Limit*64 {
		return nil, fmt.Errorf("dero: payload envelope size %d out of range", len(p))
	}
	var env argEnvelope
	dec := json.NewDecoder(strings.NewReader(string(p)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("dero: bad payload envelope: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("dero: trailing payload envelope data")
	}
	if len(env.Args) == 0 || len(env.Args) > maxPayloadArgs {
		return nil, fmt.Errorf("dero: payload argument count out of range")
	}
	out := make(anchor.Arguments, 0, len(env.Args))
	seen := make(map[string]struct{}, len(env.Args))
	for _, a := range env.Args {
		if len(a.N) == 0 || len(a.N) > maxPayloadName || strings.TrimSpace(a.N) != a.N {
			return nil, fmt.Errorf("dero: invalid argument name")
		}
		if _, ok := seen[a.N+a.T]; ok {
			return nil, fmt.Errorf("dero: duplicate argument %q", a.N+a.T)
		}
		seen[a.N+a.T] = struct{}{}
		if !validDataType(a.T) {
			return nil, fmt.Errorf("dero: unsupported argument datatype %q", a.T)
		}
		if len(a.V) > maxPayloadValue {
			return nil, fmt.Errorf("dero: argument %q value too large", a.N)
		}
		arg := anchor.Argument{Name: a.N, DataType: a.T}
		var value string
		if err := json.Unmarshal(a.V, &value); err != nil {
			return nil, fmt.Errorf("dero: argument %q value must be a JSON string: %w", a.N, err)
		}
		if a.T == anchor.DataUint64 {
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("dero: bad uint in payload: %w", err)
			}
			arg.Value = n
		} else {
			arg.Value = value
		}
		out = append(out, arg)
	}
	return out, nil
}

func ArgsToPayload(args anchor.Arguments) (chain.Payload, error) {
	if len(args) == 0 || len(args) > maxPayloadArgs {
		return nil, fmt.Errorf("dero: payload argument count out of range")
	}
	env := argEnvelope{Args: make([]argJSON, 0, len(args))}
	seen := make(map[string]struct{}, len(args))
	for _, a := range args {
		if len(a.Name) == 0 || len(a.Name) > maxPayloadName || strings.TrimSpace(a.Name) != a.Name {
			return nil, fmt.Errorf("dero: invalid argument name")
		}
		if !validDataType(a.DataType) {
			return nil, fmt.Errorf("dero: unsupported argument datatype %q", a.DataType)
		}
		if _, ok := seen[a.Name+string(a.DataType)]; ok {
			return nil, fmt.Errorf("dero: duplicate argument %q", a.Name+string(a.DataType))
		}
		seen[a.Name+string(a.DataType)] = struct{}{}
		ja := argJSON{N: a.Name, T: string(a.DataType)}
		switch v := a.Value.(type) {
		case uint64:
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(v, 10)))
		case uint:
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case uint32:
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case int:
			if v < 0 {
				return nil, fmt.Errorf("dero: negative uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case int64:
			if v < 0 {
				return nil, fmt.Errorf("dero: negative uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case float64:
			if v < 0 || v >= 18446744073709551616.0 || v != float64(uint64(v)) {
				return nil, fmt.Errorf("dero: invalid uint argument %s", a.Name)
			}
			ja.T = anchor.DataUint64
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case string:
			ja.V = json.RawMessage(strconv.Quote(v))
		case []byte:
			ja.V = json.RawMessage(strconv.Quote(string(v)))
		default:
			return nil, fmt.Errorf("dero: unsupported argument value type %T", a.Value)
		}
		if len(ja.V) > maxPayloadValue {
			return nil, fmt.Errorf("dero: argument %q value too large", a.Name)
		}
		env.Args = append(env.Args, ja)
	}
	p, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(p) > Payload0Limit*64 {
		return nil, fmt.Errorf("dero: payload envelope too large")
	}
	return p, nil
}
