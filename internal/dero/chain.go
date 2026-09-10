// Package dero implements the chain.Chain backend for the DERO network.
package dero

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

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
		if !validDataType(a.T) {
			return nil, fmt.Errorf("dero: unsupported argument datatype %q", a.T)
		}
		if _, ok := seen[a.N+a.T]; ok {
			return nil, fmt.Errorf("dero: duplicate argument %q", a.N+a.T)
		}
		seen[a.N+a.T] = struct{}{}
		if len(a.V) > maxPayloadValue {
			return nil, fmt.Errorf("dero: argument %q value too large", a.N)
		}
		arg, err := decodeEnvelopeArgument(a)
		if err != nil {
			return nil, err
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
		ja := argJSON{N: a.Name, T: string(a.DataType)}
		switch v := a.Value.(type) {
		case uint64:
			if a.DataType != anchor.DataUint64 {
				return nil, fmt.Errorf("dero: %s requires datatype U for uint64", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(v, 10)))
		case uint:
			if a.DataType != anchor.DataUint64 {
				return nil, fmt.Errorf("dero: %s requires datatype U for uint", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case uint32:
			if a.DataType != anchor.DataUint64 {
				return nil, fmt.Errorf("dero: %s requires datatype U for uint32", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
		case int:
			if a.DataType != anchor.DataInt64 {
				return nil, fmt.Errorf("dero: %s requires datatype I for int", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatInt(int64(v), 10)))
		case int64:
			if a.DataType != anchor.DataInt64 {
				return nil, fmt.Errorf("dero: %s requires datatype I for int64", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(strconv.FormatInt(v, 10)))
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("dero: %s requires a finite numeric value", a.Name)
			}
			switch a.DataType {
			case anchor.DataUint64:
				if v < 0 || v >= 18446744073709551616.0 || v != math.Trunc(v) {
					return nil, fmt.Errorf("dero: %s requires an integral uint64", a.Name)
				}
				ja.V = json.RawMessage(strconv.Quote(strconv.FormatUint(uint64(v), 10)))
			case anchor.DataInt64:
				if v < -9223372036854775808.0 || v >= 9223372036854775808.0 || v != math.Trunc(v) {
					return nil, fmt.Errorf("dero: %s requires an integral int64", a.Name)
				}
				ja.V = json.RawMessage(strconv.Quote(strconv.FormatInt(int64(v), 10)))
			case anchor.DataFloat64:
				ja.V = json.RawMessage(strconv.Quote(strconv.FormatFloat(v, 'g', -1, 64)))
			default:
				return nil, fmt.Errorf("dero: %s float64 value incompatible with datatype %s", a.Name, a.DataType)
			}
		case string:
			switch a.DataType {
			case anchor.DataString:
				ja.V = json.RawMessage(strconv.Quote(v))
			case anchor.DataHash:
				if len(v) != 64 {
					return nil, fmt.Errorf("dero: %s must be 64-char hash hex", a.Name)
				}
				if _, err := hex.DecodeString(v); err != nil {
					return nil, fmt.Errorf("dero: %s must be 64-char hash hex", a.Name)
				}
				ja.V = json.RawMessage(strconv.Quote(v))
			case anchor.DataAddress:
				decoded, err := hex.DecodeString(v)
				if err != nil || len(decoded) != 33 {
					return nil, fmt.Errorf("dero: %s must be a 33-byte compressed address key", a.Name)
				}
				if err := validateCompressedPoint(decoded); err != nil {
					return nil, fmt.Errorf("dero: %s invalid compressed address key: %w", a.Name, err)
				}
				ja.V = json.RawMessage(strconv.Quote(v))
			case anchor.DataTime:
				if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
					return nil, fmt.Errorf("dero: %s must be RFC3339 time", a.Name)
				}
				ja.V = json.RawMessage(strconv.Quote(v))
			default:
				return nil, fmt.Errorf("dero: %s string value incompatible with datatype %s", a.Name, a.DataType)
			}
		case []byte:
			switch a.DataType {
			case anchor.DataHash:
				if len(v) != 32 {
					return nil, fmt.Errorf("dero: %s hash must be 32 bytes", a.Name)
				}
				ja.V = json.RawMessage(strconv.Quote(hex.EncodeToString(v)))
			case anchor.DataAddress:
				if len(v) != 33 {
					return nil, fmt.Errorf("dero: %s must be a 33-byte compressed address key", a.Name)
				}
				if err := validateCompressedPoint(v); err != nil {
					return nil, fmt.Errorf("dero: %s invalid compressed address key: %w", a.Name, err)
				}
				ja.V = json.RawMessage(strconv.Quote(hex.EncodeToString(v)))
			default:
				return nil, fmt.Errorf("dero: %s []byte value incompatible with datatype %s", a.Name, a.DataType)
			}
		case time.Time:
			if a.DataType != anchor.DataTime {
				return nil, fmt.Errorf("dero: %s requires datatype T for time.Time", a.Name)
			}
			ja.V = json.RawMessage(strconv.Quote(v.UTC().Format(time.RFC3339Nano)))
		default:
			return nil, fmt.Errorf("dero: unsupported argument value type %T", a.Value)
		}
		wireKey := ja.N + ja.T
		if _, ok := seen[wireKey]; ok {
			return nil, fmt.Errorf("dero: duplicate argument %q", wireKey)
		}
		seen[wireKey] = struct{}{}
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
