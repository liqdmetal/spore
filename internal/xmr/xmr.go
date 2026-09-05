// Package xmr implements the chain.Chain backend for Monero (XMR).
//
// Honest model (see VISION §3): Monero has NO on-chain channel that can carry
// a spore payload. Its only free-form per-tx field exposed by the standard
// wallet RPC is an 8-byte payment ID (modern Monero rejects 32-byte ids).
// So unlike DERO (encrypted payload field) or EVM (calldata), an XMR tx cannot
// transport a whisper (~83 B) or even a long-body pointer (67 B).
//
// What Monero genuinely gives m³:
//   - identity  — the recipient's XMR (sub)address is who they are on-chain;
//   - a signal rail — a dust transfer whose 8-byte payment id is a KNOCK,
//     not content;
//   - a payment rail — dust/postage is natively Monero's own coin.
//
// The actual message content rides the off-chain rendezvous (chain-agnostic,
// already in the core), keyed by a reference. The XMR tx's 8-byte payment id
// carries that reference as a short signal: when it fits, the canonical
// payload is embedded directly; the rendezvous handshake (relay fabric, build
// step 3) carries the full body off-chain.
//
// Backend methods hit the Monero wallet RPC (v2, JSON-RPC at
// http://127.0.0.1:18082/json_rpc), which holds the keys and signs:
//
//	get_height, get_address, transfer, get_transfers.
package xmr

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/icholy/digest"

	"github.com/liqdmetal/spore/internal/chain"
)

// MaxSignal is the 8-byte payload cap (Monero payment id).
const MaxSignal = 8

// ErrPayloadTooBig is returned when a payload cannot ride an XMR tx (it does
// not fit the 8-byte payment id). The caller should use the rendezvous path
// (off-chain body keyed by this signal) — see package doc.
var ErrPayloadTooBig = errors.New("xmr: payload does not fit 8-byte payment id; ride off-chain rendezvous")

// Backend implements chain.Chain over the Monero wallet RPC.
type Backend struct {
	rpc    string
	http   *http.Client
	daemon string // optional: node RPC for height when wallet can't
}

// NewBackend builds an XMR backend. rpcURL is the wallet RPC endpoint
// (http://127.0.0.1:18082/json_rpc). login is optional "user:pass" for Digest
// auth (leave empty if the wallet RPC runs with no --rpc-login).
func NewBackend(rpcURL, login string) *Backend {
	rt := http.DefaultTransport
	if u, p, ok := strings.Cut(login, ":"); ok {
		rt = &digest.Transport{Username: u, Password: p}
	}
	return &Backend{rpc: rpcURL, http: &http.Client{Transport: rt}}
}

// Name implements chain.Chain.
func (b *Backend) Name() string { return "xmr" }

type rpcReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

func (b *Backend) call(ctx context.Context, method string, params, out interface{}) error {
	body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.rpc, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Monero wallet RPC returns top-level {id, jsonrpc, result:{...}} or {error:{code,message}}.
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.Error != nil {
		return fmt.Errorf("xmr rpc %s: %s", method, r.Error.Message)
	}
	if out != nil && len(r.Result) > 0 && string(r.Result) != "null" {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// getAddress queries the wallet's primary address.
func (b *Backend) getAddress(ctx context.Context) (string, error) {
	var out struct {
		Address string `json:"address"`
	}
	if err := b.call(ctx, "get_address", map[string]interface{}{}, &out); err != nil {
		return "", err
	}
	return out.Address, nil
}

// Address implements chain.Chain (wallet's primary address).
func (b *Backend) Address(ctx context.Context) (string, error) { return b.getAddress(ctx) }

// Height implements chain.Chain via the wallet's synced height.
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	var out struct {
		Height uint64 `json:"height"`
	}
	if err := b.call(ctx, "get_height", map[string]interface{}{}, &out); err != nil {
		return 0, err
	}
	return out.Height, nil
}

// PostPayload implements chain.Chain. amountHint is the dust/postage in
// atomic units (default 1). It posts a transfer to recipientAddr whose 8-byte
// payment id carries the payload when it fits (≤8 B, i.e. a short signal/ref);
// otherwise it returns ErrPayloadTooBig.
func (b *Backend) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	if len(p) > MaxSignal {
		return chain.PostResult{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooBig, len(p))
	}
	amt := amountHint
	if amt == 0 {
		amt = 1
	}
	paymentID := hex.EncodeToString(p) // 8 bytes -> 16 hex chars (valid 8-byte pid)
	var out struct {
		TxHash string `json:"tx_hash"`
	}
	err := b.call(ctx, "transfer", map[string]interface{}{
		"destinations": []map[string]interface{}{
			{"address": recipientAddr, "amount": amt},
		},
		"payment_id":   paymentID,
		"get_tx_key":   true,
		"unlock_time":  0,
		"priority":     0,
		"ring_size":    16,
		"get_tx_hex":   false,
		"do_not_relay": false,
	}, &out)
	if err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: out.TxHash}, nil
}

// getTransfers returns incoming transfers (optionally from minHeight).
func (b *Backend) getTransfers(ctx context.Context, in bool, minHeight uint64) ([]xmrIncoming, error) {
	var out struct {
		In      []xmrIncoming `json:"in"`
		Out     []xmrIncoming `json:"out"`
		Pending []xmrIncoming `json:"pending"`
	}
	err := b.call(ctx, "get_transfers", map[string]interface{}{
		"in":               in,
		"out":              !in,
		"pending":          true,
		"failed":           false,
		"pool":             true,
		"min_height":       minHeight,
		"filter_by_height": true,
	}, &out)
	if err != nil {
		return nil, err
	}
	if in {
		return out.In, nil
	}
	return out.Pending, nil
}

type xmrIncoming struct {
	TxID      string `json:"txid"`
	Height    uint64 `json:"height"`
	PaymentID string `json:"payment_id"`
	Address   string `json:"address"`
	Amount    uint64 `json:"amount"`
	Note      string `json:"note"`
}

// ListIncoming implements chain.Chain. It returns incoming transfers whose
// payment id decodes to a spore signal (i.e. a payload ≤8 B). Transfers
// without a payload-bearing payment id are not mycelium and are skipped.
func (b *Backend) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	list, err := b.getTransfers(ctx, true, minHeight)
	if err != nil {
		return nil, err
	}
	var out []chain.Incoming
	for _, t := range list {
		if t.PaymentID == "" {
			continue
		}
		pid, err := hex.DecodeString(t.PaymentID)
		if err != nil || len(pid) == 0 || len(pid) > MaxSignal {
			continue
		}
		// Only surface payment ids that look like our canonical signal
		// (first byte is a known kind). Otherwise skip plain payments.
		if !validKind(pid[0]) {
			continue
		}
		out = append(out, chain.Incoming{
			TxID:       t.TxID,
			TopoHeight: int64(t.Height),
			Sender:     t.Address, // our own subaddress that received; sender not exposed by wallet rpc
			Payload:    chain.Payload(pid),
		})
	}
	return out, nil
}

func validKind(b byte) bool {
	// kinds mirror whisper: 0x01 text, 0x02 pointer.
	return b == 0x01 || b == 0x02
}
