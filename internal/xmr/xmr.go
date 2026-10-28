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
// http://127.0.0.1:18083/json_rpc in this deployment — 18082 is monerod's own RPC
// port here, so the wallet takes the next one), which holds the keys and signs:
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

// ErrProofRejected marks a check_tx_proof call the WALLET answered with a
// rejection: an address that does not decode, a signature that is not a
// signature, a proof for a different transaction. That is a verdict about the
// proof. A transport failure is not, and callers must not collapse the two —
// "could not ask" is not "no", and a receipt checked against an unreachable
// wallet has been checked by nobody.
var ErrProofRejected = errors.New("xmr: the wallet rejected this transaction proof")

// Backend implements chain.Chain over the Monero wallet RPC.
type Backend struct {
	rpc    string
	http   *http.Client
	daemon string // optional: node RPC for height when wallet can't
}

// NewBackend builds an XMR backend. rpcURL is the wallet RPC endpoint
// (http://127.0.0.1:18083/json_rpc). login is optional "user:pass" for Digest
// auth (leave empty if the wallet RPC runs with no --rpc-login). Digest is not a
// preference: a real wallet answers a valid credential sent as Basic with 401.
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

// rpcError is the wallet's own error answer, as opposed to a transport failure.
// The distinction is what lets a caller treat "the wallet says no" as a verdict
// while treating an unreachable wallet as a failure to check anything.
type rpcError struct {
	method string
	msg    string
}

func (e *rpcError) Error() string { return "xmr rpc " + e.method + ": " + e.msg }

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
	const maxBody = 64 << 10 // 64 KiB RPC response cap (guards oversized wallet reply)
	lr := io.LimitReader(resp.Body, int64(maxBody)+1)
	raw, err := io.ReadAll(lr)
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
		return &rpcError{method: method, msg: r.Error.Message}
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

// TxProofCheck is what check_tx_proof answers (docs/MONERO_SETTLEMENT.md §4):
// whether the proof verifies, what it says was received at that address, and how
// deeply confirmed the payment is.
type TxProofCheck struct {
	Good          bool   `json:"good"`
	Received      uint64 `json:"received"`
	InPool        bool   `json:"in_pool"`
	Confirmations uint64 `json:"confirmations"`
}

// CheckTxProof asks a wallet to verify a get_tx_proof signature: that this txid
// paid this address, and that the message was the one signed. The wallet must
// hold the payment — that is the whole shape of the thing: no explorer, no chain
// client of spore's, just the wallet that received the money.
//
// A wallet that answers with an error returns ErrProofRejected, so a caller can
// call that a failed proof; anything else (an unreachable endpoint, a proxy, a
// timeout) comes back as-is and must be treated as a failure to check.
func CheckTxProof(ctx context.Context, rpcURL, login, txid, address, message, signature string) (*TxProofCheck, error) {
	b := NewBackend(rpcURL, login)
	var out TxProofCheck
	err := b.call(ctx, "check_tx_proof", map[string]any{
		"txid":      txid,
		"address":   address,
		"message":   message,
		"signature": signature,
	}, &out)
	if err != nil {
		var re *rpcError
		if errors.As(err, &re) {
			return nil, fmt.Errorf("%w: %s", ErrProofRejected, re.msg)
		}
		return nil, err
	}
	return &out, nil
}

// GetTxProof asks the wallet that holds a payment to sign the chain's own
// statement about it: that this txid paid this address, and that message is the
// text signed. The pair (signature, message) is exactly what CheckTxProof
// verifies later, so the message belongs to the caller — and a caller that binds
// it to anything mutable has produced a proof of nothing in particular.
//
// A wallet that refuses (a txid it does not hold, an address that is not its
// own) comes back as ErrProofRejected; a wallet that cannot be reached does not,
// because the two answers mean different things to whoever is deciding whether a
// payment is evidenced.
func GetTxProof(ctx context.Context, rpcURL, login, txid, address, message string) (string, error) {
	b := NewBackend(rpcURL, login)
	var out struct {
		Signature string `json:"signature"`
	}
	err := b.call(ctx, "get_tx_proof", map[string]any{
		"txid":    txid,
		"address": address,
		"message": message,
	}, &out)
	if err != nil {
		var re *rpcError
		if errors.As(err, &re) {
			return "", fmt.Errorf("%w: %s", ErrProofRejected, re.msg)
		}
		return "", err
	}
	// A proof with no signature is not a proof, and an empty string here would
	// travel into a record that looks evidenced and verifies against nothing.
	if out.Signature == "" {
		return "", errors.New("xmr: the wallet answered get_tx_proof with no signature")
	}
	return out.Signature, nil
}
