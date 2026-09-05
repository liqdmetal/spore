// Package dero is the seam to the DERO chain: a wallet-RPC client that posts
// anchors inside a transaction's encrypted message field (the payload_rpc
// arguments) and scans incoming transactions for anchors addressed to us.
//
// It talks plain JSON-RPC 2.0 over HTTP to the wallet's /json_rpc endpoint
// (default 127.0.0.1:20209, basic auth via --rpc-login). No derohe import is
// needed — this package speaks the wire format directly.
//
// Verified against derohe R153 source:
//   - the on-chain message field is transaction.PAYLOAD0_LIMIT = 111 bytes of
//     CBOR-encoded rpc.Arguments (a name+datatype -> value map);
//   - crypto.Hash values cross JSON as 64-char hex strings, uint64 as numbers;
//   - wallet RPC method names are bare: "transfer", "get_transfers",
//     "getaddress", "getheight", "getbalance" (handler.Map keys).
package dero

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/liqdmetal/compost/internal/anchor"
)

// Client is a wallet-RPC client.
type Client struct {
	url  string
	user string
	pass string
	http *http.Client
}

// NewClient builds a client for a wallet RPC endpoint. url is the full
// /json_rpc endpoint (e.g. "http://127.0.0.1:20209/json_rpc"). user/pass
// mirror the wallet's --rpc-login; leave empty if the wallet runs without one.
func NewClient(url, user, pass string) *Client {
	return &Client{
		url:  url,
		user: user,
		pass: pass,
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// rpcRequest / rpcResponse are the jrpc2 envelope.
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      string      `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// call performs one JSON-RPC request and decodes result into out (if non-nil).
func (c *Client) call(ctx context.Context, method string, params, out interface{}) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: "0", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("dero: wallet RPC auth failed (401)")
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("dero: bad response: %w", err)
	}
	if r.Error != nil {
		return fmt.Errorf("dero: rpc error %d: %s", r.Error.Code, r.Error.Message)
	}
	if out != nil && len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return fmt.Errorf("dero: decode result: %w", err)
		}
	}
	return nil
}

// Transfer is one destination+amount+payload entry (wire-identical to
// derohe rpc.Transfer).
type Transfer struct {
	Destination string           `json:"destination"`
	Amount      uint64           `json:"amount"`
	PayloadRPC  anchor.Arguments `json:"payload_rpc,omitempty"`
}

// TransferParams mirrors derohe rpc.Transfer_Params (subset we use).
type TransferParams struct {
	Transfers []Transfer `json:"transfers"`
	Ringsize  uint64     `json:"ringsize"`
}

// TransferResult mirrors the {txid} result.
type TransferResult struct {
	TXID string `json:"txid,omitempty"`
}

// PostAnchor embeds the anchor as the message payload of a minimum-postage
// transfer to recipientAddr and returns the txid.
//
// Amount MUST be non-zero: derohe's wallet scan (daemon_communication.go)
// classifies a transfer whose recipient balance is unchanged
// (previous_balance == changed_balance) as a ring-member decoy and skips it
// entirely — a 0-amount anchor never appears in get_transfers. Minimum
// postage is 1 atomic unit (0.00001 DERO), which flips the recipient's
// balance enough to trigger the incoming-detection path.
//
// Ringsize: a plain minimum-postage message transfer does not use SIGNER(),
// so any valid ringsize works; 2 is the minimum and cheapest, larger
// obscures the sender better. Default to 2 for message-only traffic.
func (c *Client) PostAnchor(ctx context.Context, recipientAddr string, a *anchor.Anchor, ringsize uint64) (string, error) {
	return c.PostPayload(ctx, recipientAddr, a.ToArguments(), ringsize)
}

// PostPayload posts a minimum-postage transfer carrying arbitrary typed
// payload Arguments to recipientAddr and returns the txid. It is the shared
// primitive under PostAnchor and the whisper transport. See PostAnchor for the
// non-zero-postage rule.
func (c *Client) PostPayload(ctx context.Context, recipientAddr string, payload anchor.Arguments, ringsize uint64) (string, error) {
	if ringsize == 0 {
		ringsize = 2
	}
	params := TransferParams{
		Transfers: []Transfer{{
			Destination: recipientAddr,
			Amount:      1, // minimum postage; must be > 0 or the recipient never sees it
			PayloadRPC:  payload,
		}},
		Ringsize: ringsize,
	}
	var result TransferResult
	if err := c.call(ctx, "transfer", params, &result); err != nil {
		return "", err
	}
	if result.TXID == "" {
		return "", errors.New("dero: transfer returned empty txid")
	}
	return result.TXID, nil
}

// GetTransfersParams mirrors the subset of Get_Transfers_Params we use.
type GetTransfersParams struct {
	In        bool   `json:"in"`
	MinHeight uint64 `json:"min_height,omitempty"`
}

// Entry is the subset of rpc.Entry we read.
type Entry struct {
	TopoHeight int64            `json:"topoheight"`
	Incoming   bool             `json:"incoming"`
	TXID       string           `json:"txid"`
	Sender     string           `json:"sender"`
	PayloadRPC anchor.Arguments `json:"payload_rpc"`
	// Data is the raw payload bytes as base64 (wallets like Engram that fail
	// the CBOR parse of padded payloads still return this).
	Data []byte `json:"data"`
	// PayloadError is set when the wallet could not decode payload_rpc.
	PayloadError string `json:"payloaderror"`
}

// GetTransfersResult mirrors {entries}.
type GetTransfersResult struct {
	Entries []Entry `json:"entries,omitempty"`
}

// GetTransfers fetches incoming (or outgoing) transfer entries.
func (c *Client) GetTransfers(ctx context.Context, params GetTransfersParams) ([]Entry, error) {
	var result GetTransfersResult
	if err := c.call(ctx, "get_transfers", params, &result); err != nil {
		return nil, err
	}
	return result.Entries, nil
}

// GetAddress returns the wallet's DERO address.
func (c *Client) GetAddress(ctx context.Context) (string, error) {
	var out struct {
		Address string `json:"address"`
	}
	if err := c.call(ctx, "getaddress", nil, &out); err != nil {
		return "", err
	}
	return out.Address, nil
}

// GetHeight returns the wallet's current topoheight.
func (c *Client) GetHeight(ctx context.Context) (uint64, error) {
	var out struct {
		Height uint64 `json:"height"`
	}
	if err := c.call(ctx, "getheight", nil, &out); err != nil {
		return 0, err
	}
	return out.Height, nil
}

// AnchorEvent is one anchor observed on-chain addressed to us.
type AnchorEvent struct {
	TXID       string
	TopoHeight int64
	Anchor     *anchor.Anchor
}

// IncomingAnchors polls get_transfers (in:true, min_height) and returns
// events whose payload parses as a compost anchor. Non-anchor transfers are
// skipped silently. Delivered txids are tracked so an anchor is emitted
// exactly once (the wallet's min_height filter is >=, so a cursor at the
// anchor's own height would otherwise re-match it every poll). Polls every
// interval until ctx is cancelled.
func (c *Client) IncomingAnchors(ctx context.Context, minHeight uint64, interval time.Duration) (<-chan AnchorEvent, <-chan error) {
	ch := make(chan AnchorEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errc)
		cursor := minHeight
		seen := map[string]bool{}
		for {
			entries, err := c.GetTransfers(ctx, GetTransfersParams{In: true, MinHeight: cursor})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errc <- err
				return
			}
			for _, e := range entries {
				if seen[e.TXID] {
					continue
				}
				if e.TopoHeight > int64(cursor) {
					cursor = uint64(e.TopoHeight)
				}
				a, err := anchor.FromArguments(e.PayloadRPC)
				if err != nil {
					continue // not a compost anchor (or malformed) — skip
				}
				seen[e.TXID] = true
				select {
				case ch <- AnchorEvent{TXID: e.TXID, TopoHeight: e.TopoHeight, Anchor: a}:
				case <-ctx.Done():
					return
				}
			}
			select {
			case <-time.After(interval):
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, errc
}
