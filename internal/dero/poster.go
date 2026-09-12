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
	"net/url"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/anchor"
)

// Client is a wallet-RPC client.
type Client struct {
	url  string
	user string
	pass string
	http *http.Client
}

// NormalizeWalletRPCURL completes a wallet RPC endpoint that has no path.
//
// The wallet answers "DERO BLOCKCHAIN Hello world!" at its ROOT path, so a
// bare host:port parses as a JSON error ("invalid character 'D'") and reads as
// a network or serialization fault rather than a missing path segment. Every
// endpoint that accepts a wallet URL goes through here so that trap cannot
// reappear at a call site that forgot about it — which is exactly how it
// survived in one code path after being fixed in another.
//
// A URL that ALREADY carries a path is returned untouched: /json_rpc is the
// common case, but a wallet behind a reverse proxy may legitimately live at
// /wallet/json_rpc, and appending to that would break a working deployment.
func NormalizeWalletRPCURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s // not a URL we can reason about; pass through unchanged
	}
	if u.Path != "" && u.Path != "/" {
		return s
	}
	return strings.TrimSuffix(s, "/") + "/json_rpc"
}

// NewClient builds a client for a wallet RPC endpoint. url is the full
// /json_rpc endpoint (e.g. "http://127.0.0.1:20209/json_rpc"); a bare
// host:port is accepted and completed, see NormalizeWalletRPCURL. user/pass
// mirror the wallet's --rpc-login; leave empty if the wallet runs without one.
func NewClient(endpoint, user, pass string) *Client {
	return &Client{
		url:  NormalizeWalletRPCURL(endpoint),
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
	Params  interface{} `json:"params"`
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
// The wallet RPC rejects an ABSENT "params" key and an empty object ({}); it
// accepts params:null for parameterless methods. Pass nil for those.
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
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("dero: wallet RPC HTTP status %s", resp.Status)
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
// Ringsize: a plain minimum-postage message transfer does not use SIGNER().
// Spore's E2 backend constrains new message posts to ring size 8 or 16 and
// defaults to 16. This low-level client remains generic for non-Spore callers.
func (c *Client) PostAnchor(ctx context.Context, recipientAddr string, a *anchor.Anchor, ringsize uint64) (string, error) {
	return c.PostPayload(ctx, recipientAddr, a.ToArguments(), ringsize)
}

// PostPayload posts a minimum-postage transfer carrying arbitrary typed
// payload Arguments to recipientAddr and returns the txid. It is the shared
// primitive under PostAnchor and the whisper transport. See PostAnchor for the
// non-zero-postage rule. ringsize=0 means use the wallet's configured default;
// nonzero values must be a R153-valid power of two in [2,128]. Spore callers
// should use Backend.SetSporeRingSize instead of this generic primitive.
func (c *Client) PostPayload(ctx context.Context, recipientAddr string, payload anchor.Arguments, ringsize uint64) (string, error) {
	return c.PostPayloadAmountWithRing(ctx, recipientAddr, payload, 1, ringsize)
}

// PostPayloadAmount is PostPayload with an explicit transfer amount using
// ringsize 2, the minimum R153-valid ring size. Use
// PostPayloadAmountWithRing when a different valid ring size is required.
func (c *Client) PostPayloadAmount(ctx context.Context, recipientAddr string, payload anchor.Arguments, amount uint64) (string, error) {
	return c.PostPayloadAmountWithRing(ctx, recipientAddr, payload, amount, 2)
}

// PostPayloadAmountWithRing posts an explicit amount and ringsize.
func (c *Client) PostPayloadAmountWithRing(ctx context.Context, recipientAddr string, payload anchor.Arguments, amount, ringsize uint64) (string, error) {
	if _, err := ValidateAddress(recipientAddr); err != nil {
		return "", err
	}
	// Check the exact R153 CBOR representation locally. The wallet enforces
	// PAYLOAD0_LIMIT during transfer; failing before the RPC avoids a
	// deterministic send rejection after all caller-side validation passed.
	if _, err := PackArguments(payload); err != nil {
		return "", err
	}
	if amount == 0 {
		amount = 1 // DERO treats a 0-amount transfer as a ring-member decoy
	}
	if ringsize != 0 && (ringsize < 2 || ringsize > 128 || ringsize&(ringsize-1) != 0) {
		return "", fmt.Errorf("dero: ringsize must be 0 or a power of two in [2,128], got %d", ringsize)
	}
	params := TransferParams{
		Transfers: []Transfer{{
			Destination: recipientAddr,
			Amount:      amount,
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
//
// In/Out/Coinbase are the wallet's own filters and they INTERACT: from
// walletapi/wallet.go, an entry is returned only when one of the requested
// buckets matches it (coinbase, incoming, outgoing). Asking with every bucket
// false returns nothing at all, which is why the readiness probe below sets
// them all. Out is omitempty so existing callers that only set In keep sending
// exactly the bytes they sent before.
type GetTransfersParams struct {
	In        bool   `json:"in"`
	Out       bool   `json:"out,omitempty"`
	Coinbase  bool   `json:"coinbase,omitempty"`
	MinHeight uint64 `json:"min_height,omitempty"`
}

// Entry is the subset of rpc.Entry we read.
type Entry struct {
	// Height is the block height used by R153 get_transfers min_height.
	Height uint64 `json:"height"`
	// TransactionPos and Pos are R153's block and transaction coordinates.
	// They distinguish multiple transfer records sharing one TXID.
	TransactionPos int64            `json:"tpos"`
	Pos            int64            `json:"pos"`
	TopoHeight     int64            `json:"topoheight"`
	Incoming       bool             `json:"incoming"`
	TXID           string           `json:"txid"`
	Sender         string           `json:"sender"`
	Amount         uint64           `json:"amount"` // atomic DERO (1 DERO = 100000)
	PayloadRPC     anchor.Arguments `json:"payload_rpc"`
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

// GetTransferPayloads returns decoded payload bytes for every wallet-history
// entry carrying the requested transaction ID. Both incoming and outgoing
// buckets are queried because a posting wallet may index its own transfer as
// outgoing while the destination wallet indexes it as incoming.
func (c *Client) GetTransferPayloads(ctx context.Context, txid string) ([][]byte, error) {
	if strings.TrimSpace(txid) == "" {
		return nil, errors.New("dero: transaction id is required")
	}
	entries, err := c.GetTransfers(ctx, GetTransfersParams{In: true, Out: true, Coinbase: true})
	if err != nil {
		return nil, err
	}
	payloads := make([][]byte, 0, 1)
	for _, entry := range entries {
		if entry.TXID != txid {
			continue
		}
		payload, err := EntryPayload(entry)
		if err != nil {
			return nil, fmt.Errorf("dero: transaction %s has undecodable payload: %w", txid, err)
		}
		payloads = append(payloads, append([]byte(nil), payload...))
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("dero: transaction %s was not found in wallet history", txid)
	}
	return payloads, nil
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

// GetBalance returns the wallet's balance and unlocked balance in atomic units.
// A wallet can report a non-zero balance while its transfer HISTORY is empty —
// see WalletReceiveReady, which is the check that catches that combination.
func (c *Client) GetBalance(ctx context.Context) (balance, unlocked uint64, err error) {
	var out struct {
		Balance       uint64 `json:"balance"`
		Unlocked      uint64 `json:"unlocked_balance"`
		BalanceString string `json:"balance_string"`
	}
	if err := c.call(ctx, "getbalance", nil, &out); err != nil {
		return 0, 0, err
	}
	return out.Balance, out.Unlocked, nil
}

// WalletReceiveReady reports whether this wallet can report RECEIVED transfers.
//
// Some wallets answer get_transfers with an empty set no matter what flags are
// passed, even while holding a non-zero balance: their transfer index is only
// populated by a history scan that never ran (a freshly created wallet is the
// usual case). Such a wallet is a perfectly good SENDER and a useless RECEIVER
// for anything that discovers messages through transfer history — the pointer
// is on chain and the funds arrived, but the receiver sees nothing to fetch.
//
// The signal is the combination, never either half alone: an empty history with
// a ZERO balance is just a new wallet (nothing to show), while a non-zero
// balance with a non-empty history is healthy. Only balance-without-history
// means "this wallet will silently miss inbound messages".
//
// Returned counts are for the caller's message; the error is transport-level
// only and is never used to infer readiness.
func (c *Client) WalletReceiveReady(ctx context.Context) (ready, hasHistory bool, balance uint64, err error) {
	bal, _, berr := c.GetBalance(ctx)
	if berr != nil {
		return false, false, 0, berr
	}
	// Ask for every bucket the filter accepts, so an empty answer is genuinely
	// "no history" rather than "the flags excluded it".
	entries, terr := c.GetTransfers(ctx, GetTransfersParams{In: true, Out: true, Coinbase: true})
	if terr != nil {
		return false, false, bal, terr
	}
	hasHistory = len(entries) > 0
	return hasHistory || bal == 0, hasHistory, bal, nil
}

// AnchorEvent is one anchor observed on-chain addressed to us.
type AnchorEvent struct {
	TXID       string
	TopoHeight int64
	Anchor     *anchor.Anchor
}

// IncomingAnchors polls get_transfers (in:true, min_height) and returns
// events whose payload parses as a compost anchor. Non-anchor transfers are
// skipped silently. Delivered entry identities are tracked so an anchor is
// emitted exactly once (the wallet's min_height filter is >=, so a cursor at
// the anchor's own height would otherwise re-match it every poll). Polls every
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
			maxHeight := cursor
			for _, e := range entries {
				if e.Height > maxHeight {
					maxHeight = e.Height
				}
				if e.TXID == "" {
					continue
				}
				raw, err := EntryPayload(e)
				if err != nil {
					continue // malformed or undecodable payload — skip
				}
				id := EntryIdentity(e, raw)
				if id == "" || seen[id] {
					continue
				}
				args, err := PayloadToArgs(raw)
				if err != nil {
					continue // malformed typed payload — skip
				}
				a, err := anchor.FromArguments(args)
				if err != nil {
					continue // not a compost anchor (or malformed) — skip
				}
				select {
				case ch <- AnchorEvent{TXID: e.TXID, TopoHeight: e.TopoHeight, Anchor: a}:
					seen[id] = true
				case <-ctx.Done():
					return
				}
			}
			if maxHeight > cursor {
				cursor = maxHeight
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
