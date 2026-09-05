// Package evm implements the chain.Chain backend for any EVM-compatible chain
// (generic EVM and EVM forks). It uses plain JSON-RPC (no go-ethereum import)
// so the backend is light and portable.
//
// Design: EVM has no native per-recipient encrypted message field. m³ supplies
// secrecy with its own ECDH (the same crypto powering DERO whispers); the EVM
// is identity + a carrier. A whisper is posted as transaction calldata `data`
// and the recipient discovers it via logs from a lightweight mailbox contract
// OR by scanning its own incoming txs' calldata.
//
// The minimal, dependency-free path used here: post a 0-value tx whose `data`
// carries the m³ payload, from OUR address TO the recipient address. The
// recipient (via its own node/wallet) reads txs where `to == ourAddress` and
// decrypts the calldata payload with m³ crypto. This works on ANY EVM node
// with no contract deployment. (A MyceliumMailbox contract with logs is the
// scalable follow-on; see ROADMAP.)
package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/liqdmetal/spore/internal/chain"
)

// Backend implements chain.Chain over an EVM JSON-RPC endpoint.
type Backend struct {
	rpc   string
	chain string
	http  *http.Client
	// signer wraps eth_sendTransaction; the node/wallet holds the key.
	// In practice this is a funded account unlocked on the node, or a
	// signing proxy. from is our address.
	from string
	// mailbox is the optional MyceliumMailbox contract address. When set,
	// delivery goes through the contract (deliver/read + Inbox logs) instead
	// of raw calldata txs. Empty = backward-compatible raw calldata path.
	mailbox string
}

// NewBackend builds an EVM backend. rpcURL is the JSON-RPC endpoint
// (http://host:8545). chainName is "evm" or the EVM fork's identifier.
// fromAddr is our address (the wallet/node signs sends).
func NewBackend(rpcURL, chainName, fromAddr string) *Backend {
	return &Backend{rpc: rpcURL, chain: chainName, from: fromAddr, http: &http.Client{}}
}

// SetMailbox points the backend at a deployed MyceliumMailbox contract address
// (0x-prefixed 40-hex). After this, PostPayload calls deliver() and
// ListIncoming reads Inbox logs. Empty clears it back to raw calldata.
func (b *Backend) SetMailbox(addr string) { b.mailbox = addr }

// Name implements chain.Chain.
func (b *Backend) Name() string { return b.chain }

// Address implements chain.Chain.
func (b *Backend) Address(ctx context.Context) (string, error) { return b.from, nil }

type rpcReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

func (b *Backend) call(ctx context.Context, method string, params interface{}, out interface{}) error {
	body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.rpc, bytes.NewReader(body))
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
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.Error != nil {
		return fmt.Errorf("evm rpc: %s", r.Error.Message)
	}
	if out != nil && len(r.Result) > 0 {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// Height implements chain.Chain (eth_blockNumber).
func (b *Backend) Height(ctx context.Context) (uint64, error) {
	var h string // hex
	if err := b.call(ctx, "eth_blockNumber", []interface{}{}, &h); err != nil {
		return 0, err
	}
	h = strings.TrimPrefix(h, "0x")
	n := new(big.Int)
	if _, ok := n.SetString(h, 16); !ok {
		return 0, fmt.Errorf("evm: bad block number %q", h)
	}
	return n.Uint64(), nil
}

// PostPayload implements chain.Chain. amountHint is wei; for a pure message
// post it should be 0 (the tx fee is the cost). With a mailbox contract set,
// the payload is ABI-encoded into a deliver(recipient, data) call to the
// contract; otherwise it rides as raw calldata to the recipient.
func (b *Backend) PostPayload(ctx context.Context, recipientAddr string, p chain.Payload, amountHint uint64) (chain.PostResult, error) {
	params := map[string]interface{}{
		"from": b.from,
	}
	if b.mailbox != "" {
		// Robust path: call deliver(recipient, payload) on the mailbox contract.
		// deliver() is not payable, so never attach a value here (unlike the
		// raw-calldata path, which can carry amountHint to an EOA).
		calldata, err := encodeDeliver(recipientAddr, []byte(p))
		if err != nil {
			return chain.PostResult{}, err
		}
		params["to"] = b.mailbox
		params["data"] = calldata
	} else {
		// Backward-compatible path: raw calldata to the recipient.
		params["to"] = recipientAddr
		params["data"] = "0x" + hex.EncodeToString(p)
		if amountHint > 0 {
			params["value"] = "0x" + strconv.FormatUint(amountHint, 16)
		}
	}
	var txhash string
	if err := b.call(ctx, "eth_sendTransaction", []interface{}{params}, &txhash); err != nil {
		return chain.PostResult{}, err
	}
	return chain.PostResult{TxID: txhash}, nil
}

// ListIncoming implements chain.Chain. It scans the recipient address's recent
// txs where `to == us` and returns their calldata as payloads. minHeight is
// treated as the from-block for eth_getLogs-less scanning: we return txs whose
// blockNumber >= minHeight that target us, by querying eth_getTransactionCount
// is not enough — this backend lists incoming by asking the node for the last
// N blocks' txs via eth_getBlockByNumber and filtering to==us. For simplicity
// and to avoid an archive node, we use the WebSocket/log-free approach: the
// caller polls Height and we expose ListIncoming as a scan of a block range the
// node can serve (eth_getBlockByNumber per block). To keep this lean we cap the
// lookback.
func (b *Backend) ListIncoming(ctx context.Context, minHeight uint64) ([]chain.Incoming, error) {
	// Robust path: when a mailbox contract is configured, recover payloads from
	// Inbox(to=us) logs via eth_getLogs + read(), instead of block scanning.
	if b.mailbox != "" {
		return mailboxListIncoming(ctx, b, minHeight)
	}
	// Backward-compatible path: block-scan for raw calldata txs to us.
	return evmScanIncoming(ctx, b, minHeight)
}
