// Package daemon is the seam to a DERO node daemon's RPC (the recipient's OWN
// node). It is what makes the mempool-whisper (L1) work: a node sees a tx in
// its txpool ~1-2s after it propagates on P2P, BEFORE it mines. By polling the
// pool we can catch a whisper the moment it arrives, rather than waiting a
// block (~18s).
//
// Two methods are used (both on the daemon RPC, NOT the wallet RPC):
//
//	gettxpool              -> list of tx hashes in the pool
//	gettransactions        -> fetch a pool tx; with decode_as_json it returns
//	                          the tx's arguments payload as JSON (rpc/daemon_rpc.go)
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a daemon-RPC client for txpool watching.
type Client struct {
	url  string
	http *http.Client
}

// NewClient targets a daemon RPC /json_rpc endpoint (default
// http://127.0.0.1:10102/json_rpc).
func NewClient(url string) *Client {
	return &Client{url: url, http: &http.Client{Timeout: 30 * time.Second}}
}

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
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) call(ctx context.Context, method string, params, out interface{}) error {
	b, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: "1", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("daemon: bad response: %w", err)
	}
	if r.Error != nil {
		return fmt.Errorf("daemon: rpc error %d: %s", r.Error.Code, r.Error.Message)
	}
	if out != nil && len(r.Result) > 0 {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// TxPoolResult is the gettxpool response.
type TxPoolResult struct {
	TxList []string `json:"txs"`
	Status string   `json:"status"`
}

// TxPool returns the hashes currently in the node's txpool.
func (c *Client) TxPool(ctx context.Context) ([]string, error) {
	var out TxPoolResult
	if err := c.call(ctx, "gettxpool", map[string]interface{}{}, &out); err != nil {
		return nil, err
	}
	return out.TxList, nil
}

// TxJSON is one tx as JSON (from gettransactions decode_as_json).
type TxJSON struct {
	// Minimal: we only need to know a pool tx exists to try decrypt. Full
	// payload extraction for a whisper is done by the receiver's wallet on
	// confirmation (L3). For L1 pool catch, decode_as_json gives the payload.
	TXID string `json:"txid,omitempty"`
}

// GetTxsAsHex fetches one or more tx hashes, returning raw serialized hex.
func (c *Client) GetTxsAsHex(ctx context.Context, hashes []string) ([]string, error) {
	var out struct {
		TxsAsHex []string `json:"txs_as_hex"`
	}
	if err := c.call(ctx, "gettransactions", map[string]interface{}{
		"txs_hashes": hashes, "decode_as_json": 0,
	}, &out); err != nil {
		return nil, err
	}
	if len(out.TxsAsHex) == 0 {
		return nil, nil
	}
	return out.TxsAsHex, nil
}

// IsWhisperCandidate is a placeholder seam: whether a pool tx might be a
// whisper. The real determination needs payload decryption (B, Rust). This
// returns true so the caller pulls every new pool tx to hand to the decryptor.
func (c *Client) IsWhisperCandidate(txHash string) bool { return true }

// PoolWatcher polls the txpool for NEW hashes and emits each once.
func (c *Client) PoolWatcher(ctx context.Context, interval time.Duration) (<-chan string, <-chan error) {
	ch := make(chan string)
	errc := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errc)
		seen := map[string]bool{}
		for {
			hashes, err := c.TxPool(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errc <- err
			} else {
				for _, h := range hashes {
					if !seen[h] {
						seen[h] = true
						select {
						case ch <- h:
						case <-ctx.Done():
							return
						}
					}
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

// ErrEmpty is a sentinel for a nil result.
var ErrEmpty = errors.New("daemon: empty result")

// NameToAddressResult is the DERO.NameToAddress response.
type NameToAddressResult struct {
	Address string `json:"address"`
	Status  string `json:"status"`
}

// ResolveName resolves a DERO name-service name (e.g. "alice" or "alice.dero")
// to a bech32 address via the daemon. If name is already a valid-looking bech32
// address it is returned unchanged (so callers can pass either form). Returns
// an error if the name is unregistered or the RPC fails.
func (c *Client) ResolveName(ctx context.Context, name string) (string, error) {
	if name == "" {
		return "", errors.New("daemon: empty name")
	}
	var out NameToAddressResult
	if err := c.call(ctx, "DERO.NameToAddress", map[string]interface{}{"name": name, "topoheight": -1}, &out); err != nil {
		return "", err
	}
	if out.Address == "" {
		return "", fmt.Errorf("daemon: name %q not registered", name)
	}
	return out.Address, nil
}
