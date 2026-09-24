package evm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Proxy is a loopback signing proxy in front of a read-only public EVM RPC.
// `spore msg send-e2` posts via `eth_sendTransaction` with `from` (the
// node/wallet holds the key), but public RPCs refuse to sign. The proxy
// intercepts eth_sendTransaction, signs the legacy transaction locally with
// the SAME hand-rolled EIP-155 signer the deploy command uses (btcec,
// RFC-6979 deterministic; the key is zeroed after each signing), and
// broadcasts via eth_sendRawTransaction. Every other method is forwarded to
// the upstream node verbatim, so recv-e2/auto-burn and any other EVM command
// work through the same endpoint.
//
// The key exists in memory only, is never logged, and the HTTP server built
// from Handler() must stay on loopback — the proxy signs whatever
// eth_sendTransaction arrives at it.
type Proxy struct {
	upstream string
	keyHex   string
	signer   string // 0x address of the signing key
	client   *http.Client
}

// NewProxy builds a signing proxy for the given upstream JSON-RPC endpoint
// and 32-byte hex private key.
func NewProxy(upstream, privateKeyHex string) (*Proxy, error) {
	addr, err := AddressForKey(privateKeyHex)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		upstream: upstream,
		keyHex:   privateKeyHex,
		signer:   addr,
		client:   &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Signer is the 0x address this proxy signs as.
func (p *Proxy) Signer() string { return p.signer }

// Upstream is the JSON-RPC endpoint the proxy forwards to.
func (p *Proxy) Upstream() string { return p.upstream }

// Handler returns the http.Handler implementing the proxy. Loopback only.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.handle)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "evm-proxy: POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		p.writeError(w, req.ID, "evm-proxy: bad request body")
		return
	}
	if json.Unmarshal(body, &req) != nil {
		p.writeError(w, nil, "evm-proxy: not a JSON-RPC request")
		return
	}
	if req.Method != "eth_sendTransaction" {
		p.forward(w, r, body)
		return
	}

	var params []map[string]interface{}
	if len(req.Params) > 0 && string(req.Params) != "null" {
		if json.Unmarshal(req.Params, &params) != nil || len(params) != 1 {
			p.writeError(w, req.ID, "evm-proxy: eth_sendTransaction expects exactly one params object")
			return
		}
	}
	if len(params) == 0 || params[0] == nil {
		params = []map[string]interface{}{{}}
	}
	// Value rides INSIDE the signed params: absent = plain message post,
	// present (pay-with-message's wei hint) = it is signed and sent like any
	// other field. Never attach value out of band.
	if _, present := params[0]["value"]; !present {
		params[0]["value"] = "0x0"
	}
	// Fill in `from` only when the caller left it empty. A caller-supplied
	// from that differs from the signing key must FAIL LOUDLY (via
	// SignAndSendTransaction's check), never be silently rewritten: sends
	// signed from the wrong address would break the recipient's discovery
	// scan while looking perfectly healthy on the sender side.
	if want, _ := params[0]["from"].(string); strings.TrimSpace(want) == "" {
		params[0]["from"] = p.signer
	}
	b := NewBackend(p.upstream, "evm", p.signer)
	b.SetHTTPClient(p.client)
	txHash, err := b.SignAndSendTransaction(context.Background(), p.keyHex, params[0])
	if err != nil {
		p.writeError(w, req.ID, err.Error())
		return
	}
	p.writeResult(w, req.ID, txHash)
}

// forward sends a raw JSON-RPC request to the upstream node unchanged.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "evm-proxy: bad upstream URL", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "evm-proxy: upstream unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

func (p *Proxy) writeResult(w http.ResponseWriter, id json.RawMessage, result string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": result,
	})
}

func (p *Proxy) writeError(w http.ResponseWriter, id json.RawMessage, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]interface{}{"code": -32000, "message": msg},
	})
}
