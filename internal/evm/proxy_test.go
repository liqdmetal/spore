package evm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// proxyUpstreamStub answers every method a proxy round-trip touches and
// records what arrives. It behaves like a read-only public RPC: if the proxy
// failed to intercept eth_sendTransaction, the request would land in `other`
// and no raw tx would be broadcast — both assertions fail loudly.
type proxyUpstreamStub struct {
	t      *testing.T
	srv    *httptest.Server
	rawTxs []string
	other  map[string]int
}

func newProxyUpstreamStub(t *testing.T) *proxyUpstreamStub {
	s := &proxyUpstreamStub{t: t, other: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "eth_sendRawTransaction":
			var params []string
			if json.Unmarshal(req.Params, &params) != nil || len(params) != 1 {
				writeRPCError(w, req.ID, "want one raw tx")
				return
			}
			s.rawTxs = append(s.rawTxs, params[0])
			writeRPCResult(w, req.ID, "0xfeedface")
		case "eth_chainId":
			writeRPCResult(w, req.ID, "0x14a34") // Base Sepolia's id
		case "eth_getTransactionCount":
			writeRPCResult(w, req.ID, "0x0")
		case "eth_gasPrice":
			writeRPCResult(w, req.ID, "0x3b9aca00")
		case "eth_estimateGas":
			writeRPCResult(w, req.ID, "0x5208")
		default:
			s.other[req.Method]++
			writeRPCResult(w, req.ID, "0x1")
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func postRPC(t *testing.T, h http.Handler, method string, params string) (int, map[string]interface{}) {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": float64(1), "method": method,
		"params": json.RawMessage(params),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("non-JSON proxy response (%d): %s", rec.Code, rec.Body.String())
	}
	return rec.Code, out
}

func TestProxySignsSendTransactionAndForwardsTheRest(t *testing.T) {
	up := newProxyUpstreamStub(t)
	p, err := NewProxy(up.srv.URL, rehearsalKey)
	if err != nil {
		t.Fatal(err)
	}
	h := p.Handler()

	// What `spore msg send-e2` emits on the send path: eth_sendTransaction
	// with from/to/data. The proxy must intercept and sign it locally.
	code, resp := postRPC(t, h, "eth_sendTransaction",
		`[{"from":"`+p.Signer()+`","to":"0x2222222222222222222222222222222222222222","data":"0x6869"}]`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, resp)
	}
	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	if resp["result"] != "0xfeedface" {
		t.Fatalf("result = %v", resp["result"])
	}
	if len(up.rawTxs) != 1 {
		t.Fatalf("expected one signed raw tx upstream, got %d", len(up.rawTxs))
	}
	// A signed EIP-155 tx is a 9-field RLP list; with these inputs the list
	// is long-form (0xf8 prefix). Assert the shape plus our gasPrice and
	// recipient riding inside the signed payload.
	raw := up.rawTxs[0]
	if !strings.HasPrefix(raw, "0xf8") || len(raw) < 100 {
		t.Fatalf("raw tx does not look like a signed legacy tx: %s", raw)
	}
	for _, want := range []string{"3b9aca00", "2222222222222222222222222222222222222222", "6869"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("signed tx missing %s: %s", want, raw)
		}
	}
	if up.other["eth_sendTransaction"] != 0 {
		t.Fatal("eth_sendTransaction must never reach the upstream unsigned")
	}

	// Non-signing methods pass through verbatim.
	if _, resp := postRPC(t, h, "eth_blockNumber", `[]`); resp["result"] != "0x1" {
		t.Fatalf("pass-through broken: %v", resp)
	}
}

func TestProxyFromMismatchIsAnRPCError(t *testing.T) {
	up := newProxyUpstreamStub(t)
	p, err := NewProxy(up.srv.URL, rehearsalKey)
	if err != nil {
		t.Fatal(err)
	}
	_, resp := postRPC(t, p.Handler(), "eth_sendTransaction",
		`[{"from":"0x9999999999999999999999999999999999999999","to":"0x2222222222222222222222222222222222222222","data":"0x01"}]`)
	errObj, _ := resp["error"].(map[string]interface{})
	if errObj == nil {
		t.Fatalf("want an RPC error for a from-mismatch, got %v", resp)
	}
	if len(up.rawTxs) != 0 {
		t.Fatal("nothing may be broadcast on a from-mismatch")
	}
}
