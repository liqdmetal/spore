package evm

// The contract-path value drop is a documented feature (deliver() is not
// payable), but a feature this dangerous must be pinned by a test: the CLI
// refuses -amount on the mailbox path (cmd/spore refuseValueOnMailboxPath)
// BECAUSE this branch silently drops the hint. If the drop ever changes —
// a payable deliver, a revert, a value-forwarding pattern — this test fails
// and the refusal plus the honest fee notes must be updated with it.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// valueCapturingNode answers eth_sendTransaction with a fake hash and
// records the tx params it was given.
type valueCapturingNode struct {
	mu     sync.Mutex
	params map[string]interface{}
}

func (n *valueCapturingNode) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := "0xfakehash"
		if req.Method == "eth_sendTransaction" && len(req.Params) == 1 {
			if m, ok := req.Params[0].(map[string]interface{}); ok {
				n.mu.Lock()
				n.params = m
				n.mu.Unlock()
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": res,
		})
	})
}

func (n *valueCapturingNode) sentParams() map[string]interface{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.params
}

// TestPostPayloadContractPathDropsValue pins the honest-money invariant the
// docs and the CLI refusal are written against: with a mailbox set, a nonzero
// amountHint NEVER reaches the wire. The payable calldata path (no mailbox)
// must still carry the value.
func TestPostPayloadContractPathDropsValue(t *testing.T) {
	n := &valueCapturingNode{}
	srv := httptest.NewServer(n.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	b.SetMailbox("0x0000000000000000000000000000000000000001")
	if _, err := b.PostPayload(context.Background(), "0x0000000000000000000000000000000000000002", []byte("payload"), 12345); err != nil {
		t.Fatalf("contract-path post: %v", err)
	}
	if v := n.sentParams()["value"]; v != nil {
		t.Fatalf("contract path carried tx value %v — deliver() is not payable; this branch MUST drop amountHint (the CLI refuses -amount here because of it)", v)
	}
	if to, _ := n.sentParams()["to"].(string); !strings.EqualFold(to, "0x0000000000000000000000000000000000000001") {
		t.Fatalf("contract path sent to %v, want the mailbox", to)
	}

	n2 := &valueCapturingNode{}
	srv2 := httptest.NewServer(n2.handler())
	defer srv2.Close()

	b2 := NewBackend(srv2.URL, "evm-test", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := b2.PostPayload(context.Background(), "0x0000000000000000000000000000000000000002", []byte("payload"), 12345); err != nil {
		t.Fatalf("calldata-path post: %v", err)
	}
	if v, _ := n2.sentParams()["value"].(string); v != "0x3039" { // 12345
		t.Fatalf("calldata path value = %v, want 0x3039 (the payable path must keep carrying value)", v)
	}
}
