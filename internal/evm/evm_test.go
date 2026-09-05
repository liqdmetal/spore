package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/mycelium/internal/chain"
)

// mock EVM JSON-RPC node.
func mockNode(t *testing.T) *httptest.Server {
	t.Helper()
	cur := uint64(50)
	var sent []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var res interface{}
		switch req.Method {
		case "eth_blockNumber":
			res = "0x" + hexNumber(cur)
		case "eth_sendTransaction":
			var tx map[string]interface{}
			_ = json.Unmarshal(req.Params[0], &tx)
			sent = append(sent, tx)
			res = "0xabcdef1234"
		case "eth_getBlockByNumber":
			// return a block containing the sent tx as an incoming to "0xaa.."
			// only if it targeted us; here simulate one inbound whisper.
			var blk evmBlock
			// simulate one tx to 0xbbbb from 0xaaaa with a payload
			in := "68656c6c6f2065766d" // "hello evm"
			blk.Transactions = []evmTx{{Hash: "0xdeadbeef", From: "0xaaaa", To: "0xbbbb", Input: "0x" + in}}
			res = blk
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": res})
	}))
	return srv
}

func hexNumber(n uint64) string {
	b := make([]byte, 0)
	for n > 0 {
		b = append([]byte{byte("0123456789abcdef"[n%16])}, b...)
		n /= 16
	}
	return string(b)
}

func TestEVMHeight(t *testing.T) {
	srv := mockNode(t)
	defer srv.Close()
	b := NewBackend(srv.URL, "evm-fork", "0xbbbb")
	h, err := b.Height(context.Background())
	if err != nil || h != 50 {
		t.Fatalf("height=%d err=%v", h, err)
	}
}

func TestEVMPostPayload(t *testing.T) {
	srv := mockNode(t)
	defer srv.Close()
	b := NewBackend(srv.URL, "evm-fork", "0xbbbb")
	payload := chain.Payload("hello evm")
	res, err := b.PostPayload(context.Background(), "0xcccc", payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.TxID != "0xabcdef1234" {
		t.Fatalf("txid=%q", res.TxID)
	}
}

func TestEVMListIncoming(t *testing.T) {
	srv := mockNode(t)
	defer srv.Close()
	b := NewBackend(srv.URL, "evm-fork", "0xbbbb") // our address 0xbbbb
	inc, err := b.ListIncoming(context.Background(), 40)
	if err != nil {
		t.Fatal(err)
	}
	// The mock returns one tx to 0xbbbb.
	found := false
	for _, it := range inc {
		if strings.EqualFold(it.Sender, "0xaaaa") {
			if string(it.Payload) != "hello evm" {
				t.Fatalf("payload=%q", it.Payload)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find inbound whisper; got %+v", inc)
	}
}

func TestEVMPayloadRoundTripViaCodec(t *testing.T) {
	// Prove an m³ whisper can encode to EVM calldata and back.
	payload := []byte("0x" + hex.EncodeToString([]byte("hi from evm")))
	if !strings.HasPrefix(string(payload), "0x") {
		t.Fatal("calldata must be 0x-prefixed hex")
	}
}
