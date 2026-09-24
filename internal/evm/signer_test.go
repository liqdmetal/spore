package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// signStubNode is a minimal JSON-RPC node for signer tests: it answers the
// standard tx-signing methods, records every method it saw, and captures the
// raw broadcast transactions.
type signStubNode struct {
	t       *testing.T
	srv     *httptest.Server
	calls   map[string]int
	rawTxs  []string
	chainID string
	nonce   string
	gas     string
	est     string
}

func newSignStubNode(t *testing.T) *signStubNode {
	n := &signStubNode{
		t:       t,
		calls:   map[string]int{},
		chainID: "0x2105", // Base mainnet id in tests; the value only feeds the signature
		nonce:   "0x7",
		gas:     "0x3b9aca00", // 1 gwei
		est:     "0x5208",     // 21000
	}
	n.srv = httptest.NewServer(http.HandlerFunc(n.handler))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *signStubNode) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	n.calls[req.Method]++
	switch req.Method {
	case "eth_chainId":
		writeRPCResult(w, req.ID, n.chainID)
	case "eth_getTransactionCount":
		writeRPCResult(w, req.ID, n.nonce)
	case "eth_gasPrice":
		writeRPCResult(w, req.ID, n.gas)
	case "eth_estimateGas":
		writeRPCResult(w, req.ID, n.est)
	case "eth_sendRawTransaction":
		var params []string
		if json.Unmarshal(req.Params, &params) != nil || len(params) != 1 {
			writeRPCError(w, req.ID, "eth_sendRawTransaction expects one raw tx string")
			return
		}
		n.rawTxs = append(n.rawTxs, params[0])
		writeRPCResult(w, req.ID, "0xdeadbeef")
	default:
		writeRPCError(w, req.ID, "no such method: "+req.Method)
	}
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result string) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "result": result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, msg string) {
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]interface{}{"code": -32000, "message": msg},
	})
}

// rehearsalKey is a fixed never-for-funds test key (32 bytes).
const rehearsalKey = "0102030405060708010203040506070801020304050607080102030405060708"

func decodeRawTx(t *testing.T, raw string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		t.Fatalf("bad raw tx hex: %v", err)
	}
	return b
}

func TestSignAndSendTransactionHappyPath(t *testing.T) {
	n := newSignStubNode(t)
	b := NewBackend(n.srv.URL, "evm", "")

	addr, err := AddressForKey(rehearsalKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		t.Fatalf("bad derived address %q", addr)
	}

	data := "0x" + hex.EncodeToString([]byte("payload"))
	params := map[string]interface{}{
		"from": addr,
		"to":   "0x1111111111111111111111111111111111111111",
		"data": data,
	}
	got, err := b.SignAndSendTransaction(context.Background(), rehearsalKey, params)
	if err != nil {
		t.Fatal(err)
	}
	if got != "0xdeadbeef" {
		t.Fatalf("tx hash = %q", got)
	}
	for _, m := range []string{"eth_chainId", "eth_getTransactionCount", "eth_gasPrice", "eth_estimateGas", "eth_sendRawTransaction"} {
		if n.calls[m] != 1 {
			t.Fatalf("method %s called %d times, want 1 (calls: %v)", m, n.calls[m], n.calls)
		}
	}

	// Byte-exact check: the same inputs signed through the deterministic
	// deploy-path signer must produce the identical raw transaction.
	raw := decodeRawTx(t, n.rawTxs[0])
	key, err := parsePrivateKey(rehearsalKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroKey(key)
	chainID, _ := new(big.Int).SetString("0x2105", 0)
	if chainID == nil {
		t.Fatal("bad test chain id")
	}
	want, err := signLegacyTx(key, 7, new(big.Int).SetUint64(1_000_000_000), big.NewInt(21000),
		strToPtr("0x1111111111111111111111111111111111111111"), big.NewInt(0), chainID, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100 || !strings.EqualFold(hex.EncodeToString(raw), hex.EncodeToString(want)) {
		t.Fatalf("raw tx differs from the deterministic signer output\n got: %x\nwant: %x", raw, want)
	}
}

func strToPtr(s string) *string { return &s }

func TestSignAndSendTransactionFromMismatchRefused(t *testing.T) {
	n := newSignStubNode(t)
	b := NewBackend(n.srv.URL, "evm", "")
	params := map[string]interface{}{
		"from": "0x9999999999999999999999999999999999999999",
		"to":   "0x1111111111111111111111111111111111111111",
		"data": "0x01",
	}
	if _, err := b.SignAndSendTransaction(context.Background(), rehearsalKey, params); err == nil {
		t.Fatal("want error for from != signing key address")
	}
	if n.calls["eth_sendRawTransaction"] != 0 {
		t.Fatal("nothing should be broadcast on a from-mismatch")
	}
}

func TestSignAndSendTransactionHonorsSuppliedGas(t *testing.T) {
	n := newSignStubNode(t)
	b := NewBackend(n.srv.URL, "evm", "")
	params := map[string]interface{}{
		"to":   "0x1111111111111111111111111111111111111111",
		"data": "0x01",
		"gas":  "0x186a0", // 100000
	}
	if _, err := b.SignAndSendTransaction(context.Background(), rehearsalKey, params); err != nil {
		t.Fatal(err)
	}
	if n.calls["eth_estimateGas"] != 0 {
		t.Fatal("estimateGas must not run when gas is supplied")
	}
}

func TestSignAndSendTransactionValueDecoding(t *testing.T) {
	n := newSignStubNode(t)
	b := NewBackend(n.srv.URL, "evm", "")
	// Decimal wei value must be accepted alongside 0x-hex.
	params := map[string]interface{}{
		"to":    "0x1111111111111111111111111111111111111111",
		"data":  "0x01",
		"gas":   "0x186a0",
		"value": "1000000000000000000",
	}
	if _, err := b.SignAndSendTransaction(context.Background(), rehearsalKey, params); err != nil {
		t.Fatal(err)
	}
	if n.calls["eth_sendRawTransaction"] != 1 {
		t.Fatal("expected exactly one broadcast")
	}
}
