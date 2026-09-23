package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The vectors below were generated with go-ethereum v1.14.11's reference
// implementations (types.SignTx with NewEIP155Signer, crypto.CreateAddress)
// against the test key 0x46 repeated 32 times. Signing is RFC-6979
// deterministic, so any change to spore's hand-rolled RLP encoding, EIP-155
// pre-image, or creation-address derivation breaks these tests byte-for-byte.
const (
	vecKey    = "4646464646464646464646464646464646464646464646464646464646464646"
	vecSender = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"

	// Signed legacy transfer: nonce=9, gasPrice=20 gwei, gas=21000,
	// to=0x09bB..8315, value=0, data=deadbeef, chainID=1337.
	vecRaw1 = "f86a098504a817c8008252089409bbd09a4683f264d67e9f8345e3e34c0f2d83158084deadbeef820a95a0f502fa76a70683c6692c5018869c33231b9db9ce9ce685f8e50845ba46598734a02e7c3527996a303f25bcc64476bf4458189d9e6fa0f88858f645a682d15cca4e"

	// Signed legacy contract creation: nonce=7, gasPrice=1 gwei, gas=53000,
	// to=nil, value=1 gwei, data=60806040, chainID=1337.
	vecRaw2 = "f85a078504a817c80082cf0880843b9aca008460806040820a95a076a693de24da5b7521fd779064d26fa1e4a079ba4ba5d2f3889333f478d4bc34a07314d8770af9259e7919af2fc819c0ee6ce8b16a3be20e506f6115522589882e"

	// geth crypto.CreateAddress(vecSender, 7).
	vecCreateAddrN7 = "0x393FB85c28C24868D5DfCe91194699ac342fFa6B"
	// geth crypto.CreateAddress(vecSender, 0) — nonce 0 encodes as the empty
	// RLP string, a classic off-by-one trap.
	vecCreateAddrN0 = "0x72665d3e94Cb4f374b7728F1ab21A3115C4D50Eb"
)

// rlpItems decodes the top-level items of an RLP-encoded tx list. Only string
// items appear in legacy txs, so lists are rejected. Deliberately independent
// of contract.go's encoder: the vectors must validate it, not round-trip
// through it.
func rlpItems(t *testing.T, rawHex string) [][]byte {
	t.Helper()
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("vector not hex: %v", err)
	}
	if len(raw) == 0 || raw[0] < 0xc0 {
		t.Fatal("vector is not an RLP list")
	}
	payload := raw[1:]
	if raw[0] > 0xf7 { // long list — length-of-length prefix
		ll := int(raw[0] - 0xf7)
		if len(payload) < ll {
			t.Fatal("truncated RLP")
		}
		payload = payload[ll:]
	}
	var items [][]byte
	for len(payload) > 0 {
		b := payload[0]
		var size int
		var val []byte
		switch {
		case b < 0x80: // single byte encodes itself
			val, payload = payload[:1], payload[1:]
		case b < 0xb8: // short string
			size = int(b - 0x80)
			if len(payload) < 1+size {
				t.Fatal("truncated RLP string")
			}
			val, payload = payload[1:1+size], payload[1+size:]
		case b < 0xc0: // long string
			ll := int(b - 0xb7)
			if len(payload) < 1+ll {
				t.Fatal("truncated RLP length")
			}
			for _, c := range payload[1 : 1+ll] {
				size = size<<8 | int(c)
			}
			if len(payload) < 1+ll+size {
				t.Fatal("truncated RLP string")
			}
			val, payload = payload[1+ll:1+ll+size], payload[1+ll+size:]
		default:
			t.Fatal("nested RLP list inside tx fields — not a legacy tx")
		}
		items = append(items, val)
	}
	return items
}

func itemUint(t *testing.T, b []byte) uint64 {
	t.Helper()
	if len(b) > 8 {
		t.Fatalf("field too long for uint64: %x", b)
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func TestSignLegacyTxAgainstGethVectors(t *testing.T) {
	key, err := parsePrivateKey(vecKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroKey(key)
	chainID := big.NewInt(1337)

	// Case 1: plain transfer.
	to := "0x09bBD09a4683F264d67E9F8345E3e34C0F2d8315"
	raw, err := signLegacyTx(key, 9, big.NewInt(20_000_000_000), big.NewInt(21_000), &to, big.NewInt(0), chainID, "deadbeef")
	if err != nil {
		t.Fatalf("sign transfer: %v", err)
	}
	if got := hex.EncodeToString(raw); got != vecRaw1 {
		t.Fatalf("transfer tx mismatch:\n got %s\nwant %s", got, vecRaw1)
	}

	// Case 2: contract creation (to == nil). Note the vector's gasPrice is
	// 20 gwei — geth's NewContractCreation takes (nonce, value, gas, gasPrice).
	raw, err = signLegacyTx(key, 7, big.NewInt(20_000_000_000), big.NewInt(53_000), nil, big.NewInt(1_000_000_000), chainID, "60806040")
	if err != nil {
		t.Fatalf("sign creation: %v", err)
	}
	if got := hex.EncodeToString(raw); got != vecRaw2 {
		t.Fatalf("creation tx mismatch:\n got %s\nwant %s", got, vecRaw2)
	}
}

// TestVectorStructure locks the semantic fields of vecRaw1 (v/r/s placement,
// EIP-155 v formula) so a future vector regen that accidentally produces a
// pre-155 signature cannot slip through TestSignLegacyTxAgainstGethVectors.
func TestVectorStructure(t *testing.T) {
	items := rlpItems(t, vecRaw1)
	if len(items) != 9 {
		t.Fatalf("legacy EIP-155 tx has 9 fields, got %d", len(items))
	}
	if got := itemUint(t, items[0]); got != 9 {
		t.Fatalf("nonce = %d", got)
	}
	if got := itemUint(t, items[1]); got != 20_000_000_000 {
		t.Fatalf("gasPrice = %d", got)
	}
	if got := itemUint(t, items[2]); got != 21_000 {
		t.Fatalf("gas = %d", got)
	}
	if hex.EncodeToString(items[3]) != "09bbd09a4683f264d67e9f8345e3e34c0f2d8315" {
		t.Fatalf("to = %x", items[3])
	}
	if hex.EncodeToString(items[5]) != "deadbeef" {
		t.Fatalf("data = %x", items[5])
	}
	// EIP-155: v = chainID*2 + 35 + recID = 1337*2 + 35 = 2709 for recID 0.
	if got := itemUint(t, items[6]); got != 2709 {
		t.Fatalf("v = %d, want 2709 (EIP-155, chainID 1337, recID 0)", got)
	}
	if len(items[7]) != 32 || len(items[8]) != 32 {
		t.Fatalf("r/s not 32 bytes: %d/%d", len(items[7]), len(items[8]))
	}
}

func TestCreateAddressAgainstGethVectors(t *testing.T) {
	for _, tc := range []struct {
		nonce uint64
		want  string
	}{
		{7, vecCreateAddrN7},
		{0, vecCreateAddrN0},
	} {
		got := createAddress(vecSender, tc.nonce)
		if !strings.EqualFold(got, tc.want) {
			t.Errorf("createAddress(sender, %d) = %s, want %s", tc.nonce, got, tc.want)
		}
	}
}

func TestLoadCreationCode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.bin")
	if err := os.WriteFile(p, []byte("0x6080604052604051600055\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := LoadCreationCode(p)
	if err != nil {
		t.Fatalf("LoadCreationCode: %v", err)
	}
	if code != "6080604052604051600055" {
		t.Fatalf("got %q", code)
	}
	if _, err := LoadCreationCode(filepath.Join(dir, "missing.bin")); !errors.Is(err, ErrNoCreationCode) {
		t.Fatalf("missing file: want ErrNoCreationCode, got %v", err)
	}
	if err := os.WriteFile(p, []byte("this is a readme, not bytecode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCreationCode(p); err == nil {
		t.Fatal("non-hex blob accepted")
	}
}

func TestParsePrivateKeyRejectsBadSizes(t *testing.T) {
	if _, err := parsePrivateKey(""); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("empty key: want ErrNoSigner, got %v", err)
	}
	if _, err := parsePrivateKey("abcd"); err == nil || errors.Is(err, ErrNoSigner) {
		t.Fatalf("short key: want size error, got %v", err)
	}
	if _, err := parsePrivateKey("zz" + vecKey[:62]); err == nil {
		t.Fatal("non-hex key accepted")
	}
}

// deployStubNode is a minimal EVM node mock covering the full deploy RPC
// sequence: chainId, getTransactionCount, gasPrice, estimateGas,
// sendRawTransaction, and repeated getCode polls.
type deployStubNode struct {
	mu          sync.Mutex
	sent        bool
	getCodeHits int
	rawTx       string
}

func (n *deployStubNode) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		n.mu.Lock()
		defer n.mu.Unlock()
		var res interface{}
		switch req.Method {
		case "eth_chainId":
			res = "0x7b" // 123
		case "eth_getTransactionCount":
			res = "0x7" // pins the creation address to vecCreateAddrN7
		case "eth_gasPrice":
			res = "0x4a817c800"
		case "eth_estimateGas":
			res = "0x1d4c0" // 120000
		case "eth_sendRawTransaction":
			_ = json.Unmarshal(req.Params[0], &n.rawTx)
			n.sent = true
			res = "0xdeadbeefhash"
		case "eth_getCode":
			n.getCodeHits++
			if n.sent && n.getCodeHits >= 2 {
				res = "0x6080604052" // code appears on the second poll
			} else {
				res = "0x"
			}
		default:
			res = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "result": res,
		})
	})
}

func TestDeployContractEIP155HappyPath(t *testing.T) {
	n := &deployStubNode{}
	srv := httptest.NewServer(n.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", vecSender)
	res, err := b.DeployContractEIP155(context.Background(), vecKey, "6080604052604051600055", nil)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if res.TxHash != "0xdeadbeefhash" {
		t.Fatalf("txHash = %s", res.TxHash)
	}
	// Nonce 7 from the stub: the derived address must equal the geth vector.
	if !strings.EqualFold(res.Addr, vecCreateAddrN7) {
		t.Fatalf("addr = %s, want %s", res.Addr, vecCreateAddrN7)
	}
	n.mu.Lock()
	sent := n.sent
	rawTx := n.rawTx
	n.mu.Unlock()
	if !sent || !strings.HasPrefix(rawTx, "0xf8") {
		t.Fatalf("raw tx not broadcast or not a legacy RLP tx: %q", rawTx)
	}
}

func TestDeployContractEIP155RequiresKey(t *testing.T) {
	n := &deployStubNode{}
	srv := httptest.NewServer(n.handler())
	defer srv.Close()

	b := NewBackend(srv.URL, "evm-test", vecSender)
	if _, err := b.DeployContractEIP155(context.Background(), "", "6080", nil); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("want ErrNoSigner, got %v", err)
	}
}
