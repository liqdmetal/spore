package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/whisper"
)

// A mock EVM node that actually stores calldata and serves it back in blocks.
type loopNode struct {
	mu     sync.Mutex
	height uint64
	// inbound stores txs addressed to OUR test account: hash -> {from, data}
	inbound map[string]mockTx
	seq     uint64
}
type mockTx struct {
	from string
	data []byte
}

func newLoopNode() *loopNode {
	return &loopNode{inbound: map[string]mockTx{}}
}

func (n *loopNode) handler(t *testing.T, ourAddr string) http.Handler {
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
		case "eth_blockNumber":
			res = "0x" + hexUint(n.height)
		case "eth_sendTransaction":
			var tx struct {
				To   string `json:"to"`
				Data string `json:"data"`
			}
			_ = json.Unmarshal(req.Params[0], &tx)
			n.seq++
			raw, _ := hex.DecodeString(stringsTrim0x(tx.Data))
			if stringsEqualFold(tx.To, ourAddr) {
				n.inbound["0xtx"+hexUint(n.seq)] = mockTx{from: "0xSender", data: raw}
			}
			n.height++
			res = "0xtx" + hexUint(n.seq)
		case "eth_getBlockByNumber":
			// serve the most recent inbound as a block tx to ourAddr
			var blk evmBlock
			for h, m := range n.inbound {
				blk.Transactions = []evmTx{{Hash: h, From: m.from, To: ourAddr, Input: "0x" + hex.EncodeToString(m.data)}}
				break
			}
			res = blk
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": res})
	})
}

func stringsTrim0x(s string) string {
	if len(s) > 1 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
func hexUint(n uint64) string {
	const d = "0123456789abcdef"
	var b [16]byte
	i := 16
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = d[n%16]
		n /= 16
	}
	return string(b[i:])
}

func TestEVMFullLoop(t *testing.T) {
	node := newLoopNode()
	ourAddr := "0xbbbbbb"
	srv := httptest.NewServer(node.handler(t, ourAddr))
	defer srv.Close()

	// sender posts a whisper TO ourAddr
	sender := NewBackend(srv.URL, "obscura", "0xSender")
	codec := whisper.CanonicalCodec{}
	if _, err := whisper.SendChain(context.Background(), sender, codec, ourAddr, "hi from obscura"); err != nil {
		t.Fatal(err)
	}

	// receiver (us) scans
	recv := NewBackend(srv.URL, "obscura", ourAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, _ := whisper.RecvChain(ctx, recv, codec, chain.WatchOpts{MinHeight: 0, Interval: 30 * time.Millisecond})
	for m := range ch {
		if m.Text == "hi from obscura" {
			return // PASS
		}
	}
	t.Fatal("did not receive the whisper through the EVM seam")
}
