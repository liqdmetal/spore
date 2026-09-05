package xmr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liqdmetal/mycelium/internal/chain"
	"github.com/liqdmetal/mycelium/internal/whisper"
)

// twoWalletNode emulates a Monero wallet RPC shared by a sender and receiver
// posting short signals to each other. Inbound transfers surface on get_transfers.
type twoWalletNode struct {
	// a message addressed to our test address appears as an inbound transfer
	// whose payment_id carries the canonical signal.
	inbound []map[string]interface{}
}

func (n *twoWalletNode) handler(t *testing.T, ourAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result interface{}
		switch req.Method {
		case "get_address":
			result = map[string]interface{}{"address": ourAddr}
		case "get_height":
			result = map[string]interface{}{"height": uint64(400000)}
		case "transfer":
			// A transfer to ourAddr is an inbound message for us.
			var p struct {
				Destinations []struct {
					Address string `json:"address"`
					Amount  uint64 `json:"amount"`
				} `json:"destinations"`
				PaymentID string `json:"payment_id"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if len(p.Destinations) == 1 && p.Destinations[0].Address == ourAddr {
				n.inbound = append(n.inbound, map[string]interface{}{
					"txid":       "sig" + itoa(len(n.inbound)),
					"height":     uint64(400000 + len(n.inbound)),
					"payment_id": p.PaymentID,
					"address":    ourAddr,
					"amount":     p.Destinations[0].Amount,
				})
			}
			result = map[string]interface{}{"tx_hash": "sighash"}
		case "get_transfers":
			result = map[string]interface{}{"in": n.inbound, "out": []interface{}{}, "pending": []interface{}{}, "pool": []interface{}{}}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 1, "jsonrpc": "2.0", "result": result})
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	b := []byte{}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestXMRShortSignalFullLoop proves a SHORT no-relay signal (<=8 bytes canonical)
// round-trips sender -> recipient through the XMR chain.Chain + canonical codec.
// Longer messages correctly can't ride XMR (8-byte payment id) and go via the
// off-chain rendezvous instead (see ROADMAP/VISION §3).
func TestXMRShortSignalFullLoop(t *testing.T) {
	addr := "43ReceiverSubaddress"
	node := &twoWalletNode{}
	srv := httptest.NewServer(node.handler(t, addr))
	defer srv.Close()

	// Sender uses a different wallet address but posts to addr.
	sender := NewBackend(srv.URL)
	codec := whisper.CanonicalCodec{}
	// A short signal that fits: canonical encoding of "hi" = 5 bytes.
	if _, err := whisper.SendChain(context.Background(), sender, codec, addr, "hi"); err != nil {
		t.Fatalf("send short signal: %v", err)
	}

	// Receiver (our wallet, addr) polls and must see it decrypted as text.
	recv := NewBackend(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, _ := whisper.RecvChain(ctx, recv, codec, chain.WatchOpts{MinHeight: 0, Interval: 20 * time.Millisecond})
	for m := range ch {
		if m.Text == "hi" {
			return // PASS
		}
	}
	t.Fatal("did not receive the short XMR signal through the seam")
}

// TestXMRLongTextRejected documents the honest limit: real prose (>8B canonical)
// cannot ride XMR on-chain.
func TestXMRLongTextRejected(t *testing.T) {
	srv := mockWalletRPC(t, "43Receiver")
	defer srv.Close()
	b := NewBackend(srv.URL)
	codec := whisper.CanonicalCodec{}
	longText := "this is a real message that is much longer than eight bytes"
	_, err := whisper.SendChain(context.Background(), b, codec, "43Receiver", longText)
	if err == nil {
		t.Fatal("expected long text to fail on XMR (8-byte payment id cap)")
	}
}
