package xmr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/mycelium/internal/chain"
)

// mockWalletRPC emulates the Monero wallet RPC for the methods we use.
func mockWalletRPC(t *testing.T, address string) *httptest.Server {
	t.Helper()
	height := uint64(500000)
	var received []map[string]interface{} // stored transfers (payment_id, height)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result interface{}
		switch req.Method {
		case "get_address":
			result = map[string]interface{}{"address": address, "addresses": []interface{}{map[string]interface{}{"address": address, "used": false, "index": 0}}}
		case "get_height":
			result = map[string]interface{}{"height": height}
		case "transfer":
			var p struct {
				Destinations []struct {
					Address string `json:"address"`
					Amount  uint64 `json:"amount"`
				} `json:"destinations"`
				PaymentID string `json:"payment_id"`
			}
			_ = json.Unmarshal(req.Params, &p)
			received = append(received, map[string]interface{}{
				"payment_id": p.PaymentID,
				"address":    p.Destinations[0].Address,
				"amount":     p.Destinations[0].Amount,
				"height":     height,
				"txid":       "deadbeef" + string(rune(len(received))),
			})
			height++
			result = map[string]interface{}{
				"tx_hash": "abc123",
				"tx_key":  "k",
				"amount":  p.Destinations[0].Amount,
			}
		case "get_transfers":
			// Echo back every stored transfer as an inbound.
			result = map[string]interface{}{
				"in":      received,
				"out":     []interface{}{},
				"pending": []interface{}{},
				"pool":    []interface{}{},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 1, "jsonrpc": "2.0", "result": result})
	}))
	return srv
}

func TestXMRNameAddressHeight(t *testing.T) {
	srv := mockWalletRPC(t, "43TestXMRAddress")
	defer srv.Close()
	b := NewBackend(srv.URL)
	if b.Name() != "xmr" {
		t.Fatalf("name=%s", b.Name())
	}
	addr, err := b.Address(context.Background())
	if err != nil || addr != "43TestXMRAddress" {
		t.Fatalf("addr=%s err=%v", addr, err)
	}
	h, err := b.Height(context.Background())
	if err != nil || h != 500000 {
		t.Fatalf("height=%d err=%v", h, err)
	}
}

func TestXMRPostPayloadSmallFits(t *testing.T) {
	srv := mockWalletRPC(t, "43TestXMRAddress")
	defer srv.Close()
	b := NewBackend(srv.URL)
	// A short signal (≤8 bytes) must post fine.
	payload := chain.Payload{0x01, 0x00, 0x03, 'h', 'i', 'i'} // 6 bytes
	res, err := b.PostPayload(context.Background(), "44Recipient", payload, 1)
	if err != nil {
		t.Fatalf("post small: %v", err)
	}
	if res.TxID != "abc123" {
		t.Fatalf("txid=%q", res.TxID)
	}
}

func TestXMRPostPayloadTooBig(t *testing.T) {
	srv := mockWalletRPC(t, "43TestXMRAddress")
	defer srv.Close()
	b := NewBackend(srv.URL)
	// A real whisper (~83 bytes) does NOT fit 8-byte payment id.
	big := make([]byte, 9)
	_, err := b.PostPayload(context.Background(), "44Recipient", big, 1)
	if err == nil {
		t.Fatal("expected ErrPayloadTooBig for 9-byte payload")
	}
	if !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("wrong err: %v", err)
	}
}

func TestXMRListIncoming(t *testing.T) {
	srv := mockWalletRPC(t, "43TestXMRAddress")
	defer srv.Close()
	b := NewBackend(srv.URL)
	// Seed one inbound with a canonical signal payment id (kind 0x01 text).
	// Simulate by posting a small payload first.
	_, err := b.PostPayload(context.Background(), "43TestXMRAddress", chain.Payload{0x01, 0x00, 0x03, 'h', 'i'}, 1)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := b.ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// PostPayload used address "43TestXMRAddress"; the mock stored it; ListIncoming
	// should return it as an inbound if it has a valid kind.
	found := false
	for _, it := range inc {
		if it.Payload[0] == 0x01 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no signal inbound found: %+v", inc)
	}
}
