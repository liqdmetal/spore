package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T, handler func(method string, params map[string]interface{}) map[string]interface{}) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := handler(req.Method, req.Params)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "1", "result": res})
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL)
}

func TestTxPool(t *testing.T) {
	c := testServer(t, func(method string, _ map[string]interface{}) map[string]interface{} {
		if method != "gettxpool" {
			t.Fatalf("method = %q, want gettxpool", method)
		}
		return map[string]interface{}{"txs": []string{"aaa", "bbb"}, "status": "OK"}
	})
	hashes, err := c.TxPool(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 || hashes[0] != "aaa" {
		t.Fatalf("hashes = %v", hashes)
	}
}

func TestGetTxsAsHex(t *testing.T) {
	c := testServer(t, func(method string, params map[string]interface{}) map[string]interface{} {
		if method != "gettransactions" {
			t.Fatalf("method = %q", method)
		}
		if params["decode_as_json"] != float64(0) {
			t.Fatalf("decode_as_json = %v, want 0", params["decode_as_json"])
		}
		return map[string]interface{}{"txs_as_hex": []string{"deadbeef"}}
	})
	hexes, err := c.GetTxsAsHex(context.Background(), []string{"aaa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hexes) != 1 || hexes[0] != "deadbeef" {
		t.Fatalf("hexes = %v", hexes)
	}
}

func TestPoolWatcherEmitsOnce(t *testing.T) {
	// First call returns {a,b}; later calls return {b,c}. Watcher must emit
	// each hash exactly ONCE ever (unbounded seen-set), so a and b fire on
	// the first poll, c on the second — b is NOT re-emitted just because it
	// persists across polls.
	call := 0
	c := testServer(t, func(method string, _ map[string]interface{}) map[string]interface{} {
		call++
		if call == 1 {
			return map[string]interface{}{"txs": []string{"a", "b"}}
		}
		return map[string]interface{}{"txs": []string{"b", "c"}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	ch, _ := c.PoolWatcher(ctx, 20*time.Millisecond)
	var got []string
	for h := range ch {
		got = append(got, h)
	}
	m := map[string]int{}
	for _, h := range got {
		m[h]++
	}
	// Each hash once ever.
	if m["a"] != 1 || m["b"] != 1 || m["c"] != 1 {
		t.Fatalf("got %v (want a:1 b:1 c:1)", m)
	}
}
