package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "DERO.NameToAddress" {
			t.Fatalf("method = %q", req.Method)
		}
		if req.Params["name"] != "alice" {
			t.Fatalf("name = %v", req.Params["name"])
		}
		if req.Params["topoheight"] != float64(-1) {
			t.Fatalf("topoheight = %v", req.Params["topoheight"])
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": "1",
			"result": map[string]interface{}{"address": "dero1qyy...", "status": "OK"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	addr, err := c.ResolveName(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "dero1qyy..." {
		t.Fatalf("addr = %q", addr)
	}
}

func TestResolveNameEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": "1", "result": map[string]interface{}{}})
	}))
	defer srv.Close()
	c := NewClient(srv.URL)
	if _, err := c.ResolveName(context.Background(), "ghost"); err == nil {
		t.Fatal("expected error for unregistered name")
	}
}
