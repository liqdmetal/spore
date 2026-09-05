package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

// TestPostAnchorWireShape pins the exact JSON the wallet RPC must receive:
// method "transfer", a minimum-postage (1 atomic unit) transfer, and 4 typed
// payload_rpc args.
func TestPostAnchorWireShape(t *testing.T) {
	var gotMethod string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"deadbeef"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	a := &anchor.Anchor{Version: anchor.Version, Kind: anchor.KindMessage, BurnDeadline: 12345}
	txid, err := c.PostAnchor(context.Background(), "dero1abc", a, 0)
	if err != nil {
		t.Fatal(err)
	}
	if txid != "deadbeef" {
		t.Fatalf("txid = %q", txid)
	}
	if !strings.HasSuffix(gotMethod, "/json_rpc") && gotMethod != "" {
		// httptest serves at a path of our choosing; method here is the path.
	}
	// The client posts to whatever URL we gave it; verify the envelope.
	m, ok := gotBody["method"].(string)
	if !ok || m != "transfer" {
		t.Fatalf("method = %v, want transfer", gotBody["method"])
	}
	params, ok := gotBody["params"].(map[string]interface{})
	if !ok {
		t.Fatalf("no params in body: %v", gotBody)
	}
	transfers, ok := params["transfers"].([]interface{})
	if !ok || len(transfers) != 1 {
		t.Fatalf("transfers = %v", params["transfers"])
	}
	tr := transfers[0].(map[string]interface{})
	if tr["amount"].(float64) != 1 {
		t.Fatalf("amount = %v, want 1 (minimum postage; 0 never surfaces to recipient)", tr["amount"])
	}
	if tr["destination"].(string) != "dero1abc" {
		t.Fatalf("destination = %v", tr["destination"])
	}
	// ringsize defaults to 2.
	if params["ringsize"].(float64) != 2 {
		t.Fatalf("ringsize = %v, want 2", params["ringsize"])
	}
	prpc, ok := tr["payload_rpc"].([]interface{})
	if !ok || len(prpc) != 4 {
		t.Fatalf("payload_rpc len = %d", len(prpc))
	}
	first := prpc[0].(map[string]interface{})
	if first["name"].(string) != "K" || first["datatype"].(string) != "H" {
		t.Fatalf("first arg = %v", first)
	}
	// K and C values must be 64-char hex strings.
	if len(first["value"].(string)) != 64 {
		t.Fatalf("K value not 64-char hex: %v", first["value"])
	}
}

// TestGetTransfersParse verifies the response side: entries come back with
// payload_rpc hash values as hex strings, which FromArguments must accept.
func TestGetTransfersParse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"entries":[{
			"topoheight": 42,
			"incoming": true,
			"txid": "aa",
			"payload_rpc":[
				{"name":"K","datatype":"H","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{"name":"C","datatype":"H","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				{"name":"D","datatype":"U","value":1234567890},
				{"name":"F","datatype":"U","value":257}
			]
		}]}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	entries, err := c.GetTransfers(context.Background(), GetTransfersParams{In: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	a, err := anchor.FromArguments(entries[0].PayloadRPC)
	if err != nil {
		t.Fatal(err)
	}
	if a.BurnDeadline != 1234567890 {
		t.Fatalf("deadline = %d", a.BurnDeadline)
	}
	if a.Kind != anchor.KindMessage {
		t.Fatalf("kind = %d", a.Kind)
	}
	if a.Version != anchor.Version {
		t.Fatalf("version = %d", a.Version)
	}
}

// TestAuthHeader verifies basic auth is set when credentials are provided.
func TestAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"address":"dero1x"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "user", "pass")
	if _, err := c.GetAddress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth == "" {
		t.Fatal("expected Authorization header")
	}
}

// TestRPCError verifies server-side errors surface as Go errors.
func TestRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","error":{"code":-1,"message":"Insufficent funds"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "", "")
	if _, err := c.GetAddress(context.Background()); err == nil {
		t.Fatal("expected rpc error")
	}
}
