package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientNormalizesBareEndpoint is the guard against the trap reappearing.
// The wallet serves "DERO BLOCKCHAIN Hello world!" at its root, which decodes
// as `invalid character 'D'` — a message that points at serialization, not at
// the missing path. Normalizing here, rather than at each call site, is what
// keeps a caller that never heard of the quirk from breaking.
func TestClientNormalizesBareEndpoint(t *testing.T) {
	var gotPath string
	var sawMethod bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["method"] == "getaddress" {
			sawMethod = true
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"address":"dero1qexample"}}`))
	}))
	defer srv.Close()

	// A client built from the BARE url must still reach the RPC handler.
	c := NewClient(srv.URL, "", "")
	if _, err := c.GetAddress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !sawMethod {
		t.Fatal("getaddress never reached the server")
	}
	if gotPath != "/json_rpc" {
		t.Fatalf("request path = %q, want /json_rpc (bare endpoint was not completed)", gotPath)
	}
}

// TestClientDoesNotRewriteExplicitPath: a wallet behind a reverse proxy may
// live at a path of its choosing. Completing that URL would break a working
// deployment, so an explicit path must survive untouched.
func TestClientDoesNotRewriteExplicitPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"address":"dero1qexample"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/wallet/json_rpc", "", "")
	if _, err := c.GetAddress(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/wallet/json_rpc" {
		t.Fatalf("request path = %q, want /wallet/json_rpc (explicit path was rewritten)", gotPath)
	}
}

// TestNormalizeWalletRPCURLPassthrough: inputs we cannot parse are returned
// unchanged rather than mangled into something that looks like a URL, and
// surrounding whitespace is trimmed (so a paste with a stray space still works).
func TestNormalizeWalletRPCURLPassthrough(t *testing.T) {
	for _, in := range []string{"", "not a url", "/json_rpc", "127.0.0.1:20211", "http://host/wallet"} {
		if got := NormalizeWalletRPCURL(in); got != in {
			t.Errorf("NormalizeWalletRPCURL(%q) = %q, want it unchanged", in, got)
		}
	}
	if got := NormalizeWalletRPCURL("   "); got != "" {
		t.Errorf("whitespace-only input = %q, want empty", got)
	}
	if got := NormalizeWalletRPCURL(" http://127.0.0.1:20211 "); got != "http://127.0.0.1:20211/json_rpc" {
		t.Errorf("padded url = %q, want it trimmed and completed", got)
	}
}
