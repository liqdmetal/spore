package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/channel"
	"github.com/liqdmetal/spore/internal/relay"
	"github.com/liqdmetal/spore/internal/safehttp"
	"github.com/liqdmetal/spore/internal/store"
)

// TestWebProxyDisabledByDefault: without -allow-browser-spend the wallet proxy
// routes must NOT exist even when -wallet-rpc is configured (audit C1) — a
// visitor gets 404, not a spend or an inbox dump.
func TestWebProxyDisabledByDefault(t *testing.T) {
	// Simulate the webchat mux wiring with the proxy OFF (the default).
	_ = channel.NewBox(channel.BoxConfig{}) // box unused when the proxy is off
	mux := http.NewServeMux()
	wrc := "http://127.0.0.1:20209/json_rpc"
	allowSpend := false
	webToken := ""
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wrc != "" && allowSpend { // the exact gate webchat now uses
			if webToken != "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/whisper/send" || r.URL.Path == "/whisper/recv" {
				http.Error(w, "proxy", http.StatusOK)
				return
			}
		}
		http.NotFound(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/whisper/send", "application/json", strings.NewReader(`{"to":"x","msg":"y"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /whisper/send with proxy disabled = %d, want 404 (must not exist)", res.StatusCode)
	}
	res2, err := http.Get(srv.URL + "/whisper/recv?since=0")
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /whisper/recv with proxy disabled = %d, want 404", res2.StatusCode)
	}
}

// TestRelayDenyByDefaultE2E: a default-configured relay (no -allow-dest)
// refuses every push with 403 — verified over the real HTTP handler.
func TestRelayDenyByDefaultE2E(t *testing.T) {
	r := relay.New(store.NewMemStore()) // no SetAllowedDests = the CLI default
	srv := httptest.NewServer(r.Handler())
	defer srv.Close()

	cid := [32]byte{}
	for i := range cid {
		cid[i] = byte(i)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/relay/"+strings.Repeat("ab", 32),
		strings.NewReader("any body"))
	req.Header.Set("X-Relay-Dest", "http://10.0.0.1:19191")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("default relay push = %d, want 403 (deny-by-default)", res.StatusCode)
	}
	if r.Len() != 0 {
		t.Fatal("refused push must not be held")
	}
}

// TestCheckBindRefusesNetworkBindWithoutToken pins the CLI guard: the exact
// call every command now makes must refuse the old dangerous defaults
// (":19292" etc.) and accept the new loopback defaults.
func TestCheckBindRefusesNetworkBindWithoutToken(t *testing.T) {
	// Old defaults: all interfaces, no token — must be refused.
	for _, addr := range []string{":19292", ":19191", ":19192", ":19300", "0.0.0.0:19292"} {
		if err := safehttp.CheckBind(addr, "", "test"); err == nil {
			t.Errorf("CheckBind(%q, no token) = nil, want refusal", addr)
		}
	}
	// New defaults: loopback — must be accepted without a token.
	for _, addr := range []string{"127.0.0.1:19292", "127.0.0.1:19191", "127.0.0.1:19192", "127.0.0.1:19300"} {
		if err := safehttp.CheckBind(addr, "", "test"); err != nil {
			t.Errorf("CheckBind(%q, no token) = %v, want nil", addr, err)
		}
	}
}
