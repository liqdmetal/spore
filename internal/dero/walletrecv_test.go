package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeWallet serves the two methods WalletReceiveReady uses and records every
// request body, so a test can assert WHAT was asked, not only what came back.
// The flag-interaction bug this guards (an empty get_transfers caused by
// omitting a bucket rather than by real emptiness) is invisible in a
// response-only test, which is exactly how it survived live for a whole
// session.
type fakeWallet struct {
	balance     uint64
	transfers   string // raw "result" JSON for get_transfers
	balanceErr  bool
	transferErr bool
	seen        []map[string]any
}

func (f *fakeWallet) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.seen = append(f.seen, body)
		method, _ := body["method"].(string)
		switch method {
		case "getbalance":
			if f.balanceErr {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","error":{"code":-32098,"message":"nope"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"balance":` +
				itoa(f.balance) + `,"unlocked_balance":` + itoa(f.balance) + `}}`))
		case "get_transfers":
			if f.transferErr {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","error":{"code":-32098,"message":"nope"}}`))
				return
			}
			res := f.transfers
			if res == "" {
				res = `{}`
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":` + res + `}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","error":{"code":-32601,"message":"no such method"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "", "")
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// TestWalletReceiveReadyDiscriminates is the core case: a funded wallet with an
// empty transfer index must be reported NOT ready, because such a wallet
// silently drops every inbound pointer. A funded wallet WITH history, and an
// empty wallet, must both be ready.
func TestWalletReceiveReadyDiscriminates(t *testing.T) {
	const oneEntry = `{"entries":[{"height":100,"incoming":true,"txid":"aa","amount":1}]}`

	cases := []struct {
		name        string
		balance     uint64
		transfers   string
		wantReady   bool
		wantHistory bool
	}{
		{"funded but no history is NOT ready (the trap)", 10002, "", false, false},
		{"funded with history is ready", 10002, oneEntry, true, true},
		{"empty wallet is ready (nothing to miss yet)", 0, "", true, false},
		{"empty wallet with history is ready", 0, oneEntry, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWallet{balance: tc.balance, transfers: tc.transfers}
			c := f.start(t)
			ready, hasHistory, bal, err := c.WalletReceiveReady(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ready != tc.wantReady || hasHistory != tc.wantHistory {
				t.Fatalf("ready=%v hasHistory=%v, want ready=%v hasHistory=%v",
					ready, hasHistory, tc.wantReady, tc.wantHistory)
			}
			if bal != tc.balance {
				t.Fatalf("balance=%d, want %d", bal, tc.balance)
			}
		})
	}
}

// TestWalletReceiveReadyAsksEveryBucket pins the flag interaction. The wallet
// only returns an entry when a REQUESTED bucket matches it, so probing with a
// partial filter can manufacture the very "no history" answer the check is
// supposed to detect. All three buckets must be requested.
func TestWalletReceiveReadyAsksEveryBucket(t *testing.T) {
	f := &fakeWallet{balance: 10002}
	c := f.start(t)
	if _, _, _, err := c.WalletReceiveReady(context.Background()); err != nil {
		t.Fatal(err)
	}

	var params map[string]any
	for _, b := range f.seen {
		if b["method"] == "get_transfers" {
			p, _ := b["params"].(map[string]any)
			params = p
		}
	}
	if params == nil {
		t.Fatalf("no get_transfers call seen; saw %d requests", len(f.seen))
	}
	for _, k := range []string{"in", "out", "coinbase"} {
		if v, ok := params[k].(bool); !ok || !v {
			t.Errorf("get_transfers params %q = %v, want true (a missing bucket can hide history)", k, params[k])
		}
	}
}

// TestWalletReceiveReadyParameterlessCallsSendNull pins the wallet-RPC quirk
// found live: parameterless methods reject an empty object; they want null.
func TestWalletReceiveReadyParameterlessCallsSendNull(t *testing.T) {
	f := &fakeWallet{balance: 5, transfers: `{"entries":[{"height":1}]}`}
	c := f.start(t)
	if _, _, _, err := c.WalletReceiveReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, b := range f.seen {
		if b["method"] != "getbalance" {
			continue
		}
		if v, present := b["params"]; !present || v != nil {
			t.Fatalf("getbalance params = %#v, want explicit null", v)
		}
		return
	}
	t.Fatal("no getbalance call seen")
}

// TestWalletReceiveReadyTransportErrorsAreNotReadiness: a failed call must
// surface as an error, never as "not ready" or "ready". Conflating a transport
// fault with a verdict would make the check lie in both directions.
func TestWalletReceiveReadyTransportErrorsAreNotReadiness(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fakeWallet
	}{
		{"balance error", &fakeWallet{balanceErr: true}},
		{"transfers error", &fakeWallet{balance: 7, transferErr: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.f.start(t)
			ready, hasHistory, _, err := c.WalletReceiveReady(context.Background())
			if err == nil {
				t.Fatalf("want error, got ready=%v hasHistory=%v", ready, hasHistory)
			}
			if ready || hasHistory {
				t.Fatalf("on error want both false, got ready=%v hasHistory=%v", ready, hasHistory)
			}
		})
	}
}

// TestGetTransfersParamsOmitsUnsetBuckets keeps the new Out/Coinbase fields
// from changing what existing callers send: a caller that sets only In must
// still produce {"in":true} and nothing else.
func TestGetTransfersParamsOmitsUnsetBuckets(t *testing.T) {
	b, err := json.Marshal(GetTransfersParams{In: true})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "out") || strings.Contains(got, "coinbase") {
		t.Fatalf("unset buckets leaked into the request: %s", got)
	}
	if !strings.Contains(got, `"in":true`) {
		t.Fatalf("expected in:true, got %s", got)
	}
}
