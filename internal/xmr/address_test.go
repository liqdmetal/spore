package xmr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// xmrCreateAddressLiveShape is the answer a v0.18.5.1 wallet gave create_address
// on 2026-10-28, with the address replaced by a stand-in. What the capture
// settled is the SHAPE, and it is not the shape the source struct models:
// `address_index` is a bare minor index, and `addresses` / `address_indices`
// travel beside it. Decoding into the struct shape failed loudly against the real
// wallet, which is why both are accepted here.
const (
	xmrCreateAddressLiveAddress = "8Livefixturesubaddressstandin000000000000000000000000000000000"
	xmrCreateAddressLiveShape   = `{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "address": "` + xmrCreateAddressLiveAddress + `",
    "address_index": 2,
    "address_indices": [2],
    "addresses": ["` + xmrCreateAddressLiveAddress + `"]
  }
}`
)

// The whole point of issuing an address through spore is that the wallet is told
// what the address is FOR, and that exactly one is made: MONERO_SETTLEMENT §3
// forbids reuse across orders and bulk pre-generation. So the request shape is
// the contract, and the live answer is the other half of it.
func TestCreateAddressReadsTheLiveShape(t *testing.T) {
	var method string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("mock wallet got an undecodable request: %v", err)
		}
		method, got = req.Method, req.Params
		_, _ = w.Write([]byte(xmrCreateAddressLiveShape))
	}))
	defer srv.Close()

	addr, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:ord-41")
	if err != nil {
		t.Fatalf("CreateAddress: %v", err)
	}
	if method != "create_address" {
		t.Errorf("called %q, want create_address", method)
	}
	if got["count"] != float64(1) {
		t.Errorf("count = %v, want 1 — bulk pre-generation is exactly what §3 forbids", got["count"])
	}
	if got["account_index"] != float64(0) {
		t.Errorf("account_index = %v, want 0 (the account the poller bills)", got["account_index"])
	}
	if got["label"] != "order:ord-41" {
		t.Errorf("label = %v: the wallet's own label is what a human reads when the ledger and the wallet disagree", got["label"])
	}
	if addr.Address != xmrCreateAddressLiveAddress {
		t.Errorf("address = %q", addr.Address)
	}
	if addr.Index.Major != 0 || addr.Index.Minor != 2 {
		t.Errorf("index = %d/%d, want account 0 (the one asked for) and minor 2", addr.Index.Major, addr.Index.Minor)
	}
}

// The other shape, which the source struct models and an older build sends.
func TestCreateAddressReadsTheIndexObjectShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"address":"8OBJshape","address_index":{"major":0,"minor":7}}}`))
	}))
	defer srv.Close()

	addr, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:x")
	if err != nil {
		t.Fatalf("the {major,minor} shape must still decode: %v", err)
	}
	if addr.Address != "8OBJshape" || addr.Index.Major != 0 || addr.Index.Minor != 7 {
		t.Errorf("answer misread: %+v", addr)
	}
}

// Some answers carry only the arrays. An index that can be read from either
// place is better than refusing an address the wallet just made.
func TestCreateAddressFallsBackToAddressIndices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"address":"8ARRAYonly","address_indices":[5],"addresses":["8ARRAYonly"]}}`))
	}))
	defer srv.Close()

	addr, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:x")
	if err != nil {
		t.Fatalf("CreateAddress: %v", err)
	}
	if addr.Index.Minor != 5 {
		t.Errorf("minor = %d, want 5 from address_indices", addr.Index.Minor)
	}
}

// An answer whose parts disagree is about a different request. Recording it would
// put an address in the ledger that the wallet does not associate with that
// index — the one failure that makes a payment unattributable later.
func TestCreateAddressRejectsADisagreeingAnswer(t *testing.T) {
	cases := map[string]string{
		"address vs addresses[0]": `{"jsonrpc":"2.0","id":1,"result":{"address":"8AAA","address_index":3,"addresses":["8BBB"]}}`,
		"index vs indices[0]":     `{"jsonrpc":"2.0","id":1,"result":{"address":"8AAA","address_index":3,"address_indices":[4]}}`,
		"more than one address":   `{"jsonrpc":"2.0","id":1,"result":{"address":"8AAA","address_index":3,"addresses":["8AAA","8BBB"],"address_indices":[3,4]}}`,
		"no address":              `{"jsonrpc":"2.0","id":1,"result":{"address":"","address_index":3}}`,
		"no index at all":         `{"jsonrpc":"2.0","id":1,"result":{"address":"8AAA"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			if addr, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:x"); err == nil {
				t.Errorf("accepted %s: %+v", name, addr)
			}
		})
	}
}

// A wallet that refuses keeps its own reason: "the wallet is locked" and "no
// account 0" are different afternoons.
func TestCreateAddressKeepsTheWalletsReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Account index out of range"}}`))
	}))
	defer srv.Close()

	_, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:x")
	if err == nil {
		t.Fatal("a refused create_address must be an error")
	}
	if !strings.Contains(err.Error(), "Account index out of range") {
		t.Errorf("the wallet's reason should survive: %v", err)
	}
}

// The disagreement message must name both addresses, or an operator cannot tell
// which one the wallet meant.
func TestCreateAddressDisagreementNamesBothAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		long := strings.Repeat("8", 95)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"address":%q,"address_index":1,"addresses":[%q]}}`,
			long, strings.Repeat("9", 95))
	}))
	defer srv.Close()

	_, err := CreateAddress(context.Background(), srv.URL, "", 0, "order:x")
	if err == nil {
		t.Fatal("disagreeing addresses were accepted")
	}
	if !strings.Contains(err.Error(), "…") {
		t.Errorf("both addresses should be named (abbreviated), got %v", err)
	}
}

// get_address is the reconciliation source, and it has the same shape habit as
// create_address: v0.18.5.1 answers with address OBJECTS carrying a bare
// address_index, a label and a used flag. A decoder that expected strings would
// report an empty wallet — and an empty wallet reads as "nothing to reconcile",
// which is the one wrong answer that looks like agreement.
func TestGetAddressesReadsTheLiveShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "get_address" || req.Params["account_index"] != float64(0) {
			t.Errorf("asked for %q %+v, want get_address on account 0", req.Method, req.Params)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"address":"8PRIMARY","addresses":[
			{"address":"8PRIMARY","address_index":0,"label":"Primary account","used":true},
			{"address":"8ORDERED","address_index":1,"label":"order:ord-1","used":false}]}}`))
	}))
	defer srv.Close()

	addrs, err := GetAddresses(context.Background(), srv.URL, "", 0)
	if err != nil {
		t.Fatalf("GetAddresses: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addrs))
	}
	if addrs[0].Index != 0 || addrs[0].Address != "8PRIMARY" || !addrs[0].Used || addrs[0].Label != "Primary account" {
		t.Errorf("primary misread: %+v", addrs[0])
	}
	if addrs[1].Index != 1 || addrs[1].Address != "8ORDERED" || addrs[1].Used || addrs[1].Label != "order:ord-1" {
		t.Errorf("subaddress misread: %+v", addrs[1])
	}
}

// The other element shape: bare strings, where the array position is the index.
func TestGetAddressesReadsBareStringElements(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"address":"8A","addresses":["8A","8B","8C"]}}`))
	}))
	defer srv.Close()

	addrs, err := GetAddresses(context.Background(), srv.URL, "", 0)
	if err != nil {
		t.Fatalf("GetAddresses: %v", err)
	}
	if len(addrs) != 3 || addrs[2].Index != 2 || addrs[2].Address != "8C" {
		t.Errorf("position is not the index: %+v", addrs)
	}
}

// A missing address_index falls back to the position: dropping the entry instead
// would hide an address from every reconciliation.
func TestGetAddressesFallsBackToPosition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"address":"8A","addresses":[
			{"address":"8A"},{"address":"8B","label":"order:ord-2"}]}}`))
	}))
	defer srv.Close()

	addrs, err := GetAddresses(context.Background(), srv.URL, "", 0)
	if err != nil {
		t.Fatalf("GetAddresses: %v", err)
	}
	if len(addrs) != 2 || addrs[1].Index != 1 || addrs[1].Label != "order:ord-2" {
		t.Errorf("missing index should fall back to position: %+v", addrs)
	}
}

// An empty or shapeless answer is a failure to check, never "no addresses": a
// wallet with zero addresses would make every ledger entry look correct.
func TestGetAddressesRefusesAnEmptyAnswer(t *testing.T) {
	for name, body := range map[string]string{
		"no addresses":   `{"jsonrpc":"2.0","id":1,"result":{"address":"8A"}}`,
		"empty array":    `{"jsonrpc":"2.0","id":1,"result":{"address":"8A","addresses":[]}}`,
		"index no addr":  `{"jsonrpc":"2.0","id":1,"result":{"addresses":[{"address":"","address_index":1}]}}`,
		"not an address": `{"jsonrpc":"2.0","id":1,"result":{"address":"8A","addresses":[42]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			if addrs, err := GetAddresses(context.Background(), srv.URL, "", 0); err == nil {
				t.Errorf("accepted %s: %+v", name, addrs)
			}
		})
	}
}
