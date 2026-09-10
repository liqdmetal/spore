package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

// TestPostPayloadAmountAttachesValue pins the pay-with-message send side:
// the exact -amount value lands in the SAME transfer tx as the pointer
// payload — money and message are one atomic object on the wire.
func TestPostPayloadAmountAttachesValue(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"paidtx"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	args := anchor.Arguments{{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)}}
	txid, err := c.PostPayloadAmount(context.Background(), "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq", args, 550000) // 5.5 DERO
	if err != nil {
		t.Fatal(err)
	}
	if txid != "paidtx" {
		t.Fatalf("txid = %q", txid)
	}
	params := gotBody["params"].(map[string]interface{})
	tr := params["transfers"].([]interface{})[0].(map[string]interface{})
	if tr["amount"].(float64) != 550000 {
		t.Fatalf("amount = %v, want 550000 (5.5 DERO attached to the message tx)", tr["amount"])
	}
	if tr["destination"].(string) != "dero1qyhfrd0pgtrwmnec9lzeqv38n4dj3q5zrtqrhqlaxngcucfj5vhnkqq6pn8fq" {
		t.Fatalf("destination = %v", tr["destination"])
	}
	if _, ok := tr["payload_rpc"]; !ok {
		t.Fatal("pointer payload missing from the payment tx")
	}
}

// TestListIncomingSurfacesAmount pins the receive side: the wallet-reported
// per-transfer amount propagates into chain.Incoming.Amount so recv-e2 can
// surface "received N atomic units" alongside the decrypted message.
func TestListIncomingSurfacesAmount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"entries":[
			{"height":42,"topoheight":7594414,"incoming":true,"txid":"tx1","sender":"dero1sender","amount":550000},
			{"height":43,"topoheight":7594415,"incoming":true,"txid":"tx2","sender":"dero1sender2","amount":1}
		]}}`))
	}))
	defer srv.Close()

	b := NewBackend(NewClient(srv.URL, "", ""))
	in, err := b.ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 2 {
		t.Fatalf("entries = %d", len(in))
	}
	if in[0].Amount != 550000 {
		t.Fatalf("tx1 amount = %d, want 550000", in[0].Amount)
	}
	if in[1].Amount != 1 {
		t.Fatalf("tx2 amount = %d, want 1 (postage)", in[1].Amount)
	}
}
