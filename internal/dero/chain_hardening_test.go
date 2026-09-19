package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListIncomingRejectsEmptyTXID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"entries":[{"height":1,"txid":""},{"height":2,"txid":"ok"}]}}`))
	}))
	defer srv.Close()

	in, err := NewBackend(NewClient(srv.URL, "", "")).ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 1 || in[0].TxID != "ok" {
		t.Fatalf("incoming = %#v", in)
	}
}

func TestPayloadEnvelopeRejectsTrailingAndUnknownFields(t *testing.T) {
	for _, p := range []string{
		`{"a":[{"n":"W","t":"U","v":"1"}]} {"a":[]}`,
		`{"a":[{"n":"W","t":"U","v":"1","extra":true}]}`,
	} {
		if _, err := PayloadToArgs([]byte(p)); err == nil {
			t.Fatalf("accepted malformed envelope %q", p)
		}
	}
}

func TestGetTransfersR153ShapeIncludesBlockHeight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"entries":[{"height":123,"topoheight":456,"txid":"tx"}]}}`))
	}))
	defer srv.Close()

	entries, err := NewClient(srv.URL, "", "").GetTransfers(context.Background(), GetTransfersParams{In: true, MinHeight: 123})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Height != 123 || entries[0].TopoHeight != 456 {
		t.Fatalf("entries = %#v", entries)
	}
}
