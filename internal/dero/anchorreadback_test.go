package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestGetTransferPayloadsFiltersAndDecodesExactTXID(t *testing.T) {
	payload := anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, {Name: "C", DataType: anchor.DataHash, Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, {Name: "D", DataType: anchor.DataUint64, Value: uint64(123)}, {Name: "F", DataType: anchor.DataUint64, Value: uint64(1 | uint64(anchor.KindContinuity)<<8)}}
	rawPayload, err := PackArguments(payload)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"jsonrpc": "2.0", "id": "0", "result": map[string]any{"entries": []any{
			map[string]any{"txid": "other", "payload_rpc": payload},
			map[string]any{"txid": "wanted", "payload_rpc": payload},
			map[string]any{"txid": "wanted", "data": append([]byte{0}, rawPayload...)},
		}}}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	client := NewClient(srv.URL, "", "")
	got, err := client.GetTransferPayloads(context.Background(), "wanted")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("payload count = %d, want 2", len(got))
	}
	if _, err := client.GetTransferPayloads(context.Background(), "missing"); err == nil {
		t.Fatal("missing txid unexpectedly succeeded")
	}
}
