package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestPostPayloadRejectsR153OversizeBeforeRPC(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"unexpected"}}`))
	}))
	defer srv.Close()

	payload := anchor.Arguments{{Name: "T", DataType: anchor.DataString, Value: string(make([]byte, 200))}}
	_, err := NewClient(srv.URL, "", "").PostPayloadAmountWithRing(context.Background(), "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4", payload, 1, 2)
	if err == nil {
		t.Fatal("accepted payload that exceeds R153 packed limit")
	}
	if calls != 0 {
		t.Fatalf("wallet RPC called %d times after local wire-limit rejection", calls)
	}
}

func TestPostPayloadAcceptsR153SizedPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"ok"}}`))
	}))
	defer srv.Close()

	payload := anchor.Arguments{{Name: "T", DataType: anchor.DataString, Value: "ok"}}
	got, err := NewClient(srv.URL, "", "").PostPayloadAmountWithRing(context.Background(), "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4", payload, 1, 2)
	if err != nil || got != "ok" {
		t.Fatalf("got txid=%q err=%v", got, err)
	}
}
