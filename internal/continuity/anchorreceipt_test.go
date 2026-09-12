package continuity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
	"github.com/liqdmetal/spore/internal/dero"
)

func TestAnchorReceiptRoundTripAndExactBinding(t *testing.T) {
	_, policy, anchor := testChainAnchor(t)
	wire, err := anchor.ToDEROAnchor()
	if err != nil {
		t.Fatal(err)
	}
	packed := []byte("canonical-wire-fixture")
	receipt, err := NewAnchorReceipt(anchor, "tx-1", "dero1destination", 16, 1_800_000_100, DigestAnchorWire(packed))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyAgainst(anchor, "tx-1", "dero1destination", 16, DigestAnchorWire(packed)); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyAgainst(anchor, "tx-2", "dero1destination", 16, DigestAnchorWire(packed)); !errors.Is(err, ErrInvalidAnchorReceipt) {
		t.Fatalf("accepted wrong txid: %v", err)
	}
	if err := receipt.VerifyAgainst(anchor, "tx-1", "dero1destination", 8, DigestAnchorWire(packed)); !errors.Is(err, ErrInvalidAnchorReceipt) {
		t.Fatalf("accepted wrong ringsize: %v", err)
	}
	parsed, err := ParseAnchorReceipt(mustJSON(t, receipt))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TXID != receipt.TXID || parsed.WireDigest != receipt.WireDigest {
		t.Fatalf("receipt changed through JSON: %#v", parsed)
	}
	_ = policy
	_ = wire
}

func TestVerifyAnchorPayloadMatchesWalletReadback(t *testing.T) {
	_, _, expected := testChainAnchor(t)
	wire, err := expected.ToDEROAnchor()
	if err != nil {
		t.Fatal(err)
	}
	packed, err := dero.PackArguments(wire.ToArguments())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewAnchorReceipt(expected, "tx-exact", "dero1destination", 16, 1_800_000_100, DigestAnchorWire(packed))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"jsonrpc": "2.0", "id": "0", "result": map[string]any{"entries": []any{
			map[string]any{"txid": "other", "payload_rpc": anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
			map[string]any{"txid": "tx-exact", "data": append([]byte{0}, packed...)},
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	client := dero.NewClient(server.URL, "", "")
	if err := VerifyAnchorPayload(context.Background(), client, receipt, expected); err != nil {
		t.Fatal(err)
	}

	bad := *receipt
	bad.WireDigest = DigestAnchorWire([]byte("different-wire"))
	if err := VerifyAnchorPayload(context.Background(), client, &bad, expected); !errors.Is(err, ErrInvalidAnchorReceipt) {
		t.Fatalf("accepted mismatched receipt digest: %v", err)
	}
}

func TestAnchorReceiptRejectsAmbiguousAndInvalidData(t *testing.T) {
	_, _, anchor := testChainAnchor(t)
	receipt, err := NewAnchorReceipt(anchor, "tx-1", "dero1destination", 8, 1_800_000_100, DigestAnchorWire([]byte("wire")))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"future":true}`)...)
	if _, err := ParseAnchorReceipt(unknown); err == nil {
		t.Fatal("accepted unknown receipt field")
	}
	duplicate := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"txid":"tx-2"}`)...)
	if _, err := ParseAnchorReceipt(duplicate); err == nil {
		t.Fatal("accepted duplicate receipt field")
	}
	receipt.RingSize = 4
	if err := receipt.Verify(); !errors.Is(err, ErrInvalidAnchorReceipt) {
		t.Fatalf("accepted invalid ringsize: %v", err)
	}
}
