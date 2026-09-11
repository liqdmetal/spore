package dero

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/anchor"
)

func TestSporeRingPolicy(t *testing.T) {
	for _, ring := range []uint64{8, 16} {
		if err := ValidateSporeRingSize(ring); err != nil {
			t.Fatalf("ring %d rejected: %v", ring, err)
		}
	}
	for _, ring := range []uint64{0, 2, 4, 9, 32, 128} {
		if err := ValidateSporeRingSize(ring); err == nil {
			t.Fatalf("ring %d accepted", ring)
		}
	}
	if DefaultSporeRingSize != 16 {
		t.Fatalf("default ring = %d, want 16", DefaultSporeRingSize)
	}
}

func TestSporeBackendPostsSelectedRing(t *testing.T) {
	var gotRing float64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Ringsize uint64 `json:"ringsize"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		gotRing = float64(req.Params.Ringsize)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"txid":"ring-test"}}`))
	}))
	defer srv.Close()

	b := NewBackend(NewClient(srv.URL, "", ""))
	if err := b.SetSporeRingSize(8); err != nil {
		t.Fatal(err)
	}
	payload, err := ArgsToPayload(anchor.Arguments{{Name: "K", DataType: anchor.DataHash, Value: "0100000000000000000000000000000000000000000000000000000000000000"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.PostPayload(context.Background(), "dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4", payload, 1); err != nil {
		t.Fatal(err)
	}
	if gotRing != 8 {
		t.Fatalf("posted ring = %.0f, want 8", gotRing)
	}
}

func TestPayloadCodecRejectsUnsafeNumericCoercion(t *testing.T) {
	for _, payload := range []string{
		`{"a":[{"n":"D","t":"U","v":"1.5"}]}`,
		`{"a":[{"n":"D","t":"U","v":"18446744073709551616"}]}`,
	} {
		if _, err := PayloadToArgs([]byte(payload)); err == nil {
			t.Fatalf("accepted invalid uint payload %s", payload)
		}
	}
}

func TestPayloadCodecRejectsUnknownTypesAndMissingEnvelope(t *testing.T) {
	for _, payload := range []string{
		`{"a":[{"n":"D","t":"X","v":"1"}]}`,
		`{"a":null}`,
		`{}`,
	} {
		if _, err := PayloadToArgs([]byte(payload)); err == nil {
			t.Fatalf("accepted malformed payload %s", payload)
		}
	}
}

func TestPayloadCodecRejectsUnsafeFloatCoercion(t *testing.T) {
	for _, value := range []string{"1.5", "18446744073709551616"} {
		payload := []byte(`{"a":[{"n":"D","t":"U","v":` + value + `}]}`)
		if _, err := PayloadToArgs(payload); err == nil {
			t.Fatalf("accepted unsafe numeric payload %s", payload)
		}
	}
}

func TestPayloadCodecRoundTripsSupportedArguments(t *testing.T) {
	args := anchor.Arguments{
		{Name: "W", DataType: anchor.DataUint64, Value: uint64(0xE220)},
		{Name: "S", DataType: anchor.DataString, Value: "hello"},
	}
	wire, err := ArgsToPayload(args)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PayloadToArgs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(args) || got[0].Value != uint64(0xE220) || got[1].Value != "hello" {
		t.Fatalf("round trip = %#v", got)
	}
}
