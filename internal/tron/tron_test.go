package tron

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

// validV1 / validV2 build a well-formed pointer of each version: correct
// version byte, zero reserved byte, and a nonzero deadline at [66:74].
func validV1() []byte {
	p := make([]byte, PointerV1Size)
	p[0] = PointerV1Version
	p[deadlineOffset] = 7 // nonzero burn deadline (TTL anchor)
	return p
}

func validV2() []byte {
	p := make([]byte, PointerV2Size)
	p[0] = PointerV2Version
	p[deadlineOffset] = 9
	return p
}

// TestAcceptsBothPointerVersions is the core difference from TON: V2 (106 B)
// must round-trip, or the portable-locator path is unreachable on Tron.
func TestAcceptsBothPointerVersions(t *testing.T) {
	for name, p := range map[string][]byte{"v1": validV1(), "v2": validV2()} {
		t.Run(name, func(t *testing.T) {
			s, err := EncodeComment(p)
			if err != nil {
				t.Fatalf("encode %s: %v", name, err)
			}
			got, err := ParseComment(s)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if string(got) != string(p) {
				t.Fatalf("%s pointer changed through round-trip", name)
			}
		})
	}
	// Documented memo sizes: V1 -> 100 chars, V2 -> 144 chars.
	if v1, _ := EncodeComment(validV1()); len(v1) != 100 {
		t.Fatalf("v1 memo len = %d, want 100", len(v1))
	}
	if v2, _ := EncodeComment(validV2()); len(v2) != 144 {
		t.Fatalf("v2 memo len = %d, want 144", len(v2))
	}
}

func TestEncodeRejectsInvalidPointers(t *testing.T) {
	cases := map[string][]byte{
		"zero deadline v1": make([]byte, PointerV1Size),
		"zero deadline v2": make([]byte, PointerV2Size),
		"wrong version":    append([]byte{3, 0}, make([]byte, PointerV1Size-2)...),
		"v1 len v2 version": func() []byte {
			p := make([]byte, PointerV1Size)
			p[0] = PointerV2Version
			p[deadlineOffset] = 1
			return p
		}(),
		"v2 len v1 version": func() []byte {
			p := make([]byte, PointerV2Size)
			p[0] = PointerV1Version
			p[deadlineOffset] = 1
			return p
		}(),
		"reserved byte set": func() []byte { p := validV1(); p[1] = 1; return p }(),
		"bad length":        make([]byte, 73),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := EncodeComment(p); err == nil {
				t.Fatalf("accepted invalid pointer: %s", name)
			}
		})
	}
}

func TestParseIsStrictAndCanonical(t *testing.T) {
	good, err := EncodeComment(validV1())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseComment(good + "x"); err == nil {
		t.Fatal("accepted trailing data")
	}
	if _, err := ParseComment(good[:len(good)-1]); err == nil {
		t.Fatal("accepted truncated memo")
	}
	// Unpadded base64 of a valid pointer is non-canonical -> refused.
	unpadded := base64.RawStdEncoding.EncodeToString(validV1())
	if _, err := ParseComment(unpadded); err == nil {
		t.Fatal("accepted non-canonical (unpadded) base64")
	}
	// Mutations that keep the right length but break the shape.
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong version": func(q []byte) []byte { q[0] = 9; return q },
		"reserved byte": func(q []byte) []byte { q[1] = 1; return q },
		"zero deadline": func(q []byte) []byte {
			for i := deadlineOffset; i < deadlineOffset+8; i++ {
				q[i] = 0
			}
			return q
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := mutate(validV1())
			if _, err := ParseComment(base64.StdEncoding.EncodeToString(q)); err == nil {
				t.Fatalf("accepted malformed pointer: %s", name)
			}
		})
	}
}

// TestPointerOnlyRejectsPlaintextMemo proves a human-readable memo (no pointer)
// never parses: the carrier is pointer-only, body never rides the chain.
func TestPointerOnlyRejectsPlaintextMemo(t *testing.T) {
	for _, s := range []string{"hello world", "", base64.StdEncoding.EncodeToString([]byte("not a pointer, just text"))} {
		if _, err := ParseComment(s); !errors.Is(err, ErrMalformedComment) {
			t.Fatalf("plaintext memo %q accepted or wrong error: %v", s, err)
		}
	}
}

// TestNoBurnPrimitive locks the design invariant: Tron has no erase primitive,
// so the backend must NOT implement chain.Burner (that would be a false claim).
func TestNoBurnPrimitive(t *testing.T) {
	var c chain.Chain = New(Config{})
	if _, ok := c.(chain.Burner); ok {
		t.Fatal("tron backend must not implement chain.Burner; a transfer memo is immutable")
	}
}

func memoHex(p []byte) string {
	s, _ := EncodeComment(p)
	return hex.EncodeToString([]byte(s))
}

func TestListFiltersRecipientSelfAndCarriesPointer(t *testing.T) {
	body := `{"data":[
		{"txID":"h","block_timestamp":3,"raw_data":{"data":"` + memoHex(validV2()) + `","contract":[{"type":"TransferContract","parameter":{"value":{"amount":1,"owner_address":"Tsender","to_address":"Tme"}}}]}},
		{"txID":"wrongto","block_timestamp":4,"raw_data":{"data":"` + memoHex(validV1()) + `","contract":[{"type":"TransferContract","parameter":{"value":{"owner_address":"Tsender","to_address":"Tother"}}}]}},
		{"txID":"self","block_timestamp":5,"raw_data":{"data":"` + memoHex(validV1()) + `","contract":[{"type":"TransferContract","parameter":{"value":{"owner_address":"Tme","to_address":"Tme"}}}]}},
		{"txID":"notpointer","block_timestamp":6,"raw_data":{"data":"` + hex.EncodeToString([]byte("just a note")) + `","contract":[{"type":"TransferContract","parameter":{"value":{"owner_address":"Tsender","to_address":"Tme"}}}]}}
	]}`
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(body))
	}))
	defer s.Close()
	b := New(Config{Address: "Tme", Network: "mainnet", BaseURL: s.URL, PostPath: "/send", ListPath: "/list", HeightPath: "/height", HTTPClient: s.Client()})
	got, err := b.ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TxID != "h" {
		t.Fatalf("got %#v, want only tx h", got)
	}
	if got[0].Sender != "Tsender" || len(got[0].Payload) != PointerV2Size {
		t.Fatalf("unexpected incoming: %#v", got[0])
	}
}

func TestListHonorsMinCursor(t *testing.T) {
	body := `{"data":[{"txID":"old","block_timestamp":2,"raw_data":{"data":"` + memoHex(validV1()) + `","contract":[{"type":"TransferContract","parameter":{"value":{"owner_address":"Tsender","to_address":"Tme"}}}]}}]}`
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer s.Close()
	b := New(Config{Address: "Tme", Network: "mainnet", BaseURL: s.URL, PostPath: "/send", ListPath: "/list", HeightPath: "/height", HTTPClient: s.Client()})
	got, err := b.ListIncoming(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("min cursor not honored: %#v", got)
	}
}

func TestValidateConfigRejectsBadProfiles(t *testing.T) {
	base := Config{Address: "Tme", Network: "mainnet", BaseURL: "https://api.trongrid.io", PostPath: "/p", ListPath: "/l", HeightPath: "/h"}
	ok := New(base)
	if err := ok.validateConfig(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]Config{
		"bad network":   {Address: "Tme", Network: "nope", BaseURL: "https://x", PostPath: "/p", ListPath: "/l", HeightPath: "/h"},
		"no address":    {Address: "", Network: "mainnet", BaseURL: "https://x", PostPath: "/p", ListPath: "/l", HeightPath: "/h"},
		"userinfo url":  {Address: "Tme", Network: "mainnet", BaseURL: "https://user:pass@x", PostPath: "/p", ListPath: "/l", HeightPath: "/h"},
		"non-http url":  {Address: "Tme", Network: "mainnet", BaseURL: "ftp://x", PostPath: "/p", ListPath: "/l", HeightPath: "/h"},
		"missing paths": {Address: "Tme", Network: "mainnet", BaseURL: "https://x"},
	}
	for name, cfg := range bad {
		t.Run(name, func(t *testing.T) {
			if err := New(cfg).validateConfig(); err == nil {
				t.Fatalf("accepted bad config: %s", name)
			}
		})
	}
}

func TestPostRefusesWithoutDeliveryGuarantee(t *testing.T) {
	b := New(Config{Address: "Tme", Network: "mainnet", BaseURL: "https://x", PostPath: "/p", ListPath: "/l", HeightPath: "/h"})
	_, err := b.PostPayload(context.Background(), "Tme", validV1(), 0)
	if !errors.Is(err, ErrDeliveryNotGuaranteed) {
		t.Fatalf("expected delivery-not-guaranteed, got %v", err)
	}
}

type fakeSender struct {
	gotTo, gotMemo string
}

func (f *fakeSender) Send(_ context.Context, to, memo string) (string, error) {
	f.gotTo, f.gotMemo = to, memo
	return "txid-1", nil
}

func TestPostSendsExactMemo(t *testing.T) {
	fs := &fakeSender{}
	b := New(Config{Address: "Tme", Network: "mainnet", BaseURL: "https://x", PostPath: "/p", ListPath: "/l", HeightPath: "/h", DeliveryGuaranteed: true, Sender: fs})
	res, err := b.PostPayload(context.Background(), "Tme", validV2(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.TxID != "txid-1" {
		t.Fatalf("txid = %q", res.TxID)
	}
	want, _ := EncodeComment(validV2())
	if fs.gotMemo != want || fs.gotTo != "Tme" {
		t.Fatalf("sender got to=%q memo=%q", fs.gotTo, fs.gotMemo)
	}
}

func TestHTTPHonorsCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	b := New(Config{Address: "Tme", Network: "mainnet", BaseURL: s.URL, PostPath: "/p", ListPath: "/l", HeightPath: "/h", HTTPClient: s.Client()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := b.Height(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

var _ chain.Chain = (*Backend)(nil)
