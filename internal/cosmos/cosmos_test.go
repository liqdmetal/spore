package cosmos

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/liqdmetal/spore/internal/chain"
)

func TestPostPayloadSerializesConfiguredMessage(t *testing.T) {
	var body string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		body = string(b[:n])
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"txhash":"abc"}`))
	}))
	defer s.Close()
	b := New(Config{ChainID: "cosmoshub-4", BaseURL: s.URL, PostPath: "/post", MessageField: "memo", RecipientField: "to", DeliveryGuaranteed: true})
	p := canonicalPointer()
	if _, err := b.PostPayload(context.Background(), "cosmos1recipient", p, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"memo":"`+hex.EncodeToString(p)+`"`) || !strings.Contains(body, `"to":"cosmos1recipient"`) {
		t.Fatalf("payload = %s", body)
	}
}

func TestListRejectsMalformedMemoAndFiltersRecipient(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"height":7,"messages":[{"tx_id":"1","to":"me","memo":"bad"},{"tx_id":"2","to":"other","memo":"` + hex.EncodeToString(canonicalPointer()) + `"},{"tx_id":"3","to":"me","memo":"` + hex.EncodeToString(canonicalPointer()) + `"}]}`))
	}))
	defer s.Close()
	b := New(Config{ChainID: "x", BaseURL: s.URL, ListPath: "/list", AddressValue: "me"})
	got, err := b.ListIncoming(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TxID != "3" {
		t.Fatalf("got %#v", got)
	}
}

func TestContextCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	b := New(Config{ChainID: "x", BaseURL: s.URL, HeightPath: "/height", Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Height(ctx); err == nil {
		t.Fatal("expected cancellation")
	}
}

func canonicalPointer() chain.Payload {
	p := make([]byte, PointerSize)
	p[0] = 1
	// The canonical pointer layout is: version, flags, route, CID, deadline.
	for i := 0; i < 32; i++ {
		p[2+i] = byte(i + 1)
		p[34+i] = byte(0xa0 + i)
	}
	binary.LittleEndian.PutUint64(p[66:74], 1)
	return chain.Payload(p)
}
