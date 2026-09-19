package ratchetwire_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

func TestLiveDEROShapePreservesUintValues(t *testing.T) {
	const response = `{"jsonrpc":"2.0","id":"1","result":{"entries":[{"height":7594400,"topoheight":7594414,"txid":"live-tx","amount":1,"incoming":true,"payload_rpc":[{"name":"C","datatype":"H","value":"0f766b4482ab0c400003631ff5e5ab6e1bdcc4ed2d76f0ad8a0a93452791775e"},{"name":"D","datatype":"U","value":1788969051},{"name":"R","datatype":"H","value":"301ed2dae1ef717d5e6ef786435e21d535d3ab43a7a2d2dd697f84d15bc0d6e1"},{"name":"W","datatype":"U","value":57888}]}]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(response)) }))
	defer srv.Close()

	b := dero.NewBackend(dero.NewClient(srv.URL, "", ""))
	got, err := b.ListIncoming(context.Background(), 7594000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	p, ok := (ratchetwire.DeroChainCodec{}).DecodePointer(got[0].Payload)
	if !ok {
		t.Fatalf("live DERO pointer did not decode: %s", got[0].Payload)
	}
	if p.CID[0] != 0x0f || p.Route[0] != 0x30 || p.BurnDeadline != 1788969051 {
		t.Fatalf("wrong pointer: cid=%x route=%x deadline=%d", p.CID[:2], p.Route[:2], p.BurnDeadline)
	}
}
