package dero

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoArgMethodsDoNotSendEmptyParams pins the wire shape the R153 wallet will
// accept for parameterless methods.
//
// Measured against a live R153 wallet:
//
//	params:null    -> OK
//	params:{}      -> {"code":-32602,"message":"no parameters accepted"}
//	params missing -> OK
//
// So an empty JSON OBJECT is rejected outright. The httptest fakes used by the
// rest of this package answer regardless of the request body, which is exactly
// why an earlier `struct{}{}` regression passed the whole suite while
// getaddress/getheight failed against a real wallet. This test inspects the raw
// body instead of trusting the handler's tolerance, so the regression cannot
// come back silently.
func TestNoArgMethodsDoNotSendEmptyParams(t *testing.T) {
	type probe struct {
		method string
		call   func(*Client) error
	}
	probes := []probe{
		{"getaddress", func(c *Client) error { _, err := c.GetAddress(context.Background()); return err }},
		{"getheight", func(c *Client) error { _, err := c.GetHeight(context.Background()); return err }},
	}

	for _, p := range probes {
		var body string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"0","result":{"address":"dero1x","height":1}}`))
		}))

		if err := p.call(NewClient(srv.URL, "", "")); err != nil {
			srv.Close()
			t.Fatalf("%s: %v", p.method, err)
		}
		srv.Close()

		if !strings.Contains(body, `"method":"`+p.method+`"`) {
			t.Fatalf("%s: unexpected request body %s", p.method, body)
		}
		// The rejected shape is an empty object. Absent or null are both fine.
		if strings.Contains(body, `"params":{}`) {
			t.Fatalf("%s sends params:{} which a live R153 wallet rejects with "+
				"no parameters accepted (body: %s)", p.method, body)
		}
	}
}
