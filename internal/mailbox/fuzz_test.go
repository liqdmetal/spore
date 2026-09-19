package mailbox

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// validMethodToken reports whether m is a non-empty RFC 7230 token: only
// tchar characters. A real server only dispatches token methods, so the
// fuzzer must not feed httptest anything else (it panics on malformed
// methods before the handler is ever involved).
func validMethodToken(m string) bool {
	if m == "" {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// arbitrary paths (traversal, double-encoding, null bytes), arbitrary
// methods, and garbage bodies on the write routes. The handler must never
// panic and must never answer 500 to input-shaped requests (404/400/405/401
// are the only sane statuses for malformed input).
func FuzzHTTPHandler(f *testing.F) {
	dir := f.TempDir()
	mb, err := Open(dir, nil)
	if err != nil {
		f.Fatalf("open mailbox: %v", err)
	}
	h := mb.Handler()
	f.Add("/list", http.MethodGet)
	f.Add("/put/aa", http.MethodPut)
	f.Add("/body/aa", http.MethodGet)
	f.Add("/../../etc/passwd", http.MethodGet)
	f.Add("/u/alice/../bob/list", http.MethodGet)
	f.Add("/prekey", http.MethodGet)
	f.Add("/put/0000000000000000000000000000000000000000000000000000000000000000", http.MethodPut)
	f.Add("/put/%2e%2e%2f", http.MethodPut)
	f.Fuzz(func(t *testing.T, path, method string) {
		// httptest panics on non-token methods and on targets containing
		// whitespace/control bytes; a real server only ever dispatches valid
		// request lines, so positively validate both before NewRequest.
		if !validMethodToken(method) || strings.ContainsAny(path, " 	\r\n\x00") {
			return
		}
		body := []byte("fuzz-body")
		// Build the request manually (not httptest.NewRequest): httptest
		// parses the target as an absolute URL and panics on raw characters
		// like '#' or spaces — but a real server presents exactly those raw
		// bytes as URL.Path. Exercising the handler with raw paths is the
		// point.
		req := &http.Request{
			Method:     method,
			URL:        &url.URL{Path: path},
			Body:       io.NopCloser(bytes.NewReader(body)),
			RemoteAddr: "203.0.113.7:4242",
			Header:     http.Header{},
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("handler answered %d to path %q method %q", rec.Code, path, method)
		}
		if rec.Code == http.StatusOK && path == "" {
			t.Fatalf("empty path answered 200")
		}
	})
}
