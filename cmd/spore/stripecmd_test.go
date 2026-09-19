package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestStripeBridgeRequestShape: the bridge must talk real Stripe — Basic
// auth with the API key, form-encoded bodies, and the documented call
// sequence (customer → invoiceitems → invoice → finalize).
func TestStripeBridgeRequestShape(t *testing.T) {
	os.Setenv("STRIPE_API_KEY", "sk_test_123")
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "sk_test_123" || pass != "" {
			t.Errorf("bad auth: %q %q ok=%v", user, pass, ok)
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/customers" && r.Method == http.MethodGet:
			w.Write([]byte(`{"data":[]}`))
		case r.URL.Path == "/customers":
			w.Write([]byte(`{"id":"cus_1"}`))
		case r.URL.Path == "/invoiceitems":
			body := r.FormValue("amount")
			if body != "12345" {
				t.Errorf("invoiceitems amount = %q, want 12345 (cents)", body)
			}
			w.Write([]byte(`{"id":"ii_1"}`))
		case r.URL.Path == "/invoices":
			if r.FormValue("collection_method") != "send_invoice" {
				t.Errorf("expected send_invoice collection")
			}
			w.Write([]byte(`{"id":"inv_1"}`))
		case r.URL.Path == "/invoices/inv_1/finalize":
			w.Write([]byte(`{"id":"inv_1","hosted_invoice_url":"https://pay.stripe.com/x","invoice_pdf":"https://pay.stripe.com/p.pdf"}`))
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	os.Setenv("SPORE_STRIPE_BASE", srv.URL)
	defer os.Unsetenv("SPORE_STRIPE_BASE")

	got := captureStdout(func() {
		stripeInvoiceCreate([]string{"-email", "c@x.com", "-amount", "123.45", "-currency", "usd", "-for", "Sept retainer", "-id", "inv-abc"})
	})
	for _, want := range []string{"inv_1", "https://pay.stripe.com/x", "123.45 USD", "inv-abc"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if len(calls) != 5 {
		t.Fatalf("expected 5 API calls (customer GET+create, invoiceitems, invoice, finalize), got %v", calls)
	}
}

// TestStripeBridgeRequiresKey: no key → a clear setup error, not a panic.
func TestStripeBridgeRequiresKey(t *testing.T) {
	os.Unsetenv("STRIPE_API_KEY")
	defer os.Unsetenv("STRIPE_API_KEY")
	_, err := stripeClient()
	if err == nil || !strings.Contains(err.Error(), "STRIPE_API_KEY") {
		t.Fatalf("expected a key-setup error, got %v", err)
	}
}

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
