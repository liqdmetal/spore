package main

import (
	"strings"
	"testing"
)

func TestReceiptEnvelopeRoundTrip(t *testing.T) {
	b, err := marshalReceipt("tx-abc-123", "delivered")
	if err != nil {
		t.Fatal(err)
	}
	inReplyTo, status, ok := parseReceipt(b)
	if !ok || inReplyTo != "tx-abc-123" || status != "delivered" {
		t.Fatalf("round trip = (%q, %q, %v)", inReplyTo, status, ok)
	}
}

func TestReceiptEnvelopeDetectsReadStatus(t *testing.T) {
	b, err := marshalReceipt("tx-xyz", "read")
	if err != nil {
		t.Fatal(err)
	}
	_, status, ok := parseReceipt(b)
	if !ok || status != "read" {
		t.Fatalf("got (%q, %v)", status, ok)
	}
}

func TestParseReceiptRejectsPlaintext(t *testing.T) {
	for _, b := range []string{
		"hello world",
		"",
		"not json {",
		`{"type":"spore/message/v1","in_reply_to":"x"}`,
		`{"in_reply_to":"x","status":"delivered"}`,
	} {
		if _, _, ok := parseReceipt([]byte(b)); ok {
			t.Errorf("parseReceipt(%q) accepted non-receipt", b)
		}
	}
}

func TestParseReceiptRejectsGarbageJSON(t *testing.T) {
	// Valid JSON, wrong shape entirely.
	if _, _, ok := parseReceipt([]byte(`[1,2,3]`)); ok {
		t.Fatal("accepted array")
	}
}

func TestReceiptIsStableJSON(t *testing.T) {
	b, err := marshalReceipt("a", "delivered")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, `{"type":"spore/receipt/v1"`) {
		t.Fatalf("receipt envelope lacks stable type prefix: %s", s)
	}
}
