package main

import (
	"strings"
	"testing"
)

func TestMarshalEscrowNoticeClaim(t *testing.T) {
	raw, err := marshalEscrowNotice("claim",
		"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
		"1122334455667788112233445566778811223344556677881122334455667788",
		"tx-abc", "deal closed", 2500000)
	if err != nil {
		t.Fatal(err)
	}
	kind, summary, ok := parseMoneyEnvelope(raw)
	if !ok || kind != "escrow" {
		t.Fatalf("parseMoneyEnvelope: kind=%q ok=%v", kind, ok)
	}
	if !strings.Contains(summary, "ESCROW CLAIMED") || !strings.Contains(summary, "preimage revealed") {
		t.Fatalf("claim summary = %q", summary)
	}
	rec, ok := parseMoneyRecord(raw)
	if !ok || rec.Kind != "escrow-claim" || rec.TxID != "tx-abc" || rec.Atomic != 2500000 {
		t.Fatalf("parseMoneyRecord = %+v ok=%v", rec, ok)
	}
}

func TestMarshalEscrowNoticeRefund(t *testing.T) {
	raw, err := marshalEscrowNotice("refund",
		"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		"", "tx-def", "expired", 0)
	if err != nil {
		t.Fatal(err)
	}
	kind, summary, ok := parseMoneyEnvelope(raw)
	if !ok || kind != "escrow" {
		t.Fatalf("kind=%q ok=%v", kind, ok)
	}
	if !strings.Contains(summary, "ESCROW REFUNDED") || !strings.Contains(summary, "expired") {
		t.Fatalf("refund summary = %q", summary)
	}
	// A refund must never carry a preimage.
	if strings.Contains(string(raw), "preimage\":") && !strings.Contains(string(raw), "preimage\":\"\"") {
		t.Fatalf("refund envelope carries preimage: %s", raw)
	}
}

func TestMarshalEscrowNoticeValidation(t *testing.T) {
	const h = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	if _, err := marshalEscrowNotice("claim", h, "", "tx", "", 0); err == nil {
		t.Fatal("claim without preimage accepted")
	}
	if _, err := marshalEscrowNotice("claim", h, h, "", "", 0); err == nil {
		t.Fatal("claim without txid accepted")
	}
	if _, err := marshalEscrowNotice("", h, h, "tx", "", 0); err == nil {
		t.Fatal("unknown action accepted")
	}
	if _, err := marshalEscrowNotice("claim", "", h, "tx", "", 0); err == nil {
		t.Fatal("claim without hash accepted")
	}
}
