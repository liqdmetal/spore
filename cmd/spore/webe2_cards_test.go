package main

import (
	"strings"
	"testing"
	"time"
)

// classifyWebPlain is the browser inbox's only view of typed plaintexts: the
// CLI ingest pipeline (e2ingest.go) classifies receipts and money envelopes,
// and the web path must agree exactly. A divergence here means the CLI prints
// "ESCROW CLAIMED …" while the browser shows raw JSON (or worse, treats a
// settlement like an ordinary chat line).
func TestClassifyWebPlain(t *testing.T) {
	const hash = "6b1869a76b5f5f1e0c3d4c0f9a2b1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
	const preimage = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

	t.Run("escrow claim", func(t *testing.T) {
		raw, err := marshalEscrowNotice("claim", hash, preimage, "settle-tx-1", "note", 120000)
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "escrow" {
			t.Fatalf("kind = %q, want escrow", c.Kind)
		}
		if c.Direction != "received" {
			t.Errorf("direction = %q, want received", c.Direction)
		}
		if !strings.Contains(c.Summary, "ESCROW CLAIMED") {
			t.Errorf("summary %q lacks ESCROW CLAIMED", c.Summary)
		}
		if c.Amount != "1.2" || c.Asset != "dero" {
			t.Errorf("amount/asset = %q/%q, want 1.2/dero", c.Amount, c.Asset)
		}
		if c.Txid != "settle-tx-1" {
			t.Errorf("txid = %q, want settle-tx-1", c.Txid)
		}
		if c.InReplyTo != "" {
			t.Errorf("in_reply_to = %q, want empty on a money envelope", c.InReplyTo)
		}
	})

	t.Run("escrow refund", func(t *testing.T) {
		raw, err := marshalEscrowNotice("refund", hash, "", "settle-tx-2", "", 120000)
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "escrow" || !strings.Contains(c.Summary, "ESCROW REFUNDED") {
			t.Fatalf("kind/summary = %q/%q, want escrow/ESCROW REFUNDED", c.Kind, c.Summary)
		}
	})

	t.Run("dex swap carries its input leg", func(t *testing.T) {
		raw, err := marshalDexNotice("swap", "tA->tB", 100000, "1", "dex-tx-1", "")
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "dex" {
			t.Fatalf("kind = %q, want dex", c.Kind)
		}
		if !strings.Contains(c.Summary, "DEX SWAPPED") {
			t.Errorf("summary %q lacks DEX SWAPPED", c.Summary)
		}
		if c.Amount != "1" {
			t.Errorf("amount = %q, want 1 (the swap input leg)", c.Amount)
		}
		if c.Txid != "dex-tx-1" {
			t.Errorf("txid = %q, want dex-tx-1", c.Txid)
		}
	})

	t.Run("dex wrap carries display amount", func(t *testing.T) {
		raw, err := marshalDexNotice("wrap", "dero->wdero", 500000, "5", "wrap-tx-1", "")
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "dex" || c.Amount != "5" {
			t.Fatalf("kind/amount = %q/%q, want dex/5", c.Kind, c.Amount)
		}
	})

	t.Run("payment", func(t *testing.T) {
		raw, err := marshalPayment("inv-x", "dero", 550000, "pay-tx-1", "thanks")
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "payment" {
			t.Fatalf("kind = %q, want payment", c.Kind)
		}
		if c.Amount != "5.5" || c.Asset != "dero" {
			t.Errorf("amount/asset = %q/%q, want 5.5/dero", c.Amount, c.Asset)
		}
		if c.Txid != "pay-tx-1" {
			t.Errorf("txid = %q, want pay-tx-1", c.Txid)
		}
	})

	t.Run("invoice", func(t *testing.T) {
		raw, _, err := marshalInvoice("dero", "2.5", "lunch", time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "invoice" {
			t.Fatalf("kind = %q, want invoice", c.Kind)
		}
		if c.Amount != "2.5" {
			t.Errorf("amount = %q, want 2.5", c.Amount)
		}
		if !strings.Contains(c.Summary, "INVOICE") {
			t.Errorf("summary %q lacks INVOICE", c.Summary)
		}
	})

	t.Run("receipt is an ack, not money", func(t *testing.T) {
		raw, err := marshalReceipt("orig-tx-9", "delivered")
		if err != nil {
			t.Fatal(err)
		}
		c := classifyWebPlain(raw)
		if c.Kind != "receipt" {
			t.Fatalf("kind = %q, want receipt", c.Kind)
		}
		if c.InReplyTo != "orig-tx-9" {
			t.Errorf("in_reply_to = %q, want orig-tx-9", c.InReplyTo)
		}
		if c.Direction != "" {
			t.Errorf("direction = %q, want empty on a receipt", c.Direction)
		}
		if c.Amount != "" || c.Asset != "" {
			t.Errorf("receipt must carry no money fields, got %q/%q", c.Amount, c.Asset)
		}
	})

	t.Run("ordinary plaintext is not a card", func(t *testing.T) {
		for _, b := range [][]byte{
			[]byte("see you at the meeting"),
			[]byte("{not json"),
			[]byte(`{"type":"text/plain"}`),
			[]byte(`{"type":"` + escrowType + `","txid":""}`), // invalid envelope: no txid
			nil,
		} {
			if c := classifyWebPlain(b); c.Kind != "" {
				t.Errorf("classifyWebPlain(%q) = kind %q, want none", b, c.Kind)
			}
		}
	})
}
