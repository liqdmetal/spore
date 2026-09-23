package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The spore/dex/v1 envelope is the counterparty's view of a relay-dex
// settlement. These pin the wire shape, the validation rules, and the
// in-thread rendering — the ingest side renders whatever these produce.
func TestMarshalDexNotice(t *testing.T) {
	// Swap: pool-settled, no asserted amount.
	raw, err := marshalDexNotice("swap", "tA->tB", 0, "", "tx-1", "for the tools")
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("swap not JSON: %v", err)
	}
	if env["type"] != dexType || env["action"] != "swap" || env["pair"] != "tA->tB" || env["txid"] != "tx-1" {
		t.Fatalf("swap envelope wrong: %v", env)
	}
	if v, ok := env["amount"]; ok && v != "" {
		t.Fatalf("swap must carry no amount, got %v", v)
	}

	// Wrap/unwrap carry the amount in both atomic and display form.
	raw, err = marshalDexNotice("wrap", "dero->wdero", 500000, "5", "tx-2", "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !strings.Contains(string(raw), `"atomic":500000`) || !strings.Contains(string(raw), `"amount":"5"`) {
		t.Fatalf("wrap envelope lost the amount: %s", raw)
	}

	// Validation refusals.
	if _, err := marshalDexNotice("redeem", "a->b", 1, "1", "tx", ""); err == nil {
		t.Fatal("unknown action must refuse")
	}
	if _, err := marshalDexNotice("swap", "", 0, "", "tx", ""); err == nil {
		t.Fatal("empty pair must refuse")
	}
	if _, err := marshalDexNotice("swap", "a->b", 0, "", "", ""); err == nil {
		t.Fatal("empty txid must refuse")
	}
	if _, err := marshalDexNotice("wrap", "dero->wdero", 0, "0", "tx", ""); err == nil {
		t.Fatal("zero-amount wrap must refuse")
	}
}

func TestDexEnvelopeRendersInThread(t *testing.T) {
	cases := []struct {
		action, pair string
		atomic       uint64
		display      string
		want         string
	}{
		{"swap", "tA->tB", 0, "", "DEX SWAPPED tA->tB (pool-settled)"},
		{"wrap", "dero->wdero", 500000, "5", "WRAPPED 5 dero -> wdero"},
		{"unwrap", "wdero->dero", 250000, "2.5", "UNWRAPPED 2.5 wdero -> dero"},
	}
	for _, c := range cases {
		raw, err := marshalDexNotice(c.action, c.pair, c.atomic, c.display, "tx-x", "")
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		kind, summary, ok := parseMoneyEnvelope(raw)
		if !ok || kind != "dex" {
			t.Fatalf("%s: parseMoneyEnvelope kind=%q ok=%v", c.action, kind, ok)
		}
		if !strings.Contains(summary, c.want) || !strings.Contains(summary, "tx ") {
			t.Fatalf("%s: summary %q missing %q", c.action, summary, c.want)
		}
	}
	// Unknown action inside the envelope renders NOTHING (not a money
	// message) — the ingest side must never trust type alone.
	raw, _ := json.Marshal(map[string]string{"type": dexType, "action": "gift", "pair": "a->b", "txid": "t"})
	if _, _, ok := parseMoneyEnvelope(raw); ok {
		t.Fatal("unknown dex action must not parse as a money envelope")
	}
}

func TestDexEnvelopeLedgerRecord(t *testing.T) {
	raw, err := marshalDexNotice("unwrap", "wdero->dero", 250000, "2.5", "tx-9", "settle up")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec, ok := parseMoneyRecord(raw)
	if !ok {
		t.Fatal("dex envelope must produce a ledger record")
	}
	if rec.Kind != "dex-unwrap" || rec.Asset != "dero" || rec.Atomic != 250000 || rec.TxID != "tx-9" {
		t.Fatalf("ledger record wrong: %+v", rec)
	}
	if !strings.Contains(rec.Note, "wdero->dero") || !strings.Contains(rec.Note, "settle up") {
		t.Fatalf("ledger note lost pair/note: %q", rec.Note)
	}
}

// dexAmountAtomic shares the exact big.Int money parser with invoice/pay —
// float arithmetic on money is forbidden — and only accepts the assets that
// wrap here. The asset suffix is REQUIRED, matching the rest of the money
// CLI (unit-explicit money, never a bare number).
func TestDexAmountAtomic(t *testing.T) {
	// DERO has 5 decimals: 5dero = 500000 atomic.
	got, err := dexAmountAtomic("5dero")
	if err != nil || got != 500000 {
		t.Fatalf("5dero = %d, %v", got, err)
	}
	got, err = dexAmountAtomic("2.5dero")
	if err != nil || got != 250000 {
		t.Fatalf("2.5dero = %d, %v", got, err)
	}
	got, err = dexAmountAtomic("2.5wdero")
	if err != nil || got != 250000 {
		t.Fatalf("2.5wdero = %d, %v (suffix is decorative)", got, err)
	}
	// Excess precision must refuse, not truncate: 0.000001 is below the
	// atomic unit.
	if _, err := dexAmountAtomic("0.000001"); err == nil {
		t.Fatal("sub-atomic precision must refuse")
	}
	if _, err := dexAmountAtomic(""); err == nil {
		t.Fatal("empty amount must refuse")
	}
	if _, err := dexAmountAtomic("5"); err == nil {
		t.Fatal("bare number must refuse — the asset suffix is required")
	}
	if _, err := dexAmountAtomic("0"); err == nil {
		t.Fatal("zero amount must refuse")
	}
	if _, err := dexAmountAtomic("5evm"); err == nil {
		t.Fatal("non-dero asset must refuse")
	}
}
