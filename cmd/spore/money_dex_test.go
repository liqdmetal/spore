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
	// Swap: carries its INPUT leg (a zero-deposit swap moves nothing, so a
	// settlement with no amount would claim a zero-value move of money).
	raw, err := marshalDexNotice("swap", "tA->tB", 100000, "1", "tx-1", "for the tools")
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
	if env["amount"] != "1" {
		t.Fatalf("swap must carry its input amount, got %v", env["amount"])
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
		{"swap", "tA->tB", 100000, "1", "DEX SWAPPED tA->tB (pool-settled)"},
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

// dexAmountWithAsset shares the exact big.Int money parser with invoice/pay —
// float arithmetic on money is forbidden. The suffix is REQUIRED (unit-
// explicit money, never a bare number). Every RelayDEX unit mirrors DERO's 5
// decimals (wDERO 1:1, pool tokens likewise), so the numeric part always
// parses as dero; the suffix is reported verbatim so a swap can check it
// names its input token.
func TestDexAmountAtomic(t *testing.T) {
	// DERO has 5 decimals: 5dero = 500000 atomic.
	got, asset, err := dexAmountWithAsset("5dero")
	if err != nil || got != 500000 || asset != "dero" {
		t.Fatalf("5dero = %d,%q, %v", got, asset, err)
	}
	got, asset, err = dexAmountWithAsset("2.5dero")
	if err != nil || got != 250000 || asset != "dero" {
		t.Fatalf("2.5dero = %d,%q, %v", got, asset, err)
	}
	got, asset, err = dexAmountWithAsset("2.5wdero")
	if err != nil || got != 250000 || asset != "wdero" {
		t.Fatalf("2.5wdero = %d,%q, %v", got, asset, err)
	}
	// Excess precision must refuse, not truncate: 0.000001 is below the
	// atomic unit.
	if _, _, err := dexAmountWithAsset("0.000001dero"); err == nil {
		t.Fatal("sub-atomic precision must refuse")
	}
	if _, _, err := dexAmountWithAsset(""); err == nil {
		t.Fatal("empty amount must refuse")
	}
	if _, _, err := dexAmountWithAsset("5"); err == nil {
		t.Fatal("bare number must refuse — the asset suffix is required")
	}
	if _, _, err := dexAmountWithAsset("0"); err == nil {
		t.Fatal("no asset suffix must refuse")
	}
	// A swap's input is an arbitrary RelayDEX token: any asset suffix parses,
	// with DERO's exact decimal math.
	got, asset, err = dexAmountWithAsset("10tA")
	if err != nil || got != 1000000 || asset != "ta" {
		t.Fatalf("10tA = %d,%q, %v (swap inputs name their own token)", got, asset, err)
	}
	got, asset, err = dexAmountWithAsset("7.5TB")
	if err != nil || got != 750000 || asset != "tb" {
		t.Fatalf("7.5TB = %d,%q, %v", got, asset, err)
	}
	// The suffix is a run of letters; a dash inside it is malformed rather
	// than silently truncated.
	if _, _, err := dexAmountWithAsset("7.5T-B"); err == nil {
		t.Fatal("dashed suffix must refuse, not truncate to \"7.5T-\"")
	}
}
