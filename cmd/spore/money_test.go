package main

import (
	"strings"
	"testing"
)

func TestParseAmountExact(t *testing.T) {
	cases := []struct {
		asset, num string
		want       uint64
	}{
		{"dero", "1", 100000},
		{"dero", "5.5", 550000},
		{"dero", "0.00001", 1},
		{"xmr", "1", 1000000000000},
		{"xmr", "0.000000000001", 1}, // one piconero: the smallest unit Monero has
		{"monero", "2.5", 2500000000000},
		{"btc", "0.00000001", 1},
		{"evm", "0.000000000000000001", 1},
		{"ton", "1.5", 1500000000},
		{"sol", "2", 2000000000},
	}
	for _, c := range cases {
		got, err := parseAmount(c.asset, c.num)
		if err != nil || got != c.want {
			t.Errorf("parseAmount(%s, %s) = %d, %v; want %d", c.asset, c.num, got, err, c.want)
		}
	}
}

func TestParseAmountRejects(t *testing.T) {
	bad := []struct{ asset, num string }{
		{"doge", "1"},                       // unknown asset: never guess units
		{"dero", "0.000001"},                // beyond DERO's 5-decimal precision: reject, don't truncate
		{"xmr", "0.0000000000001"},          // sub-piconero: 13 decimals, cannot be sent on Monero at all
		{"dero", "-1"},                      // negative
		{"dero", "0"},                       // zero
		{"dero", ""},                        // empty
		{"dero", "abc"},                     // garbage
		{"dero", "99999999999999999999999"}, // uint64 overflow
	}
	for _, c := range bad {
		if _, err := parseAmount(c.asset, c.num); err == nil {
			t.Errorf("parseAmount(%s, %s) accepted invalid input", c.asset, c.num)
		}
	}
}

func TestFormatAmountRoundTrip(t *testing.T) {
	cases := []struct {
		asset string
		atom  uint64
		want  string
	}{
		{"dero", 100000, "1"},
		{"dero", 550000, "5.5"},
		{"dero", 1, "0.00001"},
		{"xmr", 1000000000000, "1"},
		{"xmr", 1, "0.000000000001"},
		// 2^53+1 piconero (9007.199254740993 XMR) is the first amount a float64
		// cannot hold: the float path would render ...992 and move 1 piconero
		// less money than the record says. This case is the reason the
		// formatter goes through big.Int.
		{"xmr", 9007199254740993, "9007.199254740993"},
		{"btc", 100000000, "1"},
		{"evm", 1, "0.000000000000000001"},
	}
	for _, c := range cases {
		if got := formatAmount(c.asset, c.atom); got != c.want {
			t.Errorf("formatAmount(%s, %d) = %q, want %q", c.asset, c.atom, got, c.want)
		}
	}
}

// TestXRMPiconeroExactness pins the round trip that matters for Monero: the
// widest atomic unit in the table, with no float anywhere in the path. Monero
// itself reports integer piconero, so parse and format must agree at every
// boundary — including the 2^53 one above.
func TestXRMPiconeroExactness(t *testing.T) {
	for _, amt := range []string{"0.000000000001", "0.000000000002", "1", "9007.199254740993", "18446744.073709551615"} {
		atomic, err := parseAmount("xmr", amt)
		if err != nil {
			t.Fatalf("parseAmount(xmr, %s): %v", amt, err)
		}
		if got := formatAmount("xmr", atomic); got != amt {
			t.Errorf("xmr %s round-tripped to %q", amt, got)
		}
	}
	// One piconero over uint64's ceiling is not a rounding question, it is an
	// unrepresentable amount: refuse rather than wrap.
	if _, err := parseAmount("xmr", "18446744.073709551616"); err == nil {
		t.Error("parseAmount accepted piconero past uint64")
	}
}

func TestParseAmountFlag(t *testing.T) {
	asset, atomic, err := parseAmountFlag("5.5DERO")
	if err != nil || asset != "dero" || atomic != 550000 {
		t.Fatalf("5.5DERO = %s %d %v", asset, atomic, err)
	}
	if _, _, err := parseAmountFlag(""); err != nil {
		t.Fatal("empty should mean no payment")
	}
	// XMR is a money asset even though a Monero pointer can never carry value
	// (TestCarrierCarriesValue): the rail's atomic unit and the carrier's
	// payload seam are separate questions.
	asset, atomic, err = parseAmountFlag("2.5XMR")
	if err != nil || asset != "xmr" || atomic != 2500000000000 {
		t.Fatalf("2.5XMR = %s %d %v", asset, atomic, err)
	}
	for _, bad := range []string{"5.5", "dero", "x dero"} {
		if _, _, err := parseAmountFlag(bad); err == nil {
			t.Errorf("parseAmountFlag(%q) accepted malformed", bad)
		}
	}
}

func TestInvoicePaymentEnvelopeRoundTrip(t *testing.T) {
	raw, env, err := marshalInvoice("dero", "25", "consulting", dueTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if env.Atomic != 2500000 || env.ID == "" {
		t.Fatalf("invoice = %+v", env)
	}
	kind, summary, ok := parseMoneyEnvelope(raw)
	if !ok || kind != "invoice" || !strings.Contains(summary, "25 dero") || !strings.Contains(summary, "consulting") {
		t.Fatalf("invoice parse = %q %q %v", kind, summary, ok)
	}
	pay, err := marshalPayment(env.ID, "dero", 2500000, "tx-abc", "settled")
	if err != nil {
		t.Fatal(err)
	}
	kind, summary, ok = parseMoneyEnvelope(pay)
	if !ok || kind != "payment" || !strings.Contains(summary, "PAID 25 dero") || !strings.Contains(summary, env.ID) {
		t.Fatalf("payment parse = %q %q %v", kind, summary, ok)
	}
	// Ordinary plaintext is never money.
	if _, _, ok := parseMoneyEnvelope([]byte("hello there")); ok {
		t.Fatal("plaintext parsed as money envelope")
	}
	// Tampered/invalid envelopes rejected.
	for _, bad := range []string{
		`{"type":"spore/invoice/v1","id":"","asset":"dero","atomic":0}`,
		`{"type":"spore/payment/v1","atomic":0,"txid":""}`,
		`{"type":"spore/unknown/v1"}`,
	} {
		if _, _, ok := parseMoneyEnvelope([]byte(bad)); ok {
			t.Errorf("accepted invalid envelope %s", bad)
		}
	}
}

func TestCarrierCarriesValue(t *testing.T) {
	for _, yes := range []string{"dero", "evm", "DERO", "EVM"} {
		if !carrierCarriesValue(yes) {
			t.Errorf("%s should carry value", yes)
		}
	}
	// bitcoin/ton DISCARD amountHint in their PostPayload today: they must
	// be refused, not silently unpaid. xmr belongs here for the same reason —
	// its tx seam is an 8-byte payment id, not a value-carrying pointer — even
	// though xmr is a first-class MONEY asset (see TestXRMPiconeroExactness).
	for _, no := range []string{"nostr", "cosmos", "solana", "xmr", "bitcoin", "btc", "ton", ""} {
		if carrierCarriesValue(no) {
			t.Errorf("%s must NOT claim value carriage", no)
		}
	}
}
