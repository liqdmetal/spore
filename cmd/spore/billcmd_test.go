package main

import "testing"

func TestPlanPayments(t *testing.T) {
	price := uint64(2_500_000) // 25 DERO (1 DERO = 100000 atomic)
	entries := []billEntry{
		{Height: 100, TXID: "t1", Incoming: true, Amount: 3_000_000},  // paid, over price
		{Height: 101, TXID: "t2", Incoming: true, Amount: 2_500_000},  // exactly the price
		{Height: 102, TXID: "t3", Incoming: true, Amount: 1_000_000},  // underpaid -> skip
		{Height: 103, TXID: "t4", Incoming: false, Amount: 9_000_000}, // outgoing -> skip
		{Height: 104, TXID: "t5", Incoming: true, Amount: 2_500_000},  // duplicate handling below
	}
	done := map[string]string{"t5": "cdeadbeef"}
	plans := planPayments(price, entries, done)
	if len(plans) != 2 {
		t.Fatalf("want 2 plans (t1, t2), got %d: %+v", len(plans), plans)
	}
	if plans[0].TXID != "t1" || plans[1].TXID != "t2" {
		t.Fatalf("unexpected plan order: %+v", plans)
	}
	for _, p := range plans {
		if p.User == "" || len(p.User) > 16 {
			t.Fatalf("bad derived username %q", p.User)
		}
		if p.User != "c"+p.TXID[:min(16, len(p.TXID))] {
			t.Fatalf("username %q not derived from txid", p.User)
		}
	}
}

func TestPlanPaymentsUsernameCollisionShape(t *testing.T) {
	price := uint64(1)
	plans := planPayments(price, []billEntry{
		{TXID: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", Incoming: true, Amount: 1},
		{TXID: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778898", Incoming: true, Amount: 1},
	}, map[string]string{})
	// Both truncate to the same 16-char prefix -> the orchestrator must be
	// able to see the collision and hold the second (dedupe on user).
	seen := map[string]bool{}
	for _, p := range plans {
		if seen[p.User] {
			t.Fatalf("username collision not handled: %q", p.User)
		}
		seen[p.User] = true
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
