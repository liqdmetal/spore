package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

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

// --- DERO watermark: a held payment is only a hold if the wallet returns it ---

// deroHeldFixtureTXID is the payment whose prekey batch never arrived;
// deroLaterFixtureTXID is a later payment that must not push the watermark past
// it. Neither is verified on any chain.
const (
	deroHeldFixtureTXID  = "6f1b0c9d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
	deroLaterFixtureTXID = "1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8e9f00"
)

// TestNextBillWatermark pins the rule that keeps a deferred payment from being
// lost: min_height is inclusive and nothing else re-reads a transfer.
func TestNextBillWatermark(t *testing.T) {
	cases := []struct {
		name     string
		highest  uint64
		deferred []uint64
		want     uint64
	}{
		{"nothing deferred", 3157000, nil, 3157000},
		{"deferred pins below the highest", 3157000, []uint64{3156002}, 3156002},
		{"oldest deferred wins", 3157000, []uint64{3156002, 3155400}, 3155400},
		{"a height of 0 is never pinned", 3157000, []uint64{0}, 3157000},
		{"0 among real heights is ignored", 3157000, []uint64{0, 3155000}, 3155000},
		{"nothing seen yet", 0, nil, 0},
		{"nothing seen, 0 deferred", 0, []uint64{0}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextBillWatermark(c.highest, c.deferred); got != c.want {
				t.Errorf("nextBillWatermark(%d, %v) = %d, want %d", c.highest, c.deferred, got, c.want)
			}
		})
	}
}

// newDeroWalletMock serves get_transfers in DERO's shape and honours min_height
// the way R153 does — an inclusive >= block-height filter, with no
// filter_by_height gate (the same semantics internal/whisper/recv_state_test.go
// models) — so a two-poll test can prove what the wallet would really return.
func newDeroWalletMock(t *testing.T, entries []map[string]any) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params struct {
				In        bool   `json:"in"`
				MinHeight uint64 `json:"min_height"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("mock dero wallet: undecodable request: %v", err)
			return
		}
		if req.Method != "get_transfers" {
			t.Errorf("mock dero wallet: method = %q, want get_transfers", req.Method)
		}
		if !req.Params.In {
			t.Errorf("mock dero wallet: the request did not ask for incoming transfers")
		}
		mu.Lock()
		seen = append(seen, map[string]any{"min_height": req.Params.MinHeight})
		mu.Unlock()
		kept := []map[string]any{}
		for _, e := range entries {
			if h, _ := e["height"].(float64); uint64(h) >= req.Params.MinHeight {
				kept = append(kept, e)
			}
		}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "bill", "result": map[string]any{"entries": kept}})
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), seen...)
	}
}

// TestBillWatchDeroKeepsTheWatermarkUnderAMissingBatch is the bug the DERO path
// shipped with. A payment held because the customer's prekey batch had not
// arrived yet was only ever retried if the wallet returned it again, and DERO's
// min_height is an inclusive >= filter, so the next customer's payment — whose
// batch had arrived — pushed the watermark past the held one and the hold became
// permanent: that customer paid and no mailbox was ever created.
//
// Two polls over one state file, against a mock that filters by min_height the
// way R153 does. The second poll has to ask for the held payment's height and
// get it back.
func TestBillWatchDeroKeepsTheWatermarkUnderAMissingBatch(t *testing.T) {
	exe := buildSporeBinary(t)
	entries := []map[string]any{
		{"height": float64(3157000), "txid": deroLaterFixtureTXID, "incoming": true, "amount": float64(3000000)},
		{"height": float64(3156002), "txid": deroHeldFixtureTXID, "incoming": true, "amount": float64(3000000)},
	}
	srv, requests := newDeroWalletMock(t, entries)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	// No batch files: the customers have paid, but their devices have not
	// uploaded prekeys yet. That is the normal sequence, not an error.
	batchDir := filepath.Join(dir, "batches")
	if err := os.MkdirAll(batchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"bill", "watch", "-once",
		"-rpc", srv.URL, "-price", "25dero",
		"-users", filepath.Join(dir, "users"),
		"-tokens", filepath.Join(dir, "tokens.json"),
		"-batch-dir", batchDir, "-out", out,
	}

	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("first poll exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "holding until it arrives") {
		t.Fatalf("the missing batches should be reported as holds:\n%s", logs)
	}
	st := readBillState(t, out)
	if st.Height != 3156002 {
		t.Fatalf("watermark after the first poll = %d, want 3156002 (the oldest hold): a later payment at 3157000 must not move the watermark past a payment being held", st.Height)
	}
	if _, ok := st.Held[deroHeldFixtureTXID]; !ok {
		t.Fatalf("the held payment should be recorded: %+v", st.Held)
	}

	// The second poll is the one that was broken: at 3157000 the wallet returns
	// only the later payment, so the hold is never retried.
	logs2, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("second poll exited non-zero: %v\n%s", err, logs2)
	}
	reqs := requests()
	if len(reqs) != 2 {
		t.Fatalf("want one request per poll, saw %d", len(reqs))
	}
	// The mock decodes min_height into a typed field, so it arrives here as
	// uint64 (not the float64 a generic map decode would give).
	if got, _ := reqs[1]["min_height"].(uint64); got != 3156002 {
		t.Errorf("the second poll asked for min_height=%d, want 3156002: at any higher watermark the wallet cannot return the held payment, and it is lost", got)
	}
	if !strings.Contains(logs2, "holding until it arrives") {
		t.Errorf("the held payment was not retried on the second poll:\n%s", logs2)
	}
}
