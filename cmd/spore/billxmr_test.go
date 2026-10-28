package main

// Tests for the Monero branch of bill watch (docs/MONERO_SETTLEMENT.md §5).
//
// What is covered here: the guard table, the watermark rule, the request shape
// this poller sends, the decode of a real-shaped response, the operator's
// subaddress map, and — against a mock that verifies Digest credentials the way
// a server does — the auth path the live wallet requires.
//
// The response fixtures: the first is built from the v0.18.0.0 field set, and
// xmrLiveShapeFixture is the key set of a populated entry captured from a live
// v0.18.5.1 wallet on 2026-10-27 (identifying strings redacted, §9). What these
// tests still cannot cover, and why the command stays behind -xmr-unverified:
// nothing here proves provisioning against a live wallet. That happened once, on
// 2026-10-27/28, and is recorded in docs/MONERO_SETTLEMENT.md §8 step 5 rather
// than reproduced on every push.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/icholy/digest"
)

// xmrTransferFixtureTXID is a well-formed 64-hex txid; nothing verifies it.
const xmrTransferFixtureTXID = "3f2a1c9d4b7e5a60819fb2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f607"

// xmrTransfersFixture is a get_transfers result in the v0.18.0.0 shape. It
// deliberately carries MORE fields than the poller reads (amounts, fee, note,
// payment_id, subaddr_indices, suggested_confirmations_threshold, timestamp,
// unlock_time) so the decode is proven against a response that is not trimmed to
// what we happen to parse.
const xmrTransfersFixture = `{
  "id": "bill",
  "jsonrpc": "2.0",
  "result": {
    "in": [
      {
        "address": "8AUJdGVzdHN1YmFkZHJlc3MxMjM0NTY3ODkw",
        "amount": 2500000000000,
        "amounts": [2500000000000],
        "confirmations": 12,
        "double_spend_seen": false,
        "fee": 0,
        "height": 3156002,
        "locked": false,
        "note": "order 41",
        "payment_id": "0000000000000000",
        "subaddr_index": {"major": 0, "minor": 3},
        "subaddr_indices": [{"major": 0, "minor": 3}],
        "suggested_confirmations_threshold": 10,
        "timestamp": 1761540000,
        "txid": "` + xmrTransferFixtureTXID + `",
        "type": "in",
        "unlock_time": 0
      }
    ]
  }
}`

// xmrAddressesFixture is a get_address result in the v0.18.5.1 object shape. It
// describes the wallet xmrTransfersFixture pays: the account's own address at
// minor 0, and the receiving address at minor 3 under the label `bill address`
// writes. `bill watch` reads this once at startup to compare the issued-address
// ledger against the wallet, so a mock that cannot answer would leave every watch
// test logging an unanswered question instead of agreement.
const xmrAddressesFixture = `{
  "id": "bill",
  "jsonrpc": "2.0",
  "result": {
    "address": "8AUJprimaryaccountaddress00000000000000",
    "addresses": [
      {"address": "8AUJprimaryaccountaddress00000000000000", "address_index": {"major": 0, "minor": 0}, "label": "Primary account", "used": false},
      {"address": "8AUJdGVzdHN1YmFkZHJlc3MxMjM0NTY3ODkw", "address_index": {"major": 0, "minor": 3}, "label": "order:ord-41", "used": true}
    ]
  }
}`

// newWalletRPCMock stands in for a wallet RPC (Monero's or DERO's). It records
// the request it was sent so a test can assert the shape the poller puts on the
// wire.
func newWalletRPCMock(t *testing.T, body string, status int) (*httptest.Server, func() map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("mock wallet: undecodable request: %v", err)
		}
		mu.Lock()
		seen = map[string]any{"method": req.Method, "params": req.Params}
		mu.Unlock()
		if req.Method == "get_address" {
			// The startup drift check, which `bill watch` makes before it polls.
			// It is answered here rather than from the caller's body because the
			// two methods answer different questions.
			_, _ = w.Write([]byte(xmrAddressesFixture))
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"message":"unauthorized"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

// TestBillPollRPCXMRRequestShape pins the request, because the request is where
// this branch was wrong once already: v0.18.0.0 gates height filtering on
// filter_by_height, so sending min_height without it silently re-scans every
// transfer the wallet holds on every poll while looking perfectly correct.
func TestBillPollRPCXMRRequestShape(t *testing.T) {
	srv, seen := newWalletRPCMock(t, xmrTransfersFixture, http.StatusOK)
	entries, highest, err := billPollRPCXMR(srv.URL, "", 12345)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	got := seen()
	if got["method"] != "get_transfers" {
		t.Fatalf("method = %v, want get_transfers", got["method"])
	}
	params, _ := got["params"].(map[string]any)
	if params == nil {
		t.Fatal("request carried no params")
	}
	for _, want := range []struct {
		key  string
		val  any
		note string
	}{
		{"in", true, "incoming transfers are the whole point"},
		{"filter_by_height", true, "min_height is INERT without this: the wallet re-scans everything"},
		{"account_index", float64(0), "the poller attributes by minor index within account 0"},
		{"min_height", float64(12345), "the poller's own watermark must be sent"},
		{"out", false, "outgoing transfers are not billable events"},
		{"pending", false, "pending is not a settled payment"},
		{"pool", false, "pool entries carry no height, so they cannot pin the watermark"},
	} {
		if params[want.key] != want.val {
			t.Errorf("params[%q] = %v, want %v (%s)", want.key, params[want.key], want.val, want.note)
		}
	}

	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.TxID != xmrTransferFixtureTXID {
		t.Errorf("txid = %q", e.TxID)
	}
	if e.Amount != 2_500_000_000_000 {
		t.Errorf("amount = %d, want 2.5 XMR in piconero (integer atomic units, never decimal XMR)", e.Amount)
	}
	if e.Confirmations != 12 || e.Height != 3156002 {
		t.Errorf("confirmations/height = %d/%d", e.Confirmations, e.Height)
	}
	if e.Type != "in" {
		t.Errorf("type = %q, want \"in\"", e.Type)
	}
	if e.SubaddrIndex.Minor != 3 || e.SubaddrIndex.Major != 0 {
		t.Errorf("subaddr_index = %+v", e.SubaddrIndex)
	}
	if e.Address == "" {
		t.Error("incoming entry had no address: attribution by subaddress depends on it")
	}
	if e.Locked || e.DoubleSpend {
		t.Errorf("locked=%v double_spend_seen=%v, want false", e.Locked, e.DoubleSpend)
	}
	if highest != 3156002 {
		t.Errorf("highest = %d, want the entry's height", highest)
	}
}

// TestBillPollRPCXMRFixtureIsBillable closes the loop from wire bytes to a
// provisionable plan: a real-shaped response, the operator's labels, and the
// guards together must yield the customer's mailbox.
func TestBillPollRPCXMRFixtureIsBillable(t *testing.T) {
	srv, _ := newWalletRPCMock(t, xmrTransfersFixture, http.StatusOK)
	entries, highest, err := billPollRPCXMR(srv.URL, "", 0)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	labels := map[uint32]string{3: "cc4f19a2"}
	plans, refusals := planXMRPayments(2_500_000_000_000, 10, labels, nil, entries)
	if len(refusals) != 0 {
		t.Fatalf("a payable transfer was refused: %+v", refusals)
	}
	if len(plans) != 1 || plans[0].User != "cc4f19a2" {
		t.Fatalf("plans = %+v, want one for cc4f19a2", plans)
	}
	if plans[0].TXID != xmrTransferFixtureTXID {
		t.Errorf("plan txid = %q", plans[0].TXID)
	}
	if got := nextBillWatermark(highest, nil); got != 3156002 {
		t.Errorf("watermark = %d, want the highest height seen", got)
	}
}

// TestBillPollRPCXMRNeverReadsAsNoPayments covers the three ways a wallet RPC can
// fail. Each must be an error: a poller that turns "I cannot see the chain" into
// "nothing was paid" is the failure mode this branch exists to prevent.
func TestBillPollRPCXMRNeverReadsAsNoPayments(t *testing.T) {
	t.Run("rpc error object", func(t *testing.T) {
		srv, _ := newWalletRPCMock(t, `{"id":"bill","jsonrpc":"2.0","error":{"code":-1,"message":"wallet is not open"}}`, http.StatusOK)
		if _, _, err := billPollRPCXMR(srv.URL, "", 0); err == nil {
			t.Fatal("an RPC error object was read as no transfers")
		} else if !strings.Contains(err.Error(), "wallet is not open") {
			t.Errorf("error should carry the wallet's message, got %v", err)
		}
	})
	t.Run("http failure", func(t *testing.T) {
		srv, _ := newWalletRPCMock(t, "", http.StatusUnauthorized)
		if _, _, err := billPollRPCXMR(srv.URL, "", 0); err == nil {
			t.Fatal("HTTP 401 was read as no transfers")
		}
	})
	t.Run("malformed body", func(t *testing.T) {
		srv, _ := newWalletRPCMock(t, `{not json`, http.StatusOK)
		if _, _, err := billPollRPCXMR(srv.URL, "", 0); err == nil {
			t.Fatal("a malformed body was read as no transfers")
		}
	})
}

// TestBillPollRPCXMRMissingInKey is the omission rule: a response with no "in"
// key is an empty result, not an error. Empty categories are not guaranteed to
// serialize as [].
func TestBillPollRPCXMRMissingInKey(t *testing.T) {
	srv, _ := newWalletRPCMock(t, `{"id":"bill","jsonrpc":"2.0","result":{}}`, http.StatusOK)
	entries, highest, err := billPollRPCXMR(srv.URL, "", 700)
	if err != nil {
		t.Fatalf("a result with no \"in\" key must not be an error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want no entries, got %d", len(entries))
	}
	if highest != 700 {
		t.Fatalf("highest = %d, want the watermark unchanged", highest)
	}
	srv2, _ := newWalletRPCMock(t, `{"id":"bill","jsonrpc":"2.0","result":{"in":[]}}`, http.StatusOK)
	if entries, _, err := billPollRPCXMR(srv2.URL, "", 700); err != nil || len(entries) != 0 {
		t.Fatalf("explicit empty array = %d entries, %v", len(entries), err)
	}
}

// xmrEntry builds a billable transfer; mut adjusts it for one case.
func xmrEntry(txid string, minor uint32, mut func(*xmrTransferEntry)) xmrTransferEntry {
	e := xmrTransferEntry{
		TxID: txid, Height: 3156002, Amount: 2_500_000_000_000,
		Confirmations: 12, Type: "in",
	}
	e.SubaddrIndex.Minor = minor
	if mut != nil {
		mut(&e)
	}
	return e
}

// TestPlanXMRPaymentsGuards is §5's guard table. Every entry is either billed or
// refused with a reason; nothing is skipped quietly.
func TestPlanXMRPaymentsGuards(t *testing.T) {
	const price = 2_500_000_000_000 // 2.5 XMR in piconero
	labels := map[uint32]string{3: "cc4f19a2"}
	cases := []struct {
		name       string
		entry      xmrTransferEntry
		done       map[string]string
		wantPlan   bool
		wantRetry  bool
		wantReason string
	}{
		{name: "labelled confirmed payment", entry: xmrEntry("t1", 3, nil), wantPlan: true},
		{
			name:  "coinbase entry is not a payment",
			entry: xmrEntry("t2", 3, func(e *xmrTransferEntry) { e.Type = "block" }),
			// Not retryable: a block reward never becomes billable, so pinning
			// the watermark on it would re-scan from its height forever.
			wantReason: "coinbase",
		},
		{
			name:       "absent type fails closed",
			entry:      xmrEntry("t3", 3, func(e *xmrTransferEntry) { e.Type = "" }),
			wantReason: `type is ""`,
		},
		{
			name:       "locked is not spendable",
			entry:      xmrEntry("t4", 3, func(e *xmrTransferEntry) { e.Locked = true; e.UnlockTime = 3160000 }),
			wantRetry:  true,
			wantReason: "locked until block 3160000",
		},
		{
			name:       "double spend",
			entry:      xmrEntry("t5", 3, func(e *xmrTransferEntry) { e.DoubleSpend = true }),
			wantReason: "double_spend_seen",
		},
		{
			name:       "another account cannot be attributed",
			entry:      xmrEntry("t6", 3, func(e *xmrTransferEntry) { e.SubaddrIndex.Major = 1 }),
			wantReason: "account 1",
		},
		{
			name:       "unlabelled subaddress",
			entry:      xmrEntry("t7", 9, nil),
			wantRetry:  true,
			wantReason: "unlabelled",
		},
		{
			name:       "unconfirmed waits",
			entry:      xmrEntry("t8", 3, func(e *xmrTransferEntry) { e.Confirmations = 3 }),
			wantRetry:  true,
			wantReason: "unconfirmed (3/10)",
		},
		{
			name:       "underpaid is not a payment",
			entry:      xmrEntry("t9", 3, func(e *xmrTransferEntry) { e.Amount = 1_000_000_000_000 }),
			wantReason: "underpaid",
		},
		{
			name:  "already provisioned",
			entry: xmrEntry("t10", 3, nil),
			done:  map[string]string{"t10": "cc4f19a2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plans, refusals := planXMRPayments(price, 10, labels, c.done, []xmrTransferEntry{c.entry})
			if c.wantPlan {
				if len(plans) != 1 || len(refusals) != 0 {
					t.Fatalf("plans=%+v refusals=%+v, want one plan and no refusal", plans, refusals)
				}
				return
			}
			if len(plans) != 0 {
				t.Fatalf("got a plan for a transfer that must not be billed: %+v", plans)
			}
			if len(c.done) > 0 {
				// already billed: neither a plan nor a refusal
				if len(refusals) != 0 {
					t.Fatalf("an already-billed txid came back as a refusal: %+v", refusals)
				}
				return
			}
			if len(refusals) != 1 {
				t.Fatalf("want exactly one refusal, got %+v", refusals)
			}
			r := refusals[0]
			if !strings.Contains(r.Reason, c.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", r.Reason, c.wantReason)
			}
			if r.Retry != c.wantRetry {
				t.Errorf("retry = %v, want %v (reason %q)", r.Retry, c.wantRetry, r.Reason)
			}
			if r.TXID != c.entry.TxID {
				t.Errorf("refusal txid = %q, want %q", r.TXID, c.entry.TxID)
			}
			if r.Minor != c.entry.SubaddrIndex.Minor {
				t.Errorf("refusal minor = %d, want %d", r.Minor, c.entry.SubaddrIndex.Minor)
			}
		})
	}
}

// TestPlanXMRPaymentsIsNeverSilent is the invariant behind "hold-and-log": with
// the exception of a txid already billed, every transfer this poller sees leaves
// with either a plan or a refusal. A poller that reported nothing while holding
// money would look healthy, which is exactly the failure §5 is written against.
func TestPlanXMRPaymentsIsNeverSilent(t *testing.T) {
	entries := []xmrTransferEntry{
		xmrEntry("s1", 3, nil),
		xmrEntry("s2", 3, func(e *xmrTransferEntry) { e.Type = "block" }),
		xmrEntry("s3", 9, nil),
		xmrEntry("s4", 3, func(e *xmrTransferEntry) { e.Locked = true }),
		xmrEntry("s5", 3, func(e *xmrTransferEntry) { e.Amount = 1 }),
		xmrEntry("s6", 3, func(e *xmrTransferEntry) { e.Confirmations = 1 }),
		xmrEntry("s7", 3, func(e *xmrTransferEntry) { e.DoubleSpend = true }),
		xmrEntry("s8", 3, nil), // already billed, so legitimately silent
	}
	plans, refusals := planXMRPayments(1000, 10, map[uint32]string{3: "cc4f19a2"}, map[string]string{"s8": "cc4f19a2"}, entries)
	if got := len(plans) + len(refusals); got != len(entries)-1 {
		t.Fatalf("accounted for %d of %d transfers (one is already billed): %+v / %+v", got, len(entries), plans, refusals)
	}
}

// xmrDeferredFixtureTXID is the txid of the unconfirmed transfer in the
// watermark test; nothing verifies it.
const xmrDeferredFixtureTXID = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

// --- wiring: the pieces that live in the CLI function, not in the pure cores ---

// billWatchFixtureDirs makes the directories and label file a `bill watch`
// invocation needs.
func billWatchFixtureDirs(t *testing.T) (dir, labelFile string) {
	t.Helper()
	dir = t.TempDir()
	labelFile = filepath.Join(dir, "subaddr.json")
	if err := os.WriteFile(labelFile, []byte(`{"3":"cc4f19a2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, labelFile
}

// runBillWatch drives the real binary — the -xmr-unverified gate and the flag
// plumbing live in the CLI function, so nothing else can test them.
func runBillWatch(t *testing.T, exe string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(exe, args...)
	var buf strings.Builder
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// readBillState reads the orchestrator's own state file back.
func readBillState(t *testing.T, outDir string) billState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outDir, "bill-state.json"))
	if err != nil {
		t.Fatalf("bill-state.json: %v", err)
	}
	var st billState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("bill-state.json: %v", err)
	}
	return st
}

// billWatchXMRBase is the shared argument prefix for a Monero dry run.
func billWatchXMRBase(dir, rpcURL, out string) []string {
	return []string{
		"bill", "watch", "-once", "-dry-run",
		"-rpc", rpcURL, "-rpc-login", "spore:secret", "-price", "2.5xmr",
		"-users", filepath.Join(dir, "users"),
		"-tokens", filepath.Join(dir, "tokens.json"),
		"-batch-dir", filepath.Join(dir, "batches"),
		"-out", out,
	}
}

// TestBillWatchXMRDryRunBillsTheFixture is the whole path through a real binary:
// a mock wallet's response becomes a mailbox the operator is told about, and the
// request that produced it carried the filter_by_height the wallet requires.
func TestBillWatchXMRDryRunBillsTheFixture(t *testing.T) {
	exe := buildSporeBinary(t)
	srv, seen := newWalletRPCMock(t, xmrTransfersFixture, http.StatusOK)
	dir, labels := billWatchFixtureDirs(t)
	out := filepath.Join(dir, "out")
	args := append(billWatchXMRBase(dir, srv.URL, out), "-xmr-unverified", "-xmr-subaddresses", labels)

	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "DRY-RUN would provision") || !strings.Contains(logs, "cc4f19a2") {
		t.Errorf("no dry-run provision for the labelled subaddress:\n%s", logs)
	}
	if !strings.Contains(logs, "2.5 xmr") {
		t.Errorf("the amount should render as \"2.5 xmr\" from piconero, never through a float:\n%s", logs)
	}
	got := seen()
	params, _ := got["params"].(map[string]any)
	if params == nil || params["in"] != true || params["filter_by_height"] != true {
		t.Errorf("the poller's request shape was %+v", got)
	}
	st := readBillState(t, out)
	if st.Height != 3156002 {
		t.Errorf("state height = %d, want the transfer's own height", st.Height)
	}
	if len(st.XMRRefused) != 0 {
		t.Errorf("nothing was refused, so nothing should be recorded: %+v", st.XMRRefused)
	}
}

// TestBillWatchXMRGateRefusals drives every way the command must refuse before it
// polls. Each is a different operator mistake, so each gets its own message.
func TestBillWatchXMRGateRefusals(t *testing.T) {
	exe := buildSporeBinary(t)
	srv, _ := newWalletRPCMock(t, xmrTransfersFixture, http.StatusOK)
	dir, labels := billWatchFixtureDirs(t)
	out := filepath.Join(dir, "out")
	base := func() []string { return billWatchXMRBase(dir, srv.URL, out) }
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"xmr without -xmr-unverified", append(base(), "-xmr-subaddresses", labels), "-xmr-unverified"},
		// No ledger and no map: nothing could ever be attributed, so the poller
		// says which command issues an address rather than polling into a void.
		{"xmr with nothing labelled", append(base(), "-xmr-unverified"), "spore bill address"},
		{"zero confirmations", append(base(), "-xmr-unverified", "-xmr-subaddresses", labels, "-xmr-confirmations", "0"), "-xmr-confirmations 0 is refused"},
		{"a rail with no poller", append(base(), "-price", "5evm", "-xmr-unverified"), "not billable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logs, err := runBillWatch(t, exe, c.args...)
			if err == nil {
				t.Fatalf("must exit non-zero, but it succeeded:\n%s", logs)
			}
			if !strings.Contains(logs, c.want) {
				t.Errorf("output should mention %q:\n%s", c.want, logs)
			}
		})
	}
}

// --- live-shape and Digest auth: what a real wallet actually does ---

// xmrLiveTestNonce is a fixed nonce so the mock is deterministic. A real epee
// server issues its own.
const xmrLiveTestNonce = "dGVzdC1ub25jZQ=="

// xmrLiveShapeFixtureTXID stands in for the captured txid. The values in this
// fixture are the ones a live v0.18.5.1 wallet returned on 2026-10-27, with the
// identifying strings (subaddress, txid) replaced — the raw capture stays
// box-side by the redaction rule in MONERO_SETTLEMENT §9.
const xmrLiveShapeFixtureTXID = "b41c7e0d9a2f3865c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7"

// xmrLiveShapeFixture is one populated result.in[] entry in the EXACT key set a
// live wallet emitted (keys in the wallet's own order, values redacted as noted).
//
// It pins two things the v0.18.0.0 source reading could not:
//
//   - there is no `destinations` key on an incoming entry — that field belongs to
//     the outgoing side, even though it is declared on the shared transfer_entry
//     struct (§3 lists it in the field set; a live entry does not carry it);
//   - `payment_id` is PRESENT as a zeroed 8-byte id string, not omitted, so a
//     decoder that treats a payment_id as evidence of a spore signal must compare
//     it against zero rather than testing for emptiness.
//
// `type` is "in", `locked` and `double_spend_seen` are false, and the entry lands
// on minor 0 — the wallet's primary address, which is where a payment goes when
// no per-order subaddress was handed out.
const xmrLiveShapeFixture = `{
  "id": "bill",
  "jsonrpc": "2.0",
  "result": {
    "in": [
      {
        "address": "4AseVYawZMf7mfeYqbLvKbKfXAVDZLM3c2XC8j6j12xpDvrkhMX4CQw3hUqa3i5L2se8YZ3ztgeMA5yU2DNEsP8cHF8VNDo",
        "amount": 181978330000,
        "amounts": [181978330000],
        "confirmations": 30825,
        "double_spend_seen": false,
        "fee": 629900000,
        "height": 3762745,
        "locked": false,
        "note": "",
        "payment_id": "0000000000000000",
        "subaddr_index": {"major": 0, "minor": 0},
        "subaddr_indices": [{"major": 0, "minor": 0}],
        "suggested_confirmations_threshold": 1,
        "timestamp": 1789442539,
        "txid": "` + xmrLiveShapeFixtureTXID + `",
        "type": "in",
        "unlock_time": 0
      }
    ]
  }
}`

// digestMockCalls records what the mock wallet saw, so a test can prove the
// authenticated retry replayed the request (a digest wrapper that consumes the
// body on the first attempt is a real failure mode) and that Basic was never
// used on this rail.
type digestMockCalls struct {
	Total           int
	Unauthenticated int
	Basic           int
	Authenticated   int
	AuthedMethod    string
	AuthedParams    map[string]any
}

// newDigestWalletRPCMock stands in for the live wallet's own auth. Monero's epee
// server advertises
//
//	WWW-Authenticate: Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="…"
//
// and rejects everything else — including a *correct* credential sent as Basic
// (captured 2026-10-27: one user:pass returned 401 as Basic and 200 as Digest).
// This mock does the same, and verifies a digest response the way a server does:
// it recomputes the response hash with its own copy of the password instead of
// trusting any header that merely parses.
func newDigestWalletRPCMock(t *testing.T, user, password, body string) (*httptest.Server, func() digestMockCalls) {
	t.Helper()
	const realm = "monero-rpc"
	var (
		mu    sync.Mutex
		calls digestMockCalls
	)
	unauthorized := func(w http.ResponseWriter, challenge bool) {
		if challenge {
			w.Header().Set("WWW-Authenticate",
				`Digest qop="auth",algorithm=MD5,realm="`+realm+`",nonce="`+xmrLiveTestNonce+`",stale=false`)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":-401,"message":"Unauthorized Access"}}`))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		mu.Lock()
		calls.Total++
		switch {
		case auth == "":
			calls.Unauthenticated++
		case strings.HasPrefix(auth, "Basic "):
			calls.Basic++
		}
		mu.Unlock()
		if !strings.HasPrefix(auth, "Digest ") {
			unauthorized(w, true)
			return
		}
		cred, err := digest.ParseCredentials(auth)
		if err != nil {
			t.Errorf("mock wallet: undecodable digest credentials: %v", err)
			unauthorized(w, false)
			return
		}
		chal := &digest.Challenge{Realm: realm, Nonce: xmrLiveTestNonce, Algorithm: "MD5", QOP: []string{"auth"}}
		want, err := digest.Digest(chal, digest.Options{
			Method: r.Method, URI: r.URL.RequestURI(), Count: cred.Nc,
			Username: user, Password: password, Cnonce: cred.Cnonce,
		})
		if err != nil {
			t.Errorf("mock wallet: cannot compute the expected response: %v", err)
			unauthorized(w, false)
			return
		}
		if cred.Username != user || cred.Realm != realm || cred.Nonce != xmrLiveTestNonce || cred.Response != want.Response {
			unauthorized(w, false)
			return
		}
		// Authenticated. Record the body the retry carried: a request whose body
		// was consumed by the first, unauthenticated attempt arrives here empty and
		// must not read as a healthy poll.
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		calls.Authenticated++
		calls.AuthedMethod, calls.AuthedParams = req.Method, req.Params
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() digestMockCalls {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

// TestBillPollRPCXMRAuthenticatesWithDigest is the live-wallet auth regression.
//
// It exists because the rail shipped with SetBasicAuth, the way the DERO poller
// does it, and a live v0.18.5.1 wallet answers a valid Basic header with 401 — so
// the poll could never succeed, and every poll would fail on an auth error no
// matter how right the credential was. Two things are asserted: the digest
// challenge is answered with a credential the server accepts, and the request the
// server accepts still carries the poll's body.
func TestBillPollRPCXMRAuthenticatesWithDigest(t *testing.T) {
	t.Run("the credential is accepted and the live-shaped entry decodes", func(t *testing.T) {
		srv, calls := newDigestWalletRPCMock(t, "spore", "s3cret-monero", xmrLiveShapeFixture)
		entries, highest, err := billPollRPCXMR(srv.URL, "spore:s3cret-monero", 0)
		if err != nil {
			t.Fatalf("a live-shaped response behind Digest auth failed: %v", err)
		}
		seen := calls()
		if seen.Unauthenticated != 1 || seen.Authenticated != 1 {
			t.Errorf("challenge answered %d unauthenticated / %d authenticated times, want 1/1 (the first request probes, the retry authenticates)", seen.Unauthenticated, seen.Authenticated)
		}
		if seen.Basic != 0 {
			t.Errorf("the poller sent Basic %d time(s): a Monero wallet rejects a valid Basic header with 401, so this rail can only ever authenticate with Digest", seen.Basic)
		}
		if seen.AuthedMethod != "get_transfers" || seen.AuthedParams["in"] != true || seen.AuthedParams["filter_by_height"] != true {
			t.Errorf("the authenticated retry carried %q %+v, want get_transfers with in and filter_by_height — a body consumed by the first attempt arrives empty", seen.AuthedMethod, seen.AuthedParams)
		}
		if len(entries) != 1 {
			t.Fatalf("want 1 entry from the live shape, got %d", len(entries))
		}
		e := entries[0]
		if e.TxID != xmrLiveShapeFixtureTXID || e.Amount != 181978330000 || e.Height != 3762745 {
			t.Errorf("entry = %+v", e)
		}
		if e.Type != "in" || e.Locked || e.DoubleSpend {
			t.Errorf("type=%q locked=%v double_spend=%v, want a plain unspent payment", e.Type, e.Locked, e.DoubleSpend)
		}
		if e.SubaddrIndex.Major != 0 || e.SubaddrIndex.Minor != 0 {
			t.Errorf("subaddr_index = %+v, want the primary address (major 0, minor 0) — where a payment lands when no per-order subaddress was handed out", e.SubaddrIndex)
		}
		if e.Address == "" {
			t.Error("the live entry had no address: attribution by subaddress depends on it")
		}
		if highest != 3762745 {
			t.Errorf("highest = %d, want the entry's height", highest)
		}
		// The live entry is billable once its subaddress is labelled.
		plans, refusals := planXMRPayments(100000000000, 10, map[uint32]string{0: "cc4f19a2"}, nil, entries)
		if len(refusals) != 0 || len(plans) != 1 {
			t.Fatalf("plans=%+v refusals=%+v, want the live-shaped entry to bill", plans, refusals)
		}
	})

	t.Run("a rejected credential is an error, never no payments", func(t *testing.T) {
		srv, calls := newDigestWalletRPCMock(t, "spore", "s3cret-monero", xmrLiveShapeFixture)
		_, _, err := billPollRPCXMR(srv.URL, "spore:wrong-password", 0)
		if err == nil {
			t.Fatal("a 401 was read as an empty result: this poller would bill nothing while looking healthy")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("the error should name the HTTP status, got %v", err)
		}
		if seen := calls(); seen.Authenticated != 0 {
			t.Errorf("the mock authenticated %d request(s) with the wrong password", seen.Authenticated)
		}
	})
}

// TestBillWatchXMRKeepsTheWatermarkUnderADeferredPayment is the case that matters
// most in production: an unconfirmed payment sits BELOW a payable one, so the
// obvious watermark — the highest height seen — would step over it. Nothing ever
// re-reads a height once min_height has passed it, so that payment would be lost
// and the customer would have paid for a mailbox that never appears.
func TestBillWatchXMRKeepsTheWatermarkUnderADeferredPayment(t *testing.T) {
	exe := buildSporeBinary(t)
	fixture := `{"id":"bill","jsonrpc":"2.0","result":{"in":[` +
		`{"txid":"` + xmrTransferFixtureTXID + `","height":3157000,"amount":2500000000000,"confirmations":12,"type":"in","locked":false,"double_spend_seen":false,"subaddr_index":{"major":0,"minor":3}},` +
		`{"txid":"` + xmrDeferredFixtureTXID + `","height":3156002,"amount":2500000000000,"confirmations":3,"type":"in","locked":false,"double_spend_seen":false,"subaddr_index":{"major":0,"minor":3}}` +
		`]}}`
	srv, _ := newWalletRPCMock(t, fixture, http.StatusOK)
	dir, labels := billWatchFixtureDirs(t)
	out := filepath.Join(dir, "out")
	args := append(billWatchXMRBase(dir, srv.URL, out), "-xmr-unverified", "-xmr-subaddresses", labels)

	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "unconfirmed (3/10)") {
		t.Errorf("the unconfirmed transfer should be reported, not swallowed:\n%s", logs)
	}
	st := readBillState(t, out)
	if st.Height != 3156002 {
		t.Errorf("watermark = %d, want 3156002: it passed the deferred payment below the highest height seen (3157000), and nothing will re-read it", st.Height)
	}
	if _, ok := st.XMRRefused[xmrDeferredFixtureTXID]; !ok {
		t.Errorf("the refusal should survive in bill-state.json for an operator who was not watching the log: %+v", st.XMRRefused)
	}
}
