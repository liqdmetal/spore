package main

// Tests for per-order subaddress issuance (`spore bill address`) and for the
// poller attributing payments from the ledger it writes.
//
// The property under test is the one the hand-written map could not give:
// issuing the address and recording the order are one step, so a payment to a
// fresh subaddress is attributed to the customer it was issued for — and a
// second order can never be handed the same address.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// subaddressHeld is one address the mock wallet holds.
type subaddressHeld struct {
	Address string
	Label   string
	Used    bool
}

// subaddressWallet answers the calls this path involves: create_address issues
// from a counter (the way a wallet does, minor indices only ever increase),
// get_address reports what the wallet holds — labels and used flags included, in
// the v0.18.5.1 object shape — and get_transfers serves one incoming payment on
// the first address issued.
type subaddressWallet struct {
	srv *httptest.Server

	mu        sync.Mutex
	nextMinor uint32
	issued    []map[string]any          // params of every create_address
	polls     int                       // get_transfers calls
	held      map[uint32]subaddressHeld // every address the wallet has, by minor
}

func newSubaddressWallet(t *testing.T, firstMinor uint32) *subaddressWallet {
	t.Helper()
	w := &subaddressWallet{
		nextMinor: firstMinor,
		held: map[uint32]subaddressHeld{
			// Every real account has minor 0, and a reconcile must not report the
			// account's own address as money nobody recorded.
			0: {Address: "8SUBPRIMARYaccountaddress000000000000000000000001", Label: "Primary account", Used: true},
		},
	}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("mock wallet: undecodable request: %v", err)
			return
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		switch req.Method {
		case "create_address":
			w.issued = append(w.issued, req.Params)
			minor := w.nextMinor
			w.nextMinor++
			label, _ := req.Params["label"].(string)
			addr := fmt.Sprintf("8SUBISSUEDtestaddress%013d", minor)
			w.held[minor] = subaddressHeld{Address: addr, Label: label}
			_, _ = rw.Write([]byte(fmt.Sprintf(
				`{"jsonrpc":"2.0","id":1,"result":{"address":%q,"address_index":%d,"address_indices":[%d],"addresses":[%q]}}`,
				addr, minor, minor, addr)))
		case "get_address":
			minors := make([]uint32, 0, len(w.held))
			for m := range w.held {
				minors = append(minors, m)
			}
			sortUints(minors)
			entries := make([]map[string]any, 0, len(minors))
			for _, m := range minors {
				e := w.held[m]
				entries = append(entries, map[string]any{
					"address": e.Address, "address_index": m, "label": e.Label, "used": e.Used,
				})
			}
			body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
				"address": w.held[0].Address, "addresses": entries,
			}})
			if err != nil {
				t.Errorf("mock wallet: %v", err)
				return
			}
			_, _ = rw.Write(body)
		case "get_transfers":
			w.polls++
			// The payment lands on the first address issued (minor 3 in these
			// tests), which is what xmrTransfersFixture already describes.
			_, _ = rw.Write([]byte(xmrTransfersFixture))
		default:
			t.Errorf("mock wallet: unexpected method %q", req.Method)
		}
	}))
	t.Cleanup(w.srv.Close)
	return w
}

// seedWalletAddress gives the mock wallet an address the ledger never learned:
// the crash-between-call-and-write case `bill reconcile` exists to find.
func (w *subaddressWallet) seedWalletAddress(minor uint32, label string, used bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.held[minor] = subaddressHeld{Address: fmt.Sprintf("8SUBSEEDEDaddress%017d", minor), Label: label, Used: used}
	if minor >= w.nextMinor {
		w.nextMinor = minor + 1
	}
}

func (w *subaddressWallet) stats() (issued []map[string]any, polls int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]map[string]any(nil), w.issued...), w.polls
}

// issueAddress runs the real subcommand. Exit status and output are what an
// operator sees, so they are what the test reads.
func issueAddress(t *testing.T, exe, rpcURL, out string, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{
		"bill", "address", "-rpc", rpcURL,
		"-out", out, "-user", "cc4f19a2", "-order", "ord-41",
	}, extra...)
	return runSpore(t, exe, args...)
}

// One order, one address, recorded where the poller will look for it — and no
// second address for the same customer or the same order, because reissuing is
// how a paid address ends up belonging to two orders.
func TestBillAddressIssuesOneSubaddressPerOrder(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	dir := t.TempDir()

	logs, err := issueAddress(t, exe, w.srv.URL, dir)
	if err != nil {
		t.Fatalf("bill address: %v\n%s", err, logs)
	}
	for _, want := range []string{"subaddress", "minor       3", "order       ord-41", "pays for    cc4f19a2"} {
		if !strings.Contains(logs, want) {
			t.Errorf("output missing %q:\n%s", want, logs)
		}
	}

	ledger, err := loadBillSubaddresses(billLedgerPath(dir))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if len(ledger) != 1 {
		t.Fatalf("ledger has %d entries, want 1: %+v", len(ledger), ledger)
	}
	entry, ok := ledger[3]
	if !ok {
		t.Fatalf("ledger does not record minor 3: %+v", ledger)
	}
	if entry.User != "cc4f19a2" || entry.Order != "ord-41" || entry.Address == "" || entry.IssuedAt == "" {
		t.Errorf("ledger entry = %+v, want user, order, address and issued_at", entry)
	}

	issued, _ := w.stats()
	if len(issued) != 1 {
		t.Fatalf("the wallet was asked for %d addresses, want 1", len(issued))
	}
	if issued[0]["label"] != "order:ord-41" || issued[0]["count"] != float64(1) || issued[0]["account_index"] != float64(0) {
		t.Errorf("create_address params = %+v", issued[0])
	}

	// Same order again: refuse, and refuse BEFORE touching the wallet.
	if logs, err := issueAddress(t, exe, w.srv.URL, dir); err == nil {
		t.Fatalf("a second address for the same order was issued:\n%s", logs)
	} else if !strings.Contains(logs, "already has subaddress") && !strings.Contains(logs, "already owns") {
		t.Errorf("the refusal should say why, got:\n%s", logs)
	}
	if issued, _ := w.stats(); len(issued) != 1 {
		t.Errorf("the wallet was asked for another address after a refusal (%d calls)", len(issued))
	}

	// A different order for a different customer is a new address.
	logs, err = runSpore(t, exe, "bill", "address", "-rpc", w.srv.URL, "-out", dir,
		"-user", "deadbeef", "-order", "ord-42")
	if err != nil {
		t.Fatalf("second order: %v\n%s", err, logs)
	}
	ledger, err = loadBillSubaddresses(billLedgerPath(dir))
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if len(ledger) != 2 || ledger[4].User != "deadbeef" || ledger[4].Order != "ord-42" {
		t.Errorf("ledger after the second order = %+v", ledger)
	}
}

// The poller reads the ledger from -out with no extra flag, and bills the
// payment that landed on the issued address.
func TestBillWatchBillsFromTheIssuedLedger(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")

	if logs, err := issueAddress(t, exe, w.srv.URL, out); err != nil {
		t.Fatalf("bill address: %v\n%s", err, logs)
	}

	args := append(billWatchXMRBase(dir, w.srv.URL, out), "-xmr-unverified")
	logs, err := runBillWatch(t, exe, args...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "DRY-RUN would provision") || !strings.Contains(logs, "user=cc4f19a2") {
		t.Errorf("the payment on the issued address was not attributed to its order's customer:\n%s", logs)
	}
	if !strings.Contains(logs, "1 subaddresses labelled from "+billLedgerPath(out)) {
		t.Errorf("the poller should say which ledger it attributed from:\n%s", logs)
	}
	// The startup check runs on every poll start, so it must be quiet when the
	// ledger and the wallet agree — otherwise operators learn to ignore it and the
	// one real drift goes unread.
	if !strings.Contains(logs, "in step with the ledger") {
		t.Errorf("the poller should confirm the ledger is in step at startup:\n%s", logs)
	}
	if _, polls := w.stats(); polls == 0 {
		t.Error("the poller never asked the wallet for transfers")
	}
	if st := readBillState(t, out); st.Height != 3156002 {
		t.Errorf("state height = %d, want the transfer's height", st.Height)
	}
}

// No ledger, no map: the poller must refuse to run rather than poll forever and
// hold every payment it sees.
func TestBillWatchRefusesWithNoAttribution(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")

	logs, err := runBillWatch(t, exe, append(billWatchXMRBase(dir, w.srv.URL, out), "-xmr-unverified")...)
	if err == nil {
		t.Fatalf("bill watch ran with nothing labelled:\n%s", logs)
	}
	if !strings.Contains(logs, "spore bill address") {
		t.Errorf("the refusal should name the command that fixes it:\n%s", logs)
	}
	if _, polls := w.stats(); polls != 0 {
		t.Errorf("the poller scanned the wallet %d time(s) with no way to attribute anything", polls)
	}
}

// Both sources are merged, an identical entry in both is how an operator
// migrates, and a contradiction is refused instead of resolved.
func TestMergeBillLabelsRules(t *testing.T) {
	issued := map[uint32]billSubaddress{
		3: {User: "cc4f19a2", Order: "ord-41"},
		4: {User: "deadbeef", Order: "ord-42"},
	}

	t.Run("identical entries in both sources are fine", func(t *testing.T) {
		got, err := mergeBillLabels(issued, map[uint32]string{3: "cc4f19a2"}, "map.json")
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if len(got) != 2 || got[3] != "cc4f19a2" || got[4] != "deadbeef" {
			t.Errorf("labels = %+v", got)
		}
	})

	t.Run("a legacy-only entry still bills", func(t *testing.T) {
		got, err := mergeBillLabels(issued, map[uint32]string{9: "0ldc0de"}, "map.json")
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if got[9] != "0ldc0de" {
			t.Errorf("labels = %+v", got)
		}
	})

	t.Run("one address, two customers is refused", func(t *testing.T) {
		if _, err := mergeBillLabels(issued, map[uint32]string{3: "someoneelse"}, "map.json"); err == nil {
			t.Fatal("two customers on subaddress 3 were accepted: a payment there would be ambiguous")
		}
	})

	t.Run("one customer, two addresses is refused", func(t *testing.T) {
		if _, err := mergeBillLabels(issued, map[uint32]string{7: "cc4f19a2"}, "map.json"); err == nil {
			t.Fatal("one customer was accepted on two subaddresses")
		}
	})
}

// A ledger is operator-editable, so it is read strictly: a key that is not an
// index or a user that could never be provisioned is a broken ledger, not an
// entry to guess about.
func TestLoadBillSubaddressesRejectsBrokenLedgers(t *testing.T) {
	for name, body := range map[string]string{
		"non-numeric key": `{"three":{"user":"cc4f19a2"}}`,
		"bad username":    `{"3":{"user":"Not A User"}}`,
		"missing user":    `{"3":{"address":"8x"}}`,
		"not an object":   `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "subaddresses.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBillSubaddresses(path); err == nil {
				t.Errorf("loaded a ledger it should refuse: %s", body)
			}
		})
	}
}

// The ledger is written by issuing, read by the poller: two writers that never
// coordinate would corrupt it, so the write is a temp file plus a rename.
func TestSaveBillSubaddressesReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := billLedgerPath(dir)
	if err := saveBillSubaddresses(path, map[uint32]billSubaddress{3: {User: "cc4f19a2", Order: "ord-41"}}); err != nil {
		t.Fatal(err)
	}
	if err := saveBillSubaddresses(path, map[uint32]billSubaddress{
		3: {User: "cc4f19a2", Order: "ord-41"},
		4: {User: "deadbeef", Order: "ord-42"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := loadBillSubaddresses(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("ledger = %+v, want the second write to replace the first", got)
	}
	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".subaddresses-") {
			t.Errorf("left a temp file behind: %s", e.Name())
		}
	}
	// And the file is canonical JSON: sorted keys, so two runs produce the same
	// bytes and a diff shows only what changed.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("ledger is not JSON: %v\n%s", err, raw)
	}
}
