package main

// Tests for `bill reconcile`, and for the `bill address -adopt` half that makes
// its proposal executable.
//
// The case that matters is the one nothing else can see: create_address
// succeeded and the ledger write did not, so the wallet holds an address spore
// never recorded. Reconcile must find it, name the command that fixes it, and
// then report agreement once it has been adopted — while a ledger entry the
// wallet does not back must never read as agreement.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/xmr"
)

// runReconcile drives the real subcommand; exit status and output are the
// operator's view, so they are what the tests read.
func runReconcile(t *testing.T, exe, rpcURL, out string, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{"bill", "reconcile", "-rpc", rpcURL, "-out", out}, extra...)
	return runSpore(t, exe, args...)
}

// issueOne creates the one address the "in step" cases start from (minor 3, the
// index xmrTransfersFixture pays).
func issueOne(t *testing.T, exe string, w *subaddressWallet, out string) {
	t.Helper()
	if logs, err := issueAddress(t, exe, w.srv.URL, out); err != nil {
		t.Fatalf("bill address: %v\n%s", err, logs)
	}
}

// The ordinary state: every wallet address is either the primary or in the
// ledger. Reconcile exits 0 — because a check that always fails is not a check.
func TestBillReconcileInStep(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out)

	logs, err := runReconcile(t, exe, w.srv.URL, out)
	if err != nil {
		t.Fatalf("reconcile on a clean ledger failed: %v\n%s", err, logs)
	}
	for _, want := range []string{
		"wallet      2 address(es) on account 0",
		"in step     1",
		"minor 3",
		"the ledger and the wallet agree",
		"minor 0 is the account's own address",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("output missing %q:\n%s", want, logs)
		}
	}
}

// The crash case: the wallet has an address the ledger never learned. Reconcile
// must fail, name it, and print the exact command — including the order recovered
// from the wallet's own label.
func TestBillReconcileFindsAnAddressOnlyTheWalletKnows(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out)
	// Issued by a run that died before the ledger write.
	w.seedWalletAddress(1, "order:ord-live-1", false)

	logs, err := runReconcile(t, exe, w.srv.URL, out)
	if err == nil {
		t.Fatalf("reconcile accepted an unrecorded address:\n%s", logs)
	}
	for _, want := range []string{
		"DRIFT  1 address(es) on the wallet that the ledger does not know",
		"minor 1",
		"label order:ord-live-1",
		// The proposal has to be the command `bill address` actually takes: a
		// ledger path, not the outbox directory. It printed `-out …/subaddresses.json`
		// once, which would have written the ledger into a directory named after it.
		"spore bill address -addresses ",
		"-adopt 1 -user NAME -order ord-live-1",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("output missing %q:\n%s", want, logs)
		}
	}

	// And the proposal works: adopting it puts the two back in step, with no new
	// address minted. The orphan belongs to a customer who has no address yet —
	// adoption cannot give one customer a second address either.
	adopted, err := runSpore(t, exe, "bill", "address", "-rpc", w.srv.URL, "-out", out,
		"-adopt", "1", "-user", "deadbeef")
	if err != nil {
		t.Fatalf("adopt: %v\n%s", err, adopted)
	}
	if !strings.Contains(adopted, "adopted") || !strings.Contains(adopted, "order       ord-live-1") {
		t.Errorf("adopt output should show what it recorded:\n%s", adopted)
	}
	if issued, _ := w.stats(); len(issued) != 1 {
		t.Errorf("adopt asked the wallet for a new address (%d create_address calls); recovery must not mint another", len(issued))
	}
	ledger, err := loadBillSubaddresses(billLedgerPath(out))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := ledger[1]; !ok || e.User != "deadbeef" || e.Order != "ord-live-1" || e.Address == "" {
		t.Errorf("ledger after adopt = %+v", ledger)
	}
	if logs, err := runReconcile(t, exe, w.srv.URL, out); err != nil {
		t.Fatalf("reconcile still drifted after adoption: %v\n%s", err, logs)
	}
}

// The worse direction: a ledger entry the wallet does not back. A payment there
// would never arrive, and the poller would never report it either.
func TestBillReconcileFindsALedgerEntryTheWalletDoesNotHave(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out)

	ledger, err := loadBillSubaddresses(billLedgerPath(out))
	if err != nil {
		t.Fatal(err)
	}
	ledger[9] = billSubaddress{Address: "8SUBGHOST0000000000000000000000000000000000001", User: "deadbeef", Order: "ord-9"}
	if err := saveBillSubaddresses(billLedgerPath(out), ledger); err != nil {
		t.Fatal(err)
	}

	logs, err := runReconcile(t, exe, w.srv.URL, out)
	if err == nil {
		t.Fatalf("reconcile accepted a ledger entry the wallet does not have:\n%s", logs)
	}
	for _, want := range []string{
		"DRIFT  1 ledger entr(y/ies) the wallet does not back",
		"minor 9",
		"the wallet has no address at this index",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("output missing %q:\n%s", want, logs)
		}
	}
}

// Same index, different address: the ledger names an address the wallet does not
// associate with that index, so a payment to the recorded one is unattributable.
func TestBillReconcileCatchesAnAddressMismatch(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out)

	ledger, err := loadBillSubaddresses(billLedgerPath(out))
	if err != nil {
		t.Fatal(err)
	}
	e := ledger[3]
	e.Address = "8SUBWRONG0000000000000000000000000000000000002"
	ledger[3] = e
	if err := saveBillSubaddresses(billLedgerPath(out), ledger); err != nil {
		t.Fatal(err)
	}

	logs, err := runReconcile(t, exe, w.srv.URL, out)
	if err == nil {
		t.Fatalf("reconcile accepted a mismatched address:\n%s", logs)
	}
	if !strings.Contains(logs, "not the recorded one") {
		t.Errorf("the reason should say the addresses differ:\n%s", logs)
	}
}

// `-json` is what an alert would consume: the drift has to be in the document,
// not only in the text.
func TestBillReconcileJSON(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out)
	w.seedWalletAddress(2, "probe:shape", true)

	logs, err := runReconcile(t, exe, w.srv.URL, out, "-json")
	if err == nil {
		t.Fatalf("drift should still exit non-zero in JSON mode:\n%s", logs)
	}
	var report struct {
		Account int    `json:"account"`
		Wallet  int    `json:"wallet_addresses"`
		Ledger  int    `json:"ledger_entries"`
		Primary string `json:"primary_address"`
		Matched []struct {
			Minor int `json:"minor"`
		} `json:"matched"`
		WalletOnly []struct {
			Minor uint32 `json:"minor"`
			Label string `json:"wallet_label"`
			Adopt string `json:"adopt"`
		} `json:"wallet_only"`
		LedgerOnly []struct {
			Minor int `json:"minor"`
		} `json:"ledger_only"`
	}
	if err := json.Unmarshal([]byte(logs), &report); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, logs)
	}
	if report.Account != 0 || report.Wallet != 3 || report.Ledger != 1 || len(report.Matched) != 1 {
		t.Errorf("report counts = %+v", report)
	}
	if report.Primary == "" {
		t.Error("the primary address should be reported (and excluded from drift)")
	}
	if len(report.WalletOnly) != 1 || report.WalletOnly[0].Minor != 2 || report.WalletOnly[0].Label != "probe:shape" {
		t.Fatalf("wallet_only = %+v", report.WalletOnly)
	}
	if !strings.Contains(report.WalletOnly[0].Adopt, "-adopt 2") {
		t.Errorf("proposal = %q, want a runnable adopt command", report.WalletOnly[0].Adopt)
	}
	if len(report.LedgerOnly) != 0 {
		t.Errorf("ledger_only = %+v, want none", report.LedgerOnly)
	}
}

// An unreachable wallet must fail the check. Reading it as "no drift" is the same
// mistake tally refuses to make with a proof it cannot verify.
func TestBillReconcileUnreachableWalletFails(t *testing.T) {
	exe := buildSporeBinary(t)
	out := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	logs, err := runReconcile(t, exe, "http://127.0.0.1:1/json_rpc", out)
	if err == nil {
		t.Fatalf("an unreachable wallet was read as agreement:\n%s", logs)
	}
	if strings.Contains(logs, "the ledger and the wallet agree") {
		t.Errorf("unreachable wallet reported agreement:\n%s", logs)
	}
}

// Adoption refuses the cases where recording something would create a lie: an
// index already in the ledger, an index the wallet does not have, a label that
// contradicts -order, and a customer who already owns an address.
func TestBillAddressAdoptRefusals(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	out := filepath.Join(t.TempDir(), "out")
	issueOne(t, exe, w, out) // minor 3 -> cc4f19a2, ord-41
	w.seedWalletAddress(5, "order:ord-55", false)

	adopt := func(extra ...string) (string, error) {
		args := append([]string{"bill", "address", "-rpc", w.srv.URL, "-out", out,
			"-user", "deadbeef", "-adopt", "5"}, extra...)
		return runSpore(t, exe, args...)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"an index the ledger already has", []string{"-adopt", "3", "-user", "deadbeef"}, "already records subaddress 3"},
		{"an index the wallet does not have", []string{"-adopt", "9", "-user", "deadbeef"}, "has no subaddress 9"},
		{"an order the label contradicts", []string{"-order", "ord-99"}, "have to agree"},
		{"a customer who already owns an address", []string{"-user", "cc4f19a2"}, "already owns subaddress"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"bill", "address", "-rpc", w.srv.URL, "-out", out, "-adopt", "5", "-user", "deadbeef"}, c.args...)
			logs, err := runSpore(t, exe, args...)
			if err == nil {
				t.Fatalf("adopt accepted %s:\n%s", c.name, logs)
			}
			if !strings.Contains(logs, c.want) {
				t.Errorf("output should mention %q:\n%s", c.want, logs)
			}
		})
	}

	// Nothing was written by any refusal, and the wallet was never asked to mint.
	ledger, err := loadBillSubaddresses(billLedgerPath(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger) != 1 {
		t.Errorf("ledger changed during refusals: %+v", ledger)
	}
	if issued, _ := w.stats(); len(issued) != 1 {
		t.Errorf("create_address was called %d times, want only the original issuance", len(issued))
	}

	// The honest adoption still works afterwards.
	logs, err := adopt()
	if err != nil {
		t.Fatalf("adopt 5: %v\n%s", err, logs)
	}
	if !strings.Contains(logs, "adopted") || !strings.Contains(logs, "ord-55") {
		t.Errorf("adopt should take the order from the wallet label:\n%s", logs)
	}
}

// The startup check `bill watch` makes must answer the same question reconcile
// does, against every attribution source — and must not call a labelled address
// drift, because a warning nobody can act on is how a real one gets ignored.
func TestFindBillStartupDrift(t *testing.T) {
	wallet := []xmr.WalletAddress{
		{Index: 0, Address: "8PRIMARY", Label: "Primary account"},
		{Index: 3, Address: "8THREE", Label: "order:ord-41", Used: true},
		{Index: 5, Address: "8FIVE", Label: "order:ord-55", Used: true},
	}
	ledger := map[uint32]billSubaddress{
		3: {User: "cc4f19a2", Order: "ord-41", Address: "8THREE"},
		9: {User: "deadbeef", Order: "ord-99", Address: "8NINE"},
	}

	t.Run("a ledger in step reports nothing", func(t *testing.T) {
		inStep := map[uint32]billSubaddress{
			3: {User: "cc4f19a2", Order: "ord-41", Address: "8THREE"},
			5: {User: "deadbeef", Order: "ord-55", Address: "8FIVE"},
		}
		d := findBillStartupDrift(map[uint32]string{3: "cc4f19a2", 5: "deadbeef"}, inStep, wallet, "subaddresses.json")
		if !d.empty() {
			t.Errorf("a clean ledger produced drift: %+v", d)
		}
	})

	t.Run("the crash case is reported with the command that fixes it", func(t *testing.T) {
		d := findBillStartupDrift(map[uint32]string{3: "cc4f19a2"}, map[uint32]billSubaddress{
			3: {User: "cc4f19a2", Order: "ord-41", Address: "8THREE"},
		}, wallet, "subaddresses.json")
		if len(d.Unlabelled) != 1 || d.Unlabelled[0].Minor != 5 {
			t.Fatalf("want only minor 5 unlabelled (minor 0 is the account's own, minor 3 is labelled): %+v", d.Unlabelled)
		}
		for _, want := range []string{"-adopt 5", "-order ord-55"} {
			if !strings.Contains(d.Unlabelled[0].Adopt, want) {
				t.Errorf("the proposal %q should carry %q", d.Unlabelled[0].Adopt, want)
			}
		}
	})

	t.Run("a hand-written map still counts as attribution", func(t *testing.T) {
		// Both wallet addresses come from the legacy map alone: no ledger at all,
		// which is a wallet labelled before `bill address` existed.
		d := findBillStartupDrift(map[uint32]string{3: "cc4f19a2", 5: "deadbeef"}, nil, wallet, "subaddresses.json")
		if !d.empty() {
			t.Errorf("addresses the -xmr-subaddresses map names were reported as drift: %+v", d)
		}
	})

	t.Run("a ledger entry the wallet does not back is drift too", func(t *testing.T) {
		d := findBillStartupDrift(map[uint32]string{3: "cc4f19a2", 9: "deadbeef"}, ledger, wallet, "subaddresses.json")
		if len(d.Unbacked) != 1 || d.Unbacked[0].Minor != 9 {
			t.Fatalf("want minor 9 unbacked: %+v", d.Unbacked)
		}
		if !strings.Contains(d.Unbacked[0].Reason, "no address at this index") {
			t.Errorf("the reason should say what is wrong: %q", d.Unbacked[0].Reason)
		}
	})
}

// The daemon reports the drift BEFORE the payment that would expose it, and still
// bills: taking billing down because a recovery check is unhappy would make the
// check the outage. This is the crash case end to end — issue an address, lose the
// ledger entry, restart the poller.
func TestBillWatchReportsStartupDriftAndStillBills(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	issueOne(t, exe, w, out)
	// The address create_address made and the ledger write that never happened.
	w.seedWalletAddress(5, "order:ord-77", true)

	logs, err := runBillWatch(t, exe, append(billWatchXMRBase(dir, w.srv.URL, out), "-xmr-unverified")...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero on drift alone: %v\n%s", err, logs)
	}
	for _, want := range []string{
		"STARTUP DRIFT minor 5",
		"will be held, unattributed",
		"record it before it is paid",
		"-adopt 5",
		"-order ord-77",
		"1 drift(s)",
		"DRY-RUN would provision", // the in-step address still bills
		"user=cc4f19a2",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("startup output missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "in step with the ledger") {
		t.Errorf("a drifted ledger reported agreement:\n%s", logs)
	}
}

// The other direction is worse than an unrecorded address: a payment to it never
// arrives at all, so no hold, no refusal, no record — just a customer who paid and
// a mailbox that never appears. The startup check has to name it.
func TestBillWatchReportsALedgerEntryTheWalletDoesNotBack(t *testing.T) {
	exe := buildSporeBinary(t)
	w := newSubaddressWallet(t, 3)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	issueOne(t, exe, w, out)
	ledger, err := loadBillSubaddresses(billLedgerPath(out))
	if err != nil {
		t.Fatal(err)
	}
	ledger[9] = billSubaddress{Address: "8NINEnevermade", User: "deadbeef", Order: "ord-99"}
	if err := saveBillSubaddresses(billLedgerPath(out), ledger); err != nil {
		t.Fatal(err)
	}

	logs, err := runBillWatch(t, exe, append(billWatchXMRBase(dir, w.srv.URL, out), "-xmr-unverified")...)
	if err != nil {
		t.Fatalf("bill watch exited non-zero on drift alone: %v\n%s", err, logs)
	}
	for _, want := range []string{
		"minor 9",
		"deadbeef",
		"does not back it",
		"never arrive and never be reported",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("startup output missing %q:\n%s", want, logs)
		}
	}
}

// Label parsing is what makes adoption safe: only a label written as order:<id>
// names an order, and anything else stays unlabelled rather than inventing one.
func TestOrderFromLabel(t *testing.T) {
	for label, want := range map[string]string{
		"order:ord-41":    "ord-41",
		"order:":          "",
		"probe:shape":     "",
		"Primary account": "",
		"order:has space": "",
		"":                "",
	} {
		got, ok := orderFromLabel(label)
		if want == "" {
			if ok {
				t.Errorf("%q was read as order %q", label, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q -> (%q, %v), want %q", label, got, ok, want)
		}
	}
}
