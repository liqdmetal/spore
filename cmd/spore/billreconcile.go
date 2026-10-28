package main

// bill reconcile — diff the issued-address ledger against the wallet.
//
// Issuance has exactly one failure hole: create_address succeeds and the ledger
// write does not (a crash, a full disk, a process killed between the two). The
// wallet then owns an address spore never learned, and a payment to it is held
// forever with no name attached — money that arrived and cannot be attributed.
// The wallet's label is what makes that recoverable, and this command is the
// lookup: it reports every address the wallet has that the ledger does not know
// (with the exact `bill address -adopt` command to fix it), and the opposite
// direction too, which is worse — a ledger entry the wallet does not back, whose
// payments would never arrive and never be reported.
//
// Read-only, and it exits non-zero on any drift so a cron or an alert can watch
// it. Nothing here writes the ledger: adoption is a decision about which customer
// an address belongs to, and a tool that guessed one would attribute money to the
// wrong place, which is the failure this whole path exists to avoid.
//
//	spore bill reconcile -rpc URL -out DIR [-rpc-login u:p] [-addresses FILE] [-json]

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/liqdmetal/spore/internal/xmr"
)

// billReconcileMatched is one index the ledger and the wallet agree about.
type billReconcileMatched struct {
	Minor       uint32 `json:"minor"`
	User        string `json:"user"`
	Order       string `json:"order,omitempty"`
	Address     string `json:"address"`
	WalletLabel string `json:"wallet_label,omitempty"`
	Used        bool   `json:"used"`
}

// billReconcileWalletOnly is an address only the wallet knows, with the command
// that would record it.
type billReconcileWalletOnly struct {
	Minor       uint32 `json:"minor"`
	Address     string `json:"address"`
	WalletLabel string `json:"wallet_label,omitempty"`
	Used        bool   `json:"used"`
	Order       string `json:"order,omitempty"`
	Adopt       string `json:"adopt"`
}

// billReconcileLedgerOnly is a ledger entry the wallet does not back: either no
// address at that index, or a different address than the one recorded.
type billReconcileLedgerOnly struct {
	Minor   uint32 `json:"minor"`
	User    string `json:"user"`
	Order   string `json:"order,omitempty"`
	Address string `json:"address,omitempty"`
	Reason  string `json:"reason"`
}

// billReconcileReport is the whole answer, in one document.
type billReconcileReport struct {
	Account         uint32 `json:"account"`
	Ledger          string `json:"ledger"`
	WalletAddresses int    `json:"wallet_addresses"`
	LedgerEntries   int    `json:"ledger_entries"`
	// Primary is the account's own address (minor 0). It is reported, never
	// proposed: every account has one, no order is ever issued on it, and drift
	// that can never be fixed is not drift.
	Primary string `json:"primary_address,omitempty"`
	// Drift is len(WalletOnly)+len(LedgerOnly), in the document because a JSON
	// consumer should not have to count arrays to learn whether this is bad.
	Drift      int                       `json:"drift"`
	Matched    []billReconcileMatched    `json:"matched"`
	WalletOnly []billReconcileWalletOnly `json:"wallet_only"`
	LedgerOnly []billReconcileLedgerOnly `json:"ledger_only"`
}

func (r billReconcileReport) drift() int {
	return len(r.WalletOnly) + len(r.LedgerOnly)
}

func billReconcile(args []string) {
	fs := flag.NewFlagSet("bill reconcile", flag.ExitOnError)
	rpc := fs.String("rpc", "", "wallet RPC endpoint, e.g. http://127.0.0.1:18083/json_rpc")
	rpcLogin := fs.String("rpc-login", "", "wallet RPC credential: Digest on Monero")
	out := fs.String("out", "", "outbox directory `bill watch` uses (holds the ledger)")
	addresses := fs.String("addresses", "", "ledger path (default: OUT/subaddresses.json)")
	jsonOut := fs.Bool("json", false, "machine-readable report")
	timeout := fs.Duration("timeout", 30*time.Second, "wallet RPC timeout")
	_ = fs.Parse(args)

	if *rpc == "" {
		fmt.Fprintln(os.Stderr, "bill reconcile: -rpc is required")
		os.Exit(2)
	}
	// Either flag can name the ledger. `-out` is only the default's parent, so
	// demanding it beside an explicit -addresses refused a run that never read it
	// — and -addresses is the path the adopt command this check prints tells you
	// to edit, i.e. the one shape an operator is most likely to type.
	ledgerPath := *addresses
	if ledgerPath == "" {
		if *out == "" {
			fmt.Fprintln(os.Stderr, "bill reconcile: -out is required (or name the ledger with -addresses)")
			os.Exit(2)
		}
		ledgerPath = billLedgerPath(*out)
	}
	ledger, err := loadBillSubaddresses(ledgerPath)
	check(err)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	// The wallet is the authority on which indices exist; an unreachable wallet
	// must fail the run rather than read as "no drift", the same rule tally
	// applies to a proof it cannot check.
	wallet, err := xmr.GetAddresses(ctx, *rpc, *rpcLogin, 0)
	check(err)

	report := buildBillReconcileReport(ledger, wallet, ledgerPath)

	report.Drift = report.drift()
	if *jsonOut {
		raw, err := json.MarshalIndent(report, "", "  ")
		check(err)
		fmt.Println(string(raw))
	} else {
		printBillReconcile(report)
	}
	if report.Drift > 0 {
		// In JSON mode the document is the whole answer and stdout has to stay
		// parseable; the exit status carries the verdict.
		if !*jsonOut {
			fmt.Fprintf(os.Stderr, "bill reconcile: %d drift(s) between the wallet and %s\n", report.Drift, ledgerPath)
		}
		os.Exit(1)
	}
}

// buildBillReconcileReport compares one ledger with one wallet address list.
//
// Pure on purpose: `bill reconcile` prints it and exits on it, and `bill watch`
// logs the same comparison at startup — one implementation, so the daemon and the
// check can never disagree about what drift is.
func buildBillReconcileReport(ledger map[uint32]billSubaddress, wallet []xmr.WalletAddress, ledgerPath string) billReconcileReport {
	report := billReconcileReport{
		Account:         0,
		Ledger:          ledgerPath,
		WalletAddresses: len(wallet),
		LedgerEntries:   len(ledger),
	}
	byMinor := make(map[uint32]xmr.WalletAddress, len(wallet))
	for _, a := range wallet {
		byMinor[a.Index] = a
	}
	for _, minor := range sortedMinors(ledger) {
		e := ledger[minor]
		a, ok := byMinor[minor]
		if !ok {
			report.LedgerOnly = append(report.LedgerOnly, billReconcileLedgerOnly{
				Minor: minor, User: e.User, Order: e.Order, Address: e.Address,
				Reason: "the wallet has no address at this index",
			})
			continue
		}
		if e.Address != "" && e.Address != a.Address {
			report.LedgerOnly = append(report.LedgerOnly, billReconcileLedgerOnly{
				Minor: minor, User: e.User, Order: e.Order, Address: e.Address,
				Reason: fmt.Sprintf("the wallet's address at this index is %s, not the recorded one — a payment to the recorded address would not be attributable", shortAddress(a.Address)),
			})
			continue
		}
		report.Matched = append(report.Matched, billReconcileMatched{
			Minor: minor, User: e.User, Order: e.Order,
			Address: a.Address, WalletLabel: a.Label, Used: a.Used,
		})
	}
	for _, a := range wallet {
		if _, known := ledger[a.Index]; known {
			continue
		}
		// Minor 0 is the account's own address: it exists on every wallet, no order
		// is ever issued on it, and a payment there is a labelling decision for
		// -xmr-subaddresses rather than a missing entry. Reporting it as drift would
		// make reconcile fail forever and teach operators to ignore it.
		if a.Index == 0 {
			report.Primary = a.Address
			continue
		}
		order, _ := orderFromLabel(a.Label)
		w := billReconcileWalletOnly{
			Minor: a.Index, Address: a.Address, WalletLabel: a.Label, Used: a.Used, Order: order,
		}
		// The proposal is a command, not a sentence: whoever reads it can run it,
		// and the only thing left to decide is which customer the address pays for.
		// The path is spelled the way `bill address` takes it — a ledger path, not
		// the outbox directory — so the command in the output is the one that works.
		w.Adopt = fmt.Sprintf("spore bill address -addresses %s -adopt %d -user NAME", ledgerPath, a.Index)
		if order != "" {
			w.Adopt += " -order " + order
		}
		report.WalletOnly = append(report.WalletOnly, w)
	}
	report.Drift = report.drift()
	return report
}

// billStartupDrift is what `bill watch` needs to say before it starts billing:
// addresses the wallet holds that NOTHING labels (so a payment to them would be
// held), and ledger entries the wallet does not back (so a payment to them would
// never arrive at all).
type billStartupDrift struct {
	// Unlabelled carries the adopt command, so the warning is an instruction.
	Unlabelled []billReconcileWalletOnly
	Unbacked   []billReconcileLedgerOnly
}

func (d billStartupDrift) empty() bool { return len(d.Unlabelled) == 0 && len(d.Unbacked) == 0 }

// findBillStartupDrift answers the startup question against EVERY attribution
// source, not just the ledger: a -xmr-subaddresses map naming an address counts as
// attributed, or an operator who still uses the old map would be warned about
// every address they had already labelled — a warning they cannot act on, which
// is how a real one gets ignored.
func findBillStartupDrift(labels map[uint32]string, ledger map[uint32]billSubaddress, wallet []xmr.WalletAddress, ledgerPath string) billStartupDrift {
	report := buildBillReconcileReport(ledger, wallet, ledgerPath)
	var d billStartupDrift
	for _, w := range report.WalletOnly {
		if _, labelled := labels[w.Minor]; labelled {
			continue
		}
		d.Unlabelled = append(d.Unlabelled, w)
	}
	d.Unbacked = report.LedgerOnly
	return d
}

// billStartupDriftTimeout bounds the one wallet call the startup check makes. It
// is a daemon: a wallet that accepts the connection and then says nothing must
// not keep billing from starting.
const billStartupDriftTimeout = 30 * time.Second

// reportBillStartupDrift checks the wallet against every attribution source once,
// at startup, and says what it found before the first payment can land.
//
// This runs because the drift it reports is silent by construction. An address
// create_address made without the ledger write that should follow it is money
// waiting to arrive with no name attached: the poller will refuse it as
// unlabelled, hold it, and look exactly as healthy as one that had nothing to do
// — the failure MONERO_SETTLEMENT §3 exists to prevent. The check is upstream of
// that: it names the address on the next restart rather than when the customer's
// payment arrives and gets held.
//
// It never stops the poller. A wallet that will not answer get_address is a
// problem the poll itself reports every interval, and taking billing down
// because the check that watches billing is unhappy would be the check causing
// the outage. What it must not do is stay quiet about having failed: silence and
// agreement would then look the same.
func reportBillStartupDrift(rpcURL, login, ledgerPath string, labels map[uint32]string, ledger map[uint32]billSubaddress) {
	ctx, cancel := context.WithTimeout(context.Background(), billStartupDriftTimeout)
	defer cancel()
	wallet, err := xmr.GetAddresses(ctx, rpcURL, login, 0)
	if err != nil {
		log.Printf("bill watch: could NOT check %s against the wallet at startup: %v — this is not \"in step\"; run `spore bill reconcile -out %s` once the wallet answers", ledgerPath, err, filepath.Dir(ledgerPath))
		return
	}

	d := findBillStartupDrift(labels, ledger, wallet, ledgerPath)
	if d.empty() {
		log.Printf("bill watch: %d wallet address(es) in step with the ledger (%s)", len(wallet), ledgerPath)
		return
	}
	for _, w := range d.Unlabelled {
		log.Printf("bill watch: STARTUP DRIFT minor %d has no attribution anywhere: a payment to it will be held, unattributed (%s)", w.Minor, shortAddress(w.Address))
		log.Printf("bill watch:   record it before it is paid: %s", w.Adopt)
	}
	for _, l := range d.Unbacked {
		log.Printf("bill watch: STARTUP DRIFT the ledger names minor %d for %q (%s) but the wallet does not back it: %s — a payment to it would never arrive and never be reported", l.Minor, l.User, orderOrDash(l.Order), l.Reason)
	}
	log.Printf("bill watch: %d drift(s) between %s and the wallet; billing starts anyway, but an unrecorded address cannot be attributed until it is recorded", len(d.Unlabelled)+len(d.Unbacked), ledgerPath)
}

func printBillReconcile(r billReconcileReport) {
	fmt.Printf("wallet      %d address(es) on account %d\n", r.WalletAddresses, r.Account)
	fmt.Printf("ledger      %d entr(y/ies) (%s)\n", r.LedgerEntries, r.Ledger)
	if r.Primary != "" {
		fmt.Printf("primary     minor 0 is the account's own address, not an order address (%s)\n", shortAddress(r.Primary))
		fmt.Println("            a payment there is held until -xmr-subaddresses labels it")
	}
	if len(r.Matched) > 0 {
		fmt.Printf("in step     %d\n", len(r.Matched))
		for _, m := range r.Matched {
			fmt.Printf("  minor %-3d -> %s (%s)%s\n", m.Minor, m.User, orderOrDash(m.Order), reconcileNotes(m.Used, m.WalletLabel))
		}
	}
	if len(r.WalletOnly) > 0 {
		fmt.Printf("\nDRIFT  %d address(es) on the wallet that the ledger does not know\n", len(r.WalletOnly))
		for _, w := range r.WalletOnly {
			fmt.Printf("  minor %-3d %s%s\n", w.Minor, reconcileNotes(w.Used, w.WalletLabel), "")
			fmt.Printf("           %s\n", shortAddress(w.Address))
			fmt.Printf("           record it: %s\n", w.Adopt)
		}
	}
	if len(r.LedgerOnly) > 0 {
		fmt.Printf("\nDRIFT  %d ledger entr(y/ies) the wallet does not back\n", len(r.LedgerOnly))
		for _, l := range r.LedgerOnly {
			fmt.Printf("  minor %-3d -> %s (%s)\n", l.Minor, l.User, orderOrDash(l.Order))
			fmt.Printf("           %s\n", l.Reason)
		}
	}
	if r.Drift == 0 {
		fmt.Println("\nthe ledger and the wallet agree")
	}
}

// reconcileNotes renders the two wallet facts worth seeing beside a row: whether
// anything ever arrived there, and what the wallet calls it.
func reconcileNotes(used bool, label string) string {
	u := "unused"
	if used {
		u = "used"
	}
	if label == "" {
		return "  [" + u + ", unlabelled]"
	}
	return "  [" + u + ", label " + label + "]"
}

// shortAddress keeps a full address out of a log line while still naming it.
func shortAddress(addr string) string {
	if len(addr) <= 16 {
		return addr
	}
	return addr[:8] + "…" + addr[len(addr)-6:]
}
