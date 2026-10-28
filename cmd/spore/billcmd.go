// bill — the hosted-mailbox billing orchestrator (BUSINESS.md Line 1, first
// dollar). One wallet RPC, one price, and every matching incoming transfer
// becomes a provisioned mailbox.
//
//	spore bill watch -rpc http://127.0.0.1:20209/json_rpc -rpc-login u:p \
//	  -users /srv/spore/users -tokens /srv/spore/tokens.json \
//	  -price 25dero -batch-dir /srv/spore/batches -out /srv/spore/billed \
//	  [-relay-fwd-tokens /srv/spore/relay/fwd-tokens.json] \
//	  [-on-provision /usr/local/sbin/spore-mailbox-onboard.sh] \
//	  [-interval 30s] [-once] [-dry-run]
//
// For each new incoming transfer >= -price it provisions the mailbox (spore
// provision, which writes dir + token + notify + onboarding record), merges
// the user's token into the relay forward-token map, drops the onboarding
// record into -out, and runs -on-provision (env: USER, TOKEN, MAILBOX, PRICE,
// TXID) when given — the hook's job is delivery: email/webhook/paste the
// onboarding card to the customer. The batch file must already sit at
// <batch-dir>/<user>.json (it comes from the customer's device); payments
// whose batch is missing are held, and the poll watermark is pinned at their
// height so later polls re-read them (see nextBillWatermark — a hold that the
// wallet never returns again is not a hold, it is a lost payment).
//
// Monero is a second rail on the same orchestrator, in billxmr.go: `-price
// 2.5xmr` bills off monero-wallet-rpc. Monero carries no sender field, so the
// payer is identified by the address that was paid — one fresh subaddress per
// order, issued by `spore bill address` (billaddr.go) and read back from the
// ledger it writes, with an optional -xmr-subaddresses file merged in for a
// wallet labelled before that existed. The rail is gated behind -xmr-unverified
// because no real payment has arrived on a per-order subaddress yet
// (MONERO_SETTLEMENT §5, §8 step 5) — the whole chain has run once against the
// live wallet in the meantime (2026-10-27/28). On that rail the
// outbox receipt carries the receiving wallet's get_tx_proof over a claim bound
// to the receipt itself, verified by that wallet before the record is written, so
// the evidence travels in the record rather than beside it (§8 step 4).
// Everything downstream — provisioning, the token merge, the onboarding record,
// the hook — is shared and unchanged.
//
// Re-runs are safe: progress lives in <out>/bill-state.json.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func billcmd(args []string) {
	if len(args) == 0 {
		billUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "watch":
		billWatch(args[1:])
	case "address":
		billAddress(args[1:])
	case "reconcile":
		billReconcile(args[1:])
	case "-h", "--help", "help":
		billUsage()
	default:
		fmt.Fprintf(os.Stderr, "bill: unknown subcommand %q (want watch, address or reconcile)\n", args[0])
		os.Exit(2)
	}
}

func billUsage() {
	fmt.Fprint(os.Stderr, `spore bill — hosted mailbox billing orchestrator

  watch      poll a wallet RPC and provision paid mailboxes
  address    issue one fresh Monero subaddress for one order, and record it
  reconcile  diff the issued-address ledger against the wallet (exit 1 on drift)

watch flags:
  -rpc URL            wallet RPC endpoint (e.g. http://127.0.0.1:20209/json_rpc)
  -rpc-login u:p      wallet RPC credential: Basic on DERO, Digest on Monero
                      (the Monero wallet refuses a valid Basic header with 401)
  -price AMOUNT       minimum payment, e.g. 25dero (atomic-exact)
  -users DIR          hosted users directory (same as `+"`mailbox host -users`"+`)
  -tokens FILE        bearer token JSON map (same as `+"`mailbox host -tokens`"+`)
  -batch-dir DIR      customer prekey batches: <user>.json (provision requires it)
  -out DIR            outbox: onboarding records + bill-state.json
  -relay-fwd-tokens F optional: relay forward-token map to merge the new user into
  -on-provision S     optional hook script; env USER/TOKEN/MAILBOX/PRICE/TXID
  -interval D         poll interval (default 30s)
  -once               single poll, then exit (for cron or a test)
  -dry-run            report what would happen, change nothing

monero flags (only with a -price in xmr; EXPERIMENTAL, see
MONERO_SETTLEMENT.md §5 — one live payment has been carried through provisioning
into a receipt against a v0.18.5.1 wallet, and that receipt now carries the
wallet's own tx proof, but no real payment has arrived on a per-order
subaddress):
  -xmr-unverified     required to bill xmr at all; says every result is suspect
  -addresses F        issued-address ledger (default: OUT/subaddresses.json,
                      written by `+"`spore bill address`"+`)
  -xmr-subaddresses F optional hand-written map of subaddress minor index ->
                      hosted user, merged with the ledger (conflicts refused)
  -xmr-confirmations N confirmations before provisioning (default 10; 0 refused)

on the Monero rail, `+"`watch`"+` also compares the issued-address ledger with
the wallet once at startup, so an address nothing labels is reported before a
payment lands on it. Drift is a warning, not a failure: `+"`bill reconcile`"+` is
the same check on demand, with exit 1.

bill address flags:
  -rpc URL            wallet RPC endpoint (required)
  -rpc-login u:p      wallet RPC credential (Digest on Monero)
  -out DIR            outbox directory `+"`bill watch`"+` uses; the ledger lands here
  -addresses F        ledger path (default: OUT/subaddresses.json)
  -user NAME          hosted mailbox the address pays for (required)
  -order ID           your order reference, recorded against the address
  -adopt N            record subaddress N, which the wallet already has (recovery;
                      `+"`bill reconcile`"+` prints the exact command)

bill reconcile flags:
  -rpc URL            wallet RPC endpoint (required)
  -rpc-login u:p      wallet RPC credential (Digest on Monero)
  -out DIR            outbox directory holding the ledger (required)
  -addresses F        ledger path (default: OUT/subaddresses.json)
  -json               machine-readable report
`)
}

// billEntry is the slice of the wallet RPC transfer entry bill reads. The shape
// is DERO's: get_transfers returns result.entries with a sender-tagged incoming
// bool and atomic DERO amounts. Monero answers get_transfers under result.in[]
// with integer piconero and NO sender field at all, so an XMR price cannot be
// billed by this poller — see docs/MONERO_SETTLEMENT.md §5 for what has to be
// built first (per-order subaddress attribution).
type billEntry struct {
	Height   uint64 `json:"height"`
	TXID     string `json:"txid"`
	Incoming bool   `json:"incoming"`
	Amount   uint64 `json:"amount"` // atomic DERO (1 DERO = 100000)
}

type billState struct {
	Height uint64            `json:"height"`
	Done   map[string]string `json:"done"` // txid -> provisioned user
	Held   map[string]string `json:"held"` // txid -> user (batch missing)
	// XMRRefused is the Monero branch's LAST POLL: txid -> why it was not billed.
	// Rebuilt each poll, so a transfer that gets provisioned (or becomes
	// billable) disappears from it. It exists because the log scrolls away and
	// "the poller refused this and here is why" is the question an operator
	// actually asks. Empty on the DERO path.
	XMRRefused map[string]string `json:"xmr_refused,omitempty"`
}

type paymentPlan struct {
	TXID   string
	Height uint64
	Amount uint64
	User   string
	// Address is the receiving address the wallet reported for this transfer.
	// Empty on the DERO rail, which decodes no address; on Monero it is what a
	// tx proof answers for, and the poller refuses to bill without it.
	Address string
}

var billUserNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,15}$`)

// planPayments is the pure decision core: given the price, new incoming
// entries, and the txids already handled, return the payments to provision.
// A username is derived deterministically from the txid; two txids whose
// derived names collide are handled once (the second is skipped) so a later
// -force provision can never overwrite an earlier paid account.
func planPayments(price uint64, entries []billEntry, done map[string]string) []paymentPlan {
	var out []paymentPlan
	usedUsers := make(map[string]string, len(done)+len(entries)) // user -> first txid
	for _, u := range done {
		usedUsers[u] = u
	}
	for _, e := range entries {
		if !e.Incoming || e.Amount < price {
			continue
		}
		if _, seen := done[e.TXID]; seen {
			continue
		}
		user := "c" + e.TXID
		if len(user) > 16 {
			user = user[:16]
		}
		if _, clash := usedUsers[user]; clash {
			continue // derived-name collision: keep the first payer's account
		}
		usedUsers[user] = e.TXID
		out = append(out, paymentPlan{TXID: e.TXID, Height: e.Height, Amount: e.Amount, User: user})
	}
	return out
}

// nextBillWatermark is the min_height for the next poll: the highest height seen,
// pulled back to the oldest transfer that must be re-read.
//
// This exists because a deferred transfer is only ever seen again by being
// fetched again. min_height is an inclusive >= filter on both rails — DERO R153
// filters block height directly (internal/dero, internal/whisper), Monero gates
// the same behaviour on filter_by_height — so the boundary height re-matches and
// a deferred transfer stays visible until it is billed or becomes un-billable.
//
// A height of 0 is never pinned: it cannot be re-fetched by height, and pinning
// on one would ask the wallet for its entire history on every poll.
func nextBillWatermark(highest uint64, deferred []uint64) uint64 {
	next := highest
	for _, h := range deferred {
		if h == 0 {
			continue
		}
		if next == 0 || h < next {
			next = h
		}
	}
	return next
}

func billWatch(args []string) {
	fs := flag.NewFlagSet("bill watch", flag.ExitOnError)
	rpc := fs.String("rpc", "", "wallet RPC endpoint")
	rpcLogin := fs.String("rpc-login", "", "wallet RPC basic auth user:pass")
	price := fs.String("price", "", "minimum payment (e.g. 25dero)")
	users := fs.String("users", "", "hosted users directory")
	tokens := fs.String("tokens", "", "bearer token JSON map")
	batchDir := fs.String("batch-dir", "", "customer prekey batch directory (<user>.json)")
	out := fs.String("out", "", "outbox directory")
	relayTokens := fs.String("relay-fwd-tokens", "", "optional relay forward-token map to merge into")
	hook := fs.String("on-provision", "", "optional hook script; env USER/TOKEN/MAILBOX/PRICE/TXID")
	interval := fs.Duration("interval", 30*time.Second, "poll interval")
	once := fs.Bool("once", false, "single poll, then exit")
	dryRun := fs.Bool("dry-run", false, "report only, change nothing")
	xmrUnverified := fs.Bool("xmr-unverified", false, "bill -price xmr: no real payment has arrived on a per-order subaddress — treat every result as experimental")
	xmrSubaddresses := fs.String("xmr-subaddresses", "", "optional hand-written JSON map of Monero subaddress minor index -> hosted user; merged with the issued-address ledger")
	addresses := fs.String("addresses", "", "issued-address ledger written by `spore bill address` (default: OUT/subaddresses.json)")
	xmrConfirmations := fs.Uint64("xmr-confirmations", 10, "confirmations a Monero payment needs before a mailbox is provisioned (0 is refused)")
	_ = fs.Parse(args)

	if *rpc == "" || *price == "" || *users == "" || *tokens == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "bill watch: -rpc -price -users -tokens -out are required")
		os.Exit(2)
	}
	if *batchDir == "" {
		fmt.Fprintln(os.Stderr, "bill watch: -batch-dir is required (customer prekey batches land here)")
		os.Exit(2)
	}
	asset, priceAtomic, err := parseAmountFlag(*price)
	if err != nil {
		check(err)
	}
	if err := billAssetAllowed(asset, *xmrUnverified); err != nil {
		check(err)
	}
	// The Monero branch needs the two things Monero cannot supply about itself:
	// who a payment belongs to (the label map) and how final it has to be (the
	// confirmation floor). Both are refused up front rather than at poll time.
	var (
		xmrLabels map[uint32]string
		xmrFloor  uint64
	)
	if asset == "xmr" {
		// Attribution comes from the ledger `spore bill address` writes, because
		// issuing the address and recording the order are one step that cannot
		// disagree with itself. A hand-written map still merges in, for a wallet
		// whose addresses were labelled before the ledger existed.
		ledgerPath := *addresses
		if ledgerPath == "" {
			ledgerPath = billLedgerPath(*out)
		}
		issued, err := loadBillSubaddresses(ledgerPath)
		if err != nil {
			check(err)
		}
		var legacy map[uint32]string
		if *xmrSubaddresses != "" {
			legacy, err = loadXMRSubaddresses(*xmrSubaddresses)
			if err != nil {
				check(err)
			}
		}
		xmrLabels, err = mergeBillLabels(issued, legacy, *xmrSubaddresses)
		if err != nil {
			check(err)
		}
		if len(xmrLabels) == 0 {
			check(fmt.Errorf("%w: issue one with `spore bill address -out %s -user NAME -order ID`, or pass -xmr-subaddresses FILE (docs/MONERO_SETTLEMENT.md §3)", errNoLedgerSource, *out))
		}
		if *xmrConfirmations == 0 {
			check(errors.New("bill watch: -xmr-confirmations 0 is refused: a provisioned mailbox cannot be clawed back, and an unconfirmed payment can be reorged away (docs/MONERO_SETTLEMENT.md §5)"))
		}
		xmrFloor = *xmrConfirmations
		log.Printf("bill watch: XMR MODE IS EXPERIMENTAL — one live round trip completed 2026-10-27/28 (payment, provisioning and a receipt carrying the wallet's own tx proof), but no real payment has arrived on a per-order subaddress; %d subaddresses labelled from %s, floor %d confirmations", len(xmrLabels), ledgerPath, xmrFloor)
		// A ledger that disagrees with the wallet is silent until a payment lands
		// on the address nobody recorded, at which point the poller holds it as
		// unlabelled and looks healthy doing it. So the disagreement is reported
		// here, at startup, while there is still time to record the address.
		reportBillStartupDrift(*rpc, *rpcLogin, ledgerPath, xmrLabels, issued)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		check(err)
	}

	statePath := filepath.Join(*out, "bill-state.json")
	st := billState{Done: map[string]string{}, Held: map[string]string{}}
	if raw, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(raw, &st)
	}

	poll := func() (int, error) {
		var plans []paymentPlan
		var highest uint64
		// deferred collects the height of every transfer this poll could not bill
		// but has to see again: a Monero refusal that can still become payable, or
		// a payment held for a prekey batch that has not arrived yet.
		var deferred []uint64
		if asset == "xmr" {
			entries, h, err := billPollRPCXMR(*rpc, *rpcLogin, st.Height)
			if err != nil {
				return 0, err
			}
			var refusals []billXMRRefusal
			plans, refusals = planXMRPayments(priceAtomic, xmrFloor, xmrLabels, st.Done, entries)
			for _, r := range refusals {
				log.Printf("not billing txid=%s subaddress=%d: %s", r.TXID, r.Minor, r.Reason)
				if r.Retry {
					deferred = append(deferred, r.Height)
				}
			}
			st.XMRRefused = xmrRefusalSummary(refusals)
			highest = h
		} else {
			entries, h, err := billPollRPC(*rpc, *rpcLogin, st.Height)
			if err != nil {
				return 0, err
			}
			plans = planPayments(priceAtomic, entries, st.Done)
			highest = h
		}
		n := 0
		for _, p := range plans {
			if *dryRun {
				log.Printf("DRY-RUN would provision txid=%s user=%s amount=%d atomic (%s %s)", p.TXID, p.User, p.Amount, formatAmount(asset, p.Amount), asset)
				n++
				continue
			}
			batch := filepath.Join(*batchDir, p.User+".json")
			if _, err := os.Stat(batch); err != nil {
				log.Printf("txid=%s user=%s: batch %s missing — holding until it arrives", p.TXID, p.User, batch)
				st.Held[p.TXID] = p.User
				// Pin the watermark at this payment's height. Without it, the next
				// payment from a customer whose batch DID arrive advances the
				// watermark past this one, the wallet never returns it again, and a
				// paid customer is never provisioned — the hold would be a silent
				// hole rather than a wait. p.Height is DERO's block height, which is
				// exactly what get_transfers min_height filters.
				deferred = append(deferred, p.Height)
				continue
			}
			// The evidence is taken here, after the batch check and before the
			// record exists, because the wallet has to sign the claim the receipt
			// will make and only then can the record be written with it (§8 step 4).
			var ev billEvidence
			if asset == "xmr" {
				ev = billXMRProvePayment(*rpc, *rpcLogin, asset, p)
				if ev.Proof == nil {
					// Paid money, provisioned mailbox, no evidence: the one combination
					// that must shout. The receipt records the reason too, because the
					// log is the first thing to scroll away.
					log.Printf("txid=%s user=%s: NO CHAIN PROOF ATTACHED: %s — provisioning anyway, and %s.receipt.json records this", p.TXID, p.User, ev.Err, p.User)
				}
			}
			if err := billProvision(*users, *tokens, *batchDir, *out, asset, p, ev, *relayTokens, *hook); err != nil {
				log.Printf("txid=%s user=%s: provision failed: %v", p.TXID, p.User, err)
				continue
			}
			st.Done[p.TXID] = p.User
			delete(st.Held, p.TXID)
			delete(st.XMRRefused, p.TXID) // billed now: no longer a refusal
			n++
		}
		// The watermark is the highest height seen, pulled back to the oldest
		// deferred transfer. It is deliberately not clamped to st.Height: a hold
		// below the current watermark has to be fetched again, and min_height is
		// inclusive.
		if next := nextBillWatermark(highest, deferred); next != st.Height {
			st.Height = next
		}
		raw, _ := json.MarshalIndent(st, "", "  ")
		_ = os.WriteFile(statePath, append(raw, '\n'), 0o600)
		return n, nil
	}

	for {
		n, err := poll()
		if err != nil {
			log.Printf("poll error: %v", err)
		} else if n > 0 {
			log.Printf("provisioned %d mailbox(es) this pass", n)
		}
		if *once {
			return
		}
		time.Sleep(*interval)
	}
}

// billPollRPC calls wallet get_transfers {in:true, min_height: h} with basic
// auth. Returns the new incoming entries and the highest height seen.
func billPollRPC(rpcURL, login string, minHeight uint64) ([]billEntry, uint64, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "bill", "method": "get_transfers",
		"params": map[string]any{"in": true, "min_height": minHeight},
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if login != "" {
		u, p, ok := strings.Cut(login, ":")
		if ok {
			req.SetBasicAuth(u, p)
		}
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Entries []billEntry `json:"entries"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	if out.Error != nil {
		return nil, 0, errors.New(out.Error.Message)
	}
	var entries []billEntry
	maxH := minHeight
	for _, e := range out.Result.Entries {
		if !e.Incoming {
			continue
		}
		entries = append(entries, e)
		if e.Height > maxH {
			maxH = e.Height
		}
	}
	return entries, maxH, nil
}

// billMailbox is the public mailbox URL a paid account is provisioned at. It is
// one function because the URL is part of the claim a receipt's tx proof binds,
// and two spellings of it would make the proof and the record disagree.
func billMailbox(user string) string {
	return "https://mail.sporem3.io/u/" + user
}

// billProvision runs the shipped `spore provision` subprocess (same binary),
// merges the user into the relay forward-token map, files the onboarding
// record into the outbox, and runs the delivery hook. asset and ev travel into
// the outbox receipt: a record that cites a payment without saying which rail it
// was on (atomic units of what?) or without the chain's own evidence is a claim
// the operator cannot check later.
func billProvision(usersDir, tokensFile, batchDir, outDir, asset string, p paymentPlan, ev billEvidence, relayTokens, hook string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self: %w", err)
	}
	mailbox := billMailbox(p.User)
	cmd := exec.Command(self, "provision",
		"-users", usersDir, "-name", p.User,
		"-tokens", tokensFile,
		"-batch", filepath.Join(batchDir, p.User+".json"),
		"-mailbox-url", mailbox,
		"-force",
	)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("provision: %v: %s", err, strings.TrimSpace(string(b)))
	}
	// Relay forward-token merge: the relay presents this token on the last
	// hop to this user's mailbox. The relay itself still needs a restart (its
	// allowlist is startup config) — the hook or operator handles that.
	if relayTokens != "" {
		tok, err := billReadToken(usersDir, p.User)
		if err != nil {
			return err
		}
		raw, _ := os.ReadFile(relayTokens)
		m := map[string]string{}
		_ = json.Unmarshal(raw, &m)
		m[mailbox] = tok
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(relayTokens, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	// File the record: onboarding card + payment receipt.
	onboard, err := os.ReadFile(filepath.Join(usersDir, p.User, "onboarding.json"))
	if err != nil {
		return err
	}
	receipt := billReceiptRecord(asset, p, mailbox, time.Now().UTC().Format(time.RFC3339), ev)
	rb, _ := json.MarshalIndent(receipt, "", "  ")
	_ = os.WriteFile(filepath.Join(outDir, p.User+".onboarding.json"), onboard, 0o600)
	_ = os.WriteFile(filepath.Join(outDir, p.User+".receipt.json"), append(rb, '\n'), 0o600)
	if hook != "" {
		env := append(os.Environ(),
			"SPORE_BILL_USER="+p.User,
			"SPORE_BILL_TOKEN="+billReadTokenOr(usersDir, p.User, ""),
			"SPORE_BILL_MAILBOX="+mailbox,
			"SPORE_BILL_PRICE="+strconv.FormatUint(p.Amount, 10),
			"SPORE_BILL_TXID="+p.TXID,
		)
		c := exec.Command(hook)
		c.Env = env
		if b, err := c.CombinedOutput(); err != nil {
			log.Printf("hook %s: %v: %s", hook, err, strings.TrimSpace(string(b)))
		}
	}
	return nil
}

// billReceiptRecord is the outbox record for one billed payment: what was paid,
// who it was for, and — on the Monero rail — the wallet's own proof of that
// payment, or the reason there is none.
//
// It is its own function because it is the artifact. Key names follow
// JOB_RECEIPT_V1's settlement line (txid, amount_atomic) and its tx_proof block,
// so one reader can follow both documents, and asset travels with the amount
// because atomic units mean nothing without the rail they are denominated in.
func billReceiptRecord(asset string, p paymentPlan, mailbox, provisionedAt string, ev billEvidence) map[string]any {
	rec := map[string]any{
		"asset": asset, "txid": p.TXID, "height": p.Height, "amount_atomic": p.Amount,
		"user": p.User, "mailbox": mailbox, "provisioned_at": provisionedAt,
	}
	if ev.Proof != nil {
		rec["tx_proof"] = ev.Proof
	}
	if ev.Err != "" {
		rec["tx_proof_error"] = ev.Err
	}
	return rec
}

// billReadToken returns the user's bearer token from the tokens map.
func billReadToken(tokensFile, user string) (string, error) {
	t := billReadTokenOr(tokensFile, user, "")
	if t == "" {
		return "", fmt.Errorf("no token for user %q in %s", user, tokensFile)
	}
	return t, nil
}

func billReadTokenOr(tokensFile, user, fallback string) string {
	raw, err := os.ReadFile(tokensFile)
	if err != nil {
		return fallback
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return fallback
	}
	if t := m[user]; t != "" {
		return t
	}
	return fallback
}

// billConstTimeEq exists so the token merge can stay constant-time against
// the map lookup elsewhere; used by tests.
func billConstTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
