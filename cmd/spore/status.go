// status — the spore HUD: connection health at a glance.
//
//	spore status [-chain dero|evm|xmr|solana ...] [-mailbox ADDR] [-timeout 5s]
//
// Reports per configured chain whether the RPC/wallet endpoint is reachable,
// our address, and the current chain height — plus whether a mailbox (if one
// is configured/running) is serving. On the EVM path it also prints the
// configured MyceliumMailbox contract, the chain it belongs to, and whether it
// is a shipped default or the operator's own override, so the live contract is
// visible at a glance. It is the "am I actually connected?" sanity check
// before you try to send or receive.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/backend"
	"github.com/liqdmetal/spore/internal/chain"
	"github.com/liqdmetal/spore/internal/crypto"
	"github.com/liqdmetal/spore/internal/evm"
	"github.com/liqdmetal/spore/internal/handoff"
	"github.com/liqdmetal/spore/internal/ratchetwire"
)

// StatusJSONSchema versions the combined operational status report contract.
const StatusJSONSchema = "spore/status/v1"

type statusJSONCheck struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	NextAction string `json:"next_action,omitempty"`
}

type statusJSONSummary struct {
	Status   string `json:"status"`
	Checks   int    `json:"checks"`
	Errors   int    `json:"errors"`
	Warnings int    `json:"warnings"`
	Skipped  int    `json:"skipped"`
}

type statusJSONReport struct {
	Schema      string            `json:"schema"`
	ReadOnly    bool              `json:"read_only"`
	GeneratedAt string            `json:"generated_at"`
	Summary     statusJSONSummary `json:"summary"`
	Checks      []statusJSONCheck `json:"checks"`
}

func buildStatusJSONReport(probes []statusProbe, mailboxLine string, home, handoffDir, stateKeyPath string) (statusJSONReport, error) {
	return buildStatusJSONReportWithPool(probes, mailboxLine, home, handoffDir, stateKeyPath, "")
}

// buildStatusJSONReportWithPool is buildStatusJSONReport plus the prekey
// rejection check for the OPK pool at opkPool (empty: no pool, no check).
func buildStatusJSONReportWithPool(probes []statusProbe, mailboxLine string, home, handoffDir, stateKeyPath, opkPool string) (statusJSONReport, error) {
	report := statusJSONReport{Schema: StatusJSONSchema, ReadOnly: true, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Checks: []statusJSONCheck{}}
	add := func(id, status, detail, action string) {
		report.Checks = append(report.Checks, statusJSONCheck{ID: id, Status: status, Detail: detail, NextAction: action})
		switch status {
		case "error":
			report.Summary.Errors++
		case "warning":
			report.Summary.Warnings++
		case "skipped":
			report.Summary.Skipped++
		}
	}
	for _, p := range probes {
		if p.skipped {
			add("carrier-"+p.name, "skipped", p.detail, "Configure a carrier endpoint when this installation needs chain connectivity.")
		} else if p.ok {
			add("carrier-"+p.name, "ok", fmt.Sprintf("reachable; address=%s height=%d", p.address, p.height), "")
		} else {
			add("carrier-"+p.name, "error", p.detail, "Check the configured RPC, wallet, credentials, and network.")
		}
	}
	if mailboxLine != "" {
		if strings.Contains(mailboxLine, "⚠") {
			add("evm-mailbox", "warning", mailboxLine, "Confirm the mailbox contract matches the chain used by the RPC.")
		} else {
			add("evm-mailbox", "ok", mailboxLine, "")
		}
	}

	keyPath := stateKeyPath
	if keyPath == "" && home != "" {
		keyPath = filepath.Join(home, "state.key")
	}
	storePath := filepath.Join(handoffDir, "handoffs.enc")
	if handoffDir == "" {
		storePath = ""
	}
	if keyPath == "" || storePath == "" {
		add("handoffs", "skipped", "Encrypted handoff state is not configured; no state was created.", "Configure -state-dir and -state-key, then rerun status.")
	} else if _, err := os.Stat(storePath); os.IsNotExist(err) {
		add("handoffs", "ok", "No existing handoff store; nothing queued.", "")
	} else if err != nil {
		add("handoffs", "error", fmt.Sprintf("Cannot inspect handoff store path: %v", err), "Check the path and permissions without altering encrypted state.")
	} else {
		key, err := readHexFile(keyPath, 32)
		if err != nil {
			if os.IsNotExist(err) {
				add("handoffs", "error", "Handoff store exists but the configured state key file is missing.", "Restore the protected state key; do not initialize a replacement key over existing state.")
			} else {
				add("handoffs", "error", fmt.Sprintf("Cannot read configured state key: %v", err), "Check state-key path and permissions without exposing key contents.")
			}
		} else {
			rows, err := handoff.ReadOnlyListIncludingExpired(storePath, key)
			crypto.Zero(key)
			if err != nil {
				add("handoffs", "error", fmt.Sprintf("Cannot inspect encrypted handoff store: %v", err), "Verify the state key and preserve a backup before attempting recovery.")
			} else {
				active, expired, queued, blocked, waiting, providerReview, buyerDecision := 0, 0, 0, 0, 0, 0, 0
				for _, r := range rows {
					if r.Local.Address == "" {
						continue
					}
					if r.Latest().Terms.ExpiresAt <= time.Now().Unix() {
						expired++
						continue
					}
					active++
					if r.Status() == "brief" && r.Local == r.Latest().Terms.Provider {
						providerReview++
					}
					if r.Status() == "deliver" && r.Local == r.Latest().Terms.Buyer {
						buyerDecision++
					}
					for _, d := range r.Outbox {
						if d.Preparing {
							blocked++
						} else if !d.Sent && !d.ApplicationReceived {
							queued++
						} else if d.Sent && !d.ApplicationReceived {
							waiting++
						}
					}
				}
				switch {
				case blocked > 0:
					add("handoffs", "error", fmt.Sprintf("%d handoff(s); %d delivery preparation(s) are blocked.", active, blocked), "Do not re-encrypt or retry blindly; preserve state and use handoff recovery guidance.")
				case queued > 0:
					add("handoffs", "warning", fmt.Sprintf("%d handoff(s); %d event(s) queued locally.", active, queued), "Run `spore work-order handoff status` then `flush` after checking the pinned session.")
				case waiting > 0:
					add("handoffs", "warning", fmt.Sprintf("%d handoff(s); %d posted event(s) await signed peer-persistence receipts.", active, waiting), "Wait for a signed persistence receipt; posting is not proof of peer persistence or human approval.")
				default:
					add("handoffs", "ok", fmt.Sprintf("%d unexpired encrypted handoff record(s); local delivery queue clear.", active), "")
				}
				if providerReview > 0 || buyerDecision > 0 {
					add("handoff-human-action", "warning", fmt.Sprintf("%d provider brief review(s) and %d buyer deliverable decision(s) remain.", providerReview, buyerDecision), "Open each handoff, review the exact brief/result and policy, then explicitly deliver or accept/reject; persistence is not approval.")
				}
				if expired > 0 {
					add("handoffs-expired", "warning", fmt.Sprintf("%d expired encrypted handoff record(s) remain; status did not prune them.", expired), "Review retention policy, then run `spore work-order handoff prune` explicitly if appropriate.")
				}
			}
		}
	}

	journalDir := handoffDir
	if journalDir == "" {
		journalDir = filepath.Dir(keyPath)
	}
	if journalDir == "" || keyPath == "" {
		add("receive-recovery", "skipped", "Encrypted receive journal is not configured.", "Configure -state-dir and -state-key to inspect pending receive recovery.")
	} else {
		journalPath := filepath.Join(journalDir, "receive-pending.enc")
		if _, err := os.Stat(journalPath); err == nil {
			add("receive-recovery", "warning", "A receive journal exists and requires validation/recovery before more sends or receives.", "Run the relevant `msg recv-e2` or handoff recovery workflow; do not delete the journal.")
		} else if os.IsNotExist(err) {
			add("receive-recovery", "ok", "No pending application receive journal.", "")
		} else {
			return report, fmt.Errorf("status: inspect receive journal: %w", err)
		}
	}
	gapStateDir := handoffDir
	if gapStateDir == "" {
		gapStateDir = filepath.Join(home, "state")
	}
	if keyPath == "" {
		add("message-gaps", "skipped", "E2 state key is not configured; persistent gap status cannot be decrypted.", "Configure the state-key path to inspect durable E2 gap state.")
	} else if _, err := os.Stat(gapStateDir); os.IsNotExist(err) {
		add("message-gaps", "ok", "No E2 session state exists; no recoverable or confirmed message gaps are recorded.", "")
	} else if err != nil {
		add("message-gaps", "error", fmt.Sprintf("Cannot inspect E2 state directory: %v", err), "Check state directory and permissions without altering session files.")
	} else {
		key, err := readHexFile(keyPath, 32)
		if err != nil {
			add("message-gaps", "error", fmt.Sprintf("Cannot read E2 state key: %v", err), "Check state-key path and permissions without exposing key contents.")
		} else {
			gaps, err := ratchetwire.ReadOnlyGaps(gapStateDir, key, time.Now())
			crypto.Zero(key)
			if err != nil {
				add("message-gaps", "error", fmt.Sprintf("Cannot inspect durable E2 gaps: %v", err), "Verify the E2 state key and preserve a backup before attempting recovery.")
			} else if gaps.LossPersistenceError != "" {
				add("message-gaps", "error", fmt.Sprintf("Confirmed gaps could not be persisted: %s", gaps.LossPersistenceError), "Keep the active receiver output and repair the state-directory write failure before shutdown.")
			} else if gaps.ExpiredUnclassified > 0 {
				add("message-gaps", "warning", fmt.Sprintf("%d gap(s) exceeded their deadline while the receiver was stopped; they are not yet classified as confirmed loss.", gaps.ExpiredUnclassified), "Start `spore msg recv-e2` to sweep expired skipped keys and record confirmed losses.")
			} else if len(gaps.Pending) > 0 || gaps.LostTotal > 0 {
				add("message-gaps", "warning", fmt.Sprintf("%d recoverable gap(s), %d confirmed lost message(s).", len(gaps.Pending), gaps.LostTotal), "Keep the receiver running until pending gaps arrive or expire; confirmed losses cannot be decrypted again.")
				if gaps.LostTruncated {
					add("message-gaps-detail", "warning", fmt.Sprintf("The bounded loss ledger contains %d identities; count may be truncated.", len(gaps.Lost)), "Treat the count as a lower bound after the identity cap is reached.")
				}
			} else {
				add("message-gaps", "ok", "No recoverable or confirmed E2 message gaps recorded.", "")
			}
		}
	}
	addPrekeyRejections(add, opkPool)
	addFabricRefusals(add, handoffDir)
	add("body-store", "skipped", "Body-store connectivity is not probed by default; status does not fetch, put, or delete ciphertext.", "Use a controlled end-to-end E2 test if you need to verify body-store access.")
	report.Summary.Checks = len(report.Checks)
	switch {
	case report.Summary.Errors > 0:
		report.Summary.Status = "error"
	case report.Summary.Warnings > 0:
		report.Summary.Status = "warning"
	case report.Summary.Skipped > 0:
		report.Summary.Status = "incomplete"
	default:
		report.Summary.Status = "ok"
	}
	return report, nil
}

// addPrekeyRejections reports the persisted prekey rejection counts for the OPK
// pool at opkPool. Only the counts are read from the pool file; no key material
// is put into the report. With no pool configured, nothing is added.
func addPrekeyRejections(add func(id, status, detail, action string), opkPool string) {
	if opkPool == "" {
		return
	}
	counts, err := ratchetwire.ReadOnlyPrekeyRejections(opkPool)
	if os.IsNotExist(err) {
		add("prekey-rejections", "ok", "No OPK pool file yet; no prekey rejections recorded.", "")
		return
	}
	if err != nil {
		add("prekey-rejections", "error", fmt.Sprintf("Cannot read prekey rejection counts: %v", err), "Check the OPK pool path and permissions without exposing key contents.")
		return
	}
	lookup, validate := counts[ratchetwire.StageLookup], counts[ratchetwire.StageValidate]
	authenticate, commit := counts[ratchetwire.StageAuthenticate], counts[ratchetwire.StageCommit]
	detail := fmt.Sprintf("rejected prekey handshakes: lookup=%d validate=%d authenticate=%d commit=%d", lookup, validate, authenticate, commit)
	if lookup+validate+authenticate+commit == 0 {
		add("prekey-rejections", "ok", detail, "")
		return
	}
	add("prekey-rejections", "warning", detail, "Lookup and authenticate rejections are usually replays or forged inits; validate rejections point to a wrong identity or bundle. Check the e2 log lines for the txids.")
}

func renderStatusJSON(w io.Writer, report statusJSONReport) error {
	if w == nil {
		return errors.New("status: nil JSON output")
	}
	return json.NewEncoder(w).Encode(report)
}

func renderStatusText(w io.Writer, report statusJSONReport) error {
	if w == nil {
		return errors.New("status: nil text output")
	}
	if _, err := fmt.Fprintln(w, "spore status"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "---------------"); err != nil {
		return err
	}
	for _, check := range report.Checks {
		mark := "✅"
		if check.Status == "warning" || check.Status == "skipped" {
			mark = "⚠"
		}
		if check.Status == "error" {
			mark = "❌"
		}
		if _, err := fmt.Fprintf(w, "  %s %-22s %s\n", mark, check.ID, check.Detail); err != nil {
			return err
		}
		if check.NextAction != "" {
			if _, err := fmt.Fprintf(w, "      next: %s\n", check.NextAction); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(w, "---------------"); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s: %d checks, %d error(s), %d warning(s), %d skipped\n", report.Summary.Status, report.Summary.Checks, report.Summary.Errors, report.Summary.Warnings, report.Summary.Skipped)
	return err
}

// statusProbe is one connection's health result.
type statusProbe struct {
	name    string
	ok      bool
	skipped bool
	detail  string
	address string
	height  uint64
}

func statuscmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	timeout := fs.Duration("timeout", 5*time.Second, "per-connection probe timeout")
	mailboxHTTP := fs.String("mailbox-http", "", "optional running mailbox base URL (e.g. http://127.0.0.1:19292) to probe")
	jsonOutput := fs.Bool("json", false, "emit machine-readable unified status")
	fs.String("config", "", "config file path (default ~/.spore/config.json or $SPORE_CONFIG)")
	stateDir := fs.String("state-dir", "", "encrypted endpoint/handoff state directory")
	stateKey := fs.String("state-key", "", "file containing 32-byte hex state encryption key")
	opkPool := fs.String("opk-pool", "", "endpoint-local OPK pool JSON; its persisted prekey rejection counts are reported")
	addChainFlags(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*2)
	defer cancel()

	var probes []statusProbe
	var c chain.Chain
	chainName := fs.Lookup("chain").Value.String()
	if fs.Lookup("rpc").Value.String() == "" {
		probes = append(probes, statusProbe{name: chainName, skipped: true, detail: "No carrier RPC endpoint is configured; no network probe was attempted."})
	} else {
		var buildErr error
		c, buildErr = backend.Build(ctx, backend.ChainConfig{Type: chainName, RPC: fs.Lookup("rpc").Value.String(), Login: fs.Lookup("rpc-login").Value.String(), From: fs.Lookup("from").Value.String(), KeyFile: fs.Lookup("keyfile").Value.String(), ProgramID: fs.Lookup("program").Value.String(), Mailbox: mailboxContractOrDefault(fs)})
		if buildErr != nil {
			probes = append(probes, statusProbe{name: chainName, detail: buildErr.Error()})
		} else {
			probes = append(probes, probeChain(ctx, c))
		}
	}

	home, _ := DefaultConfigDir()
	configFile := fs.Lookup("config").Value.String()
	cfg, _ := LoadConfig(configPath(configFile))
	effectiveStateDir := *stateDir
	if effectiveStateDir == "" && cfg != nil {
		effectiveStateDir = cfg.StateDir
	}
	if effectiveStateDir == "" {
		effectiveStateDir = filepath.Join(home, "state")
	}
	keyPath := *stateKey
	if keyPath == "" && cfg != nil {
		keyPath = cfg.StateKey
	}
	if keyPath == "" {
		keyPath = filepath.Join(home, "state.key")
	}

	// The EVM mailbox is the "which contract am I pointed at?" fact. Resolve
	// it for EVM operators whether or not one is configured, so the line is
	// never a silent absence. The chain id comes from the registry when the
	// address is a shipped default, else from the live backend.
	mailboxLine := ""
	if evmBackend, ok := c.(*evm.Backend); ok {
		var chainID uint64
		known := false
		if fs.Lookup("rpc").Value.String() != "" {
			if id, err := evmBackend.ChainID(ctx); err == nil && id != nil && id.IsUint64() {
				chainID, known = id.Uint64(), true
			}
		}
		mailboxLine = mailboxStatusLine(evmBackend.Mailbox(), chainID, known)
	}

	// Optional mailbox HTTP probe.
	if *mailboxHTTP != "" {
		probes = append(probes, probeMailbox(ctx, *mailboxHTTP))
	}

	report, err := buildStatusJSONReportWithPool(probes, mailboxLine, home, effectiveStateDir, keyPath, *opkPool)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *jsonOutput {
		if err := renderStatusJSON(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	} else if err := renderStatusText(os.Stdout, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if report.Summary.Errors > 0 {
		os.Exit(1)
	}
}

// mailboxStatusLine renders the configured EVM MyceliumMailbox for the status
// HUD — the address, the chain it belongs to, and whether it is a shipped
// default or the operator's own override:
//
//	mailbox       0x12…cd  chain=8453   shipped default (v0.9.0)
//	mailbox       0x12…cd  chain=31337  user override (-mailbox / config evm_mailbox)
//	mailbox       none configured (EVM only; set -mailbox or config evm_mailbox)
//
// connectedChainID is the chain the RPC is actually on (known=false when the
// backend could not report it). A shipped default's chain id comes from the
// registry — its address is only valid there — so a connected chain that
// differs is called out rather than silently trusted.
func mailboxStatusLine(mailbox string, connectedChainID uint64, known bool) string {
	if mailbox == "" {
		return "  mailbox       none configured (EVM only; set -mailbox or config evm_mailbox)"
	}
	if d, ok := evm.MailboxDeploymentByAddress(mailbox); ok {
		line := fmt.Sprintf("  mailbox       %-25s chain=%d  shipped default (%s)", truncMid(mailbox, 22), d.ChainID, d.Default)
		if !known {
			line += "  ⚠ connected chain unknown"
		}
		if known && connectedChainID != d.ChainID {
			line += fmt.Sprintf("  ⚠ connected chain is %d", connectedChainID)
		}
		return line
	}
	chainID := "unknown"
	if known {
		chainID = strconv.FormatUint(connectedChainID, 10)
	}
	return fmt.Sprintf("  mailbox       %-25s chain=%s  user override (-mailbox / config evm_mailbox)", truncMid(mailbox, 22), chainID)
}

// probeChain checks one chain.Chain: reachable (Height succeeds) + address.
func probeChain(ctx context.Context, c chain.Chain) statusProbe {
	name := c.Name()
	sp := statusProbe{name: name}
	// Address first (cheap / local) — a reachable backend returns it.
	addrCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr, aerr := c.Address(addrCtx)
	if aerr != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("address: %v", aerr)
		return sp
	}
	sp.address = addr

	// Height = the real "am I connected to a live node/chain" check.
	hctx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	h, herr := c.Height(hctx)
	if herr != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("node/chain: %v", herr)
		return sp
	}
	sp.height = h
	sp.ok = true
	sp.detail = "ok"
	return sp
}

// probeMailbox checks an always-on mailbox's HTTP surface is up.
func probeMailbox(ctx context.Context, base string) statusProbe {
	sp := statusProbe{name: "mailbox"}
	// The mailbox exposes /list (used by `mailbox list`). A 200/405 means it's
	// serving. We treat "got any HTTP response from the host" as reachable.
	url := base + "/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		sp.ok = false
		sp.detail = err.Error()
		return sp
	}
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		sp.ok = false
		sp.detail = fmt.Sprintf("unreachable: %v", err)
		return sp
	}
	defer resp.Body.Close()
	sp.ok = true
	sp.detail = fmt.Sprintf("serving (HTTP %d)", resp.StatusCode)
	return sp
}

// renderStatus prints the HUD. mailboxLine is the pre-rendered EVM mailbox
// summary (empty on non-EVM chains).
func renderStatus(probes []statusProbe, mailboxLine string) {
	fmt.Println("spore status")
	fmt.Println("---------------")
	if mailboxLine != "" {
		fmt.Println(mailboxLine)
	}
	anyDown := false
	for _, p := range probes {
		mark := "✅"
		if !p.ok {
			mark = "❌"
			anyDown = true
		}
		line := fmt.Sprintf("  %s %-9s ", mark, p.name)
		if p.ok {
			line += fmt.Sprintf("ok  addr=%s  height=%d", truncMid(p.address, 22), p.height)
		} else {
			line += p.detail
		}
		fmt.Println(line)
	}
	fmt.Println("---------------")
	if anyDown {
		fmt.Println("some connections are DOWN — check your RPC/wallet/mailbox.")
		os.Exit(1)
	}
	fmt.Println("all connections healthy.")
}

func truncMid(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 8 {
		return s[:n]
	}
	return s[:n/2] + "…" + s[len(s)-(n/2):]
}
