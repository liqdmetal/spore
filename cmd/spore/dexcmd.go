// In-thread relay-dex operations: `msg dex swap`, `msg dex wrap`, `msg dex
// unwrap`.
//
// Roadmap #1's remaining "swap UX" is money movement, not escrow: a swap has
// no claim/refund legs (nothing sits in escrow — the pool settles both sides
// atomically in one SC invoke), so these are operator-side money commands
// that ANNOUNCE their outcome in-thread on the ratcheted session, exactly
// like `msg escrow claim|refund` do. The DEX takes its bps fee in-contract
// (90% LP / 10% treasury per docs/BUSINESS.md "Line 2") — this CLI never
// handles the rake, only surfaces the settlement.
//
// Contract IDs come from the SPORE_SAP_* environment variables (see
// internal/sap); an unconfigured deployment refuses LOCALLY before any
// wallet RPC.
//
//	spore msg dex swap   -ta TOKENA -tb TOKENB -min-out N -to ADDR -session HEX [-rpc URL ...]
//	spore msg dex wrap   -amount 5dero   -to ADDR -session HEX ...
//	spore msg dex unwrap -amount 5wdero  -to ADDR -session HEX ...
//
// wrap/unwrap amounts use the same unit-explicit money syntax as invoice/pay
// (5dero, 2.5wdero — suffix required) and are converted with the exact
// big.Int parser; float arithmetic on money is forbidden.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/liqdmetal/spore/internal/dero"
	"github.com/liqdmetal/spore/internal/receipts"
	"github.com/liqdmetal/spore/internal/sap"
)

// dexClient builds the wallet-RPC client from the shared e2Common flags and
// seeds the sap contract IDs from the environment. Shared by all three
// subcommands.
func dexClient(fs *flag.FlagSet) (*dero.Client, error) {
	sap.LoadContractIDsFromEnv()
	fsRPC := fs.Lookup("rpc")
	if fsRPC == nil || fsRPC.Value.String() == "" {
		return nil, errors.New("dex requires -rpc (DERO wallet RPC)")
	}
	u, p := parseLogin(fs.Lookup("rpc-login").Value.String())
	return dero.NewClient(fsRPC.Value.String(), u, p), nil
}

// dexRequire enforces the common required flags across the three subcommands.
// (The in-thread announce itself is escrowAnnounce — identical semantics:
// SendNext on the durable session, pointer post, stderr-only failure that
// never hides that the money already moved on-chain.)
func dexRequire(to, sessionHex string) {
	if to == "" || sessionHex == "" {
		check(fmt.Errorf("dex requires -to and -session (the in-thread settlement notice rides that session)"))
	}
}

func msgDEXSwap(args []string) {
	fs := flag.NewFlagSet("msg dex swap", flag.ExitOnError)
	tokenA := fs.String("ta", "", "source token (RelayDEX token identifier)")
	tokenB := fs.String("tb", "", "destination token (RelayDEX token identifier)")
	minOut := fs.Uint64("min-out", 0, "minimum accepted output of -tb (the SC enforces the bound)")
	to := fs.String("to", "", "counterparty chain address (receives the in-thread settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	dexRequire(*to, *sessionHex)
	if *tokenA == "" || *tokenB == "" || *minOut == 0 {
		check(fmt.Errorf("dex swap requires -ta -tb -min-out (0 output would accept anything the pool gives)"))
	}
	if strings.EqualFold(*tokenA, *tokenB) {
		check(fmt.Errorf("dex swap: -ta and -tb must differ"))
	}
	client, err := dexClient(fs)
	check(err)
	ring, err := deroRingSizeFromFlags(fs, "dero")
	check(err)

	txid, err := sap.DEXSwap(context.Background(), client, *tokenA, *tokenB, *minOut, ring)
	check(err)
	fmt.Printf("DEX SWAPPED %s -> %s (min-out %d) tx %s\n", *tokenA, *tokenB, *minOut, shortTx(txid))

	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "dex-swap", Asset: "dero",
		Note: *note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "dex: ledger %s: %v\n", *receiptsFile, err)
	}
	env, err := marshalDexNotice("swap", fmt.Sprintf("%s->%s", *tokenA, *tokenB), 0, "", txid, *note)
	check(err)
	escrowAnnounce(fs, *to, *sessionHex, env)
}

func msgDEXWrap(args []string) {
	fs := flag.NewFlagSet("msg dex wrap", flag.ExitOnError)
	amount := fs.String("amount", "", "DERO to wrap into wDERO, whole units with asset suffix (e.g. 5dero)")
	to := fs.String("to", "", "counterparty chain address (receives the in-thread settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	dexRequire(*to, *sessionHex)
	atomic, err := dexAmountAtomic(*amount)
	check(err)
	client, err := dexClient(fs)
	check(err)
	ring, err := deroRingSizeFromFlags(fs, "dero")
	check(err)

	txid, err := sap.WrapDERO(context.Background(), client, atomic, ring)
	check(err)
	fmt.Printf("WDERO WRAPPED %s tx %s\n", formatAmount("dero", atomic), shortTx(txid))

	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "dex-wrap", Asset: "dero",
		Atomic: atomic, Note: *note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "dex: ledger %s: %v\n", *receiptsFile, err)
	}
	env, err := marshalDexNotice("wrap", "dero->wdero", atomic, formatAmount("dero", atomic), txid, *note)
	check(err)
	escrowAnnounce(fs, *to, *sessionHex, env)
}

func msgDEXUnwrap(args []string) {
	fs := flag.NewFlagSet("msg dex unwrap", flag.ExitOnError)
	amount := fs.String("amount", "", "wDERO to unwrap back to DERO, whole units with asset suffix (e.g. 5wdero)")
	to := fs.String("to", "", "counterparty chain address (receives the in-thread settlement notice)")
	sessionHex := fs.String("session", "", "16-hex session id of the open conversation")
	note := fs.String("note", "", "optional note for the counterparty")
	receiptsFile := fs.String("receipts", "receipts.json", "ledger file to append this settlement to")
	e2Common(fs)
	_ = fs.Parse(args)
	if err := loadConfigForFlags(fs); err != nil {
		check(err)
	}
	dexRequire(*to, *sessionHex)
	atomic, err := dexAmountAtomic(*amount)
	check(err)
	client, err := dexClient(fs)
	check(err)
	ring, err := deroRingSizeFromFlags(fs, "dero")
	check(err)

	txid, err := sap.UnwrapDERO(context.Background(), client, atomic, ring)
	check(err)
	fmt.Printf("WDERO UNWRAPPED %s tx %s\n", formatAmount("dero", atomic), shortTx(txid))

	if err := receipts.Append(*receiptsFile, receipts.Record{At: time.Now().Unix(), Session: *sessionHex,
		Peer: *to, Direction: "sent", Kind: "dex-unwrap", Asset: "dero",
		Atomic: atomic, Note: *note, TxID: txid}); err != nil {
		fmt.Fprintf(os.Stderr, "dex: ledger %s: %v\n", *receiptsFile, err)
	}
	env, err := marshalDexNotice("unwrap", "wdero->dero", atomic, formatAmount("dero", atomic), txid, *note)
	check(err)
	escrowAnnounce(fs, *to, *sessionHex, env)
}

// msgDEXFees prints the operator fee schedule and the sap contract-ID
// configuration state. docs/BUSINESS.md ("Line 2") REQUIRES publishing the
// exact rake: "the DEX already takes a bps fee (90% LP / 10% treasury on
// AMM; atomic swaps free)" — this is that publication, straight from the
// CLI, so an operator quoting terms to a counterparty never guesses. It also
// doubles as the config doctor for the SPORE_SAP_* seam: a deployment with
// unset contract IDs sees exactly which env vars are missing.
func msgDEXFees() {
	htlc, dex, wdero := sap.ContractIDs()
	fmt.Println("relay-dex fee schedule (taken in-contract, never by this CLI):")
	fmt.Println("  AMM swap      bps fee on the traded leg — 90% to LPs, 10% to treasury")
	fmt.Println("  atomic swaps  free")
	fmt.Println("  HTLC escrow   per-hand fee to the contract's baked fee_collector")
	fmt.Println("  wrap/unwrap   no spore-side or dex-side fee")
	fmt.Println()
	fmt.Println("contract IDs (set via environment):")
	fmt.Printf("  %-24s %s\n", sap.EnvHTLCSignature, dashOrSet(htlc))
	fmt.Printf("  %-24s %s\n", sap.EnvDEXSignature, dashOrSet(dex))
	fmt.Printf("  %-24s %s\n", sap.EnvWrappedDeroName, dashOrSet(wdero))
}

// dashOrSet renders a configured value or an explicit unset marker.
func dashOrSet(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

// dexAmountAtomic parses a whole-unit amount for wrap/unwrap using the same
// exact big.Int money parser as invoice/pay (float arithmetic on money is
// forbidden). The asset suffix is optional and decorative here.
func dexAmountAtomic(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("dex: -amount is required")
	}
	// wDERO mirrors DERO 1:1 (same 5 decimals), so a wdero suffix parses
	// identically — rewrite it to the dero unit the shared parser knows.
	if t := strings.TrimSpace(s); len(t) >= 5 && strings.EqualFold(t[len(t)-5:], "wdero") {
		s = t[:len(t)-5] + "dero"
	}
	asset, atomic, err := parseAmountFlag(s)
	if err != nil {
		return 0, err
	}
	if asset != "dero" && asset != "wdero" {
		return 0, fmt.Errorf("dex: -amount asset %q: only dero/wdero wrap here (suffix required, e.g. 5dero)", asset)
	}
	if atomic == 0 {
		return 0, errors.New("dex: -amount must be greater than zero")
	}
	return atomic, nil
}
