// derosim — a local DERO wallet-RPC simulator with honest relay-dex
// contract semantics, for two-party escrow/dex soaks without mainnet.
//
//	spore derosim serve -listen 127.0.0.1:20219
//
// Point one party's -rpc at /w/alice and the other's at /w/bob; contract
// state (HTLC locks, pool reserves, wDERO supply) is shared, like on-chain.
// SPORE_SAP_* contract IDs are fixed and printed at startup — export them
// for the session and every sap command routes into the simulator:
//
//	export SPORE_SAP_HTLC_SC=...
//	export SPORE_SAP_DEX_SC=...
//	export SPORE_SAP_WDERO_SC=...
//
// The simulator implements exactly the wallet-RPC surface spore uses
// (transfer, get_transfers, getaddress, getheight, getbalance, sc_invoke)
// with per-party balances and histories. Ring signatures and blocks are NOT
// simulated — a soak exercises spore's session, envelope, ledger, and store
// logic against contract-shaped money movement, not DERO's cryptography.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/liqdmetal/spore/internal/derosim"
)

func derosimcmd(args []string) {
	if len(args) == 0 {
		derosimUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "serve":
		derosimServe(args[1:])
	case "-h", "--help":
		derosimUsage()
	default:
		fmt.Fprintf(os.Stderr, "derosim: unknown subcommand %q (want serve)\n", args[0])
		os.Exit(2)
	}
}

func derosimUsage() {
	fmt.Fprint(os.Stderr, `usage:
  spore derosim serve -listen 127.0.0.1:20219
                       (two-party wallet-RPC simulator: /w/alice, /w/bob;
                        shared RelayHTLC/RelayDEX/RelayWrappedDero state;
                        /debug/state + /debug/bump for the soak driver)
`)
}

func derosimServe(args []string) {
	fs := flag.NewFlagSet("derosim serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:20219", "HTTP listen address for the simulator")
	_ = fs.Parse(args)

	// Fixed contract IDs: the sim is the chain, so it defines the SCIDs the
	// SPORE_SAP_* env vars will point at. Hex-shaped so the CLI's config
	// surfaces treat them like real contract IDs.
	htlcSCID := "sim-htlc-00000000000000000000000000000000000000000000000000000000000001"
	dexSCID := "sim-dex-000000000000000000000000000000000000000000000000000000000000002"
	wderoSCID := "sim-wdero-0000000000000000000000000000000000000000000000000000000003"
	s := derosim.New(htlcSCID, dexSCID, wderoSCID)
	s.AddWallet("alice")
	s.AddWallet("bob")

	srv := &http.Server{Addr: *listen, Handler: derosim.ServeHandler(s)}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("derosim: %v", err)
	}
	addr := ln.Addr().String()
	fmt.Printf("derosim listening on http://%s\n", addr)
	fmt.Printf("  wallets:     %s/w/alice  %s/w/bob  (pass to -rpc)\n", urlBase(addr), urlBase(addr))
	fmt.Printf("  alice addr:  %s\n", s.Address("alice"))
	fmt.Printf("  bob addr:    %s\n", s.Address("bob"))
	fmt.Printf("  debug:       %s/debug/state  %s/debug/bump\n", urlBase(addr), urlBase(addr))
	fmt.Printf("\n  export SPORE_SAP_HTLC_SC=%s\n", htlcSCID)
	fmt.Printf("  export SPORE_SAP_DEX_SC=%s\n", dexSCID)
	fmt.Printf("  export SPORE_SAP_WDERO_SC=%s\n", wderoSCID)
	fmt.Println()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("derosim: %v", err)
	}
}

func urlBase(addr string) string { return "http://" + addr }
