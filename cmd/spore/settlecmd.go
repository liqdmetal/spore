// settle — SporRelay settlement subcommands.
//
//	spore settle discover <source-amount> <dest-address> [--chain C] [--fee-pct F]
//	spore settle execute <objective-id> <route-index>
//	spore settle assurance <objective-id> [none|light|full]
//
// The implementation lives in internal/sporrelay/cli; this file is the command
// surface (dispatch + usage) so `spore settle` behaves like every other command:
// an unknown subcommand is a loud exit-2, not a silent no-op.
//
// SPORE_RELAY_URL names the RelayOS relayer endpoint (see internal/sporrelay).
package main

import (
	"fmt"
	"os"

	"github.com/liqdmetal/spore/internal/sporrelay/cli"
)

func settlecmd(args []string) {
	if len(args) == 0 {
		settleUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "discover":
		cli.Discover(args[1:])
	case "execute":
		cli.Execute(args[1:])
	case "assurance":
		cli.Assurance(args[1:])
	case "-h", "--help", "help":
		settleUsage()
	default:
		fmt.Fprintf(os.Stderr, "settle: unknown subcommand %q (want discover|execute|assurance)\n", args[0])
		settleUsage()
		os.Exit(2)
	}
}

func settleUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore settle discover <source-amount> <dest-address> [--chain C] [--fee-pct F]
        ask the relayer for cross-chain routes to a destination
        e.g. spore settle discover 50USDC dero1q... --chain evm --fee-pct 0.5
  spore settle execute <objective-id> <route-index>
        execute a discovered route through the relayer
  spore settle assurance <objective-id> [none|light|full]
        generate the assurance proof for a settled objective
  spore settle -h, --help

environment:
  SPORE_RELAY_URL   RelayOS relayer base URL (required by all three)`)
}
