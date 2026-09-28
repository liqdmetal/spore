// contract — deploy the MyceliumMailbox contract from a funded local key.
//
//	spore contract deploy-mycelium -rpc http://127.0.0.1:8545 \
//	    -private-key 0x... -bin tools/mycelium.bin
//
// This closes the roadmap gap "EVM never deployed": the EVM backend could
// always CONSUME a mailbox contract, but nothing in the repo could PRODUCE
// one — the address had to be deployed by hand with forge/foundry. This
// command signs and broadcasts the creation transaction itself (hand-rolled
// EIP-155 over btcec — no go-ethereum dependency), derives the contract
// address locally, waits for code to appear on chain, and prints the address
// to hand to -mailbox.
//
// The private key is accepted on argv for CI/scripted deploys (matching the
// other -private-key surfaces in this repo) or via SPORE_EVM_PRIVATE_KEY;
// the environment form is preferred so the key stays out of shell history.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/liqdmetal/spore/internal/evm"
)

func contractcmd(args []string) {
	if len(args) == 0 {
		contractUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "deploy-mycelium":
		contractDeployMycelium(args[1:])
	case "estimate":
		contractEstimate(args[1:])
	case "-h", "--help", "help":
		contractUsage()
	default:
		fmt.Fprintf(os.Stderr, "contract: unknown subcommand %q (want deploy-mycelium | estimate)\n", args[0])
		contractUsage()
		os.Exit(2)
	}
}

func contractUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore contract estimate -rpc URL [-mailbox ADDR] [-to ADDR] [-payload-bytes N] [-rounds N] [-gas-price WEI]
        answer "what does this deployment cost" in one command: live
        eth_gasPrice × live eth_estimateGas for deploy (+ deliver on an
        existing mailbox), with a conservative, clearly-labeled fallback
        for burn. See docs/LIVE_NODES.md §3.
        -rpc            EVM JSON-RPC endpoint
        -from           sender address to quote for (the funded key you
                        will deploy with; default: from-less estimate)
        -mailbox        already-deployed MyceliumMailbox address (adds
                        deliver/burn rows to the estimate)
        -to             deliver recipient (default: a synthetic address;
                        gas does not depend on the value)
        -payload-bytes  deliver payload size to price (default 116 — the
                        canonical E2 pointer)
        -rounds         deliver+burn rounds to total (default 12)
        -gas-price      wei override; default: live eth_gasPrice
  spore contract deploy-mycelium -rpc URL -private-key HEX -bin FILE [-gas-price WEI] [-wait 2m]
        deploy contracts/MyceliumMailbox.sol from a funded local key.
        -rpc          EVM JSON-RPC endpoint (e.g. http://127.0.0.1:8545)
        -private-key  32-byte hex secp256k1 key, FUNDED on the target chain
                      (prefer SPORE_EVM_PRIVATE_KEY so the key stays out of
                      shell history)
        -bin          solc creation bytecode (solc --bin); default
                      tools/mycelium.bin — generate it with:
                        solc --bin contracts/MyceliumMailbox.sol | tail -1 > tools/mycelium.bin
                      (contract estimate shares this default via -bin)
        -gas-price    wei; default: eth_gasPrice
        -wait         how long to wait for the contract code to appear (default 2m)
prints:
  tx hash, derived+verified contract address, and the -mailbox value to use.`)
}

func contractDeployMycelium(args []string) {
	fs := flag.NewFlagSet("contract deploy-mycelium", flag.ExitOnError)
	rpc := fs.String("rpc", "", "EVM JSON-RPC endpoint (e.g. http://127.0.0.1:8545)")
	privKey := fs.String("private-key", "", "32-byte hex private key, funded (prefer SPORE_EVM_PRIVATE_KEY)")
	bin := fs.String("bin", "tools/mycelium.bin", "solc --bin creation bytecode file")
	gasPriceWei := fs.String("gas-price", "", "gas price in wei (default: eth_gasPrice)")
	wait := fs.Duration("wait", 0, "max wait for the contract code to appear (default 2m)")
	_ = fs.Parse(args)

	if *rpc == "" {
		fmt.Fprintln(os.Stderr, "contract deploy-mycelium: -rpc required")
		fs.Usage()
		os.Exit(2)
	}
	keyHex := strings.TrimSpace(*privKey)
	if keyHex == "" {
		keyHex = strings.TrimSpace(os.Getenv("SPORE_EVM_PRIVATE_KEY"))
	}
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "contract deploy-mycelium: no key: pass -private-key or set SPORE_EVM_PRIVATE_KEY (32-byte hex, funded)")
		os.Exit(2)
	}

	code, err := evm.LoadCreationCode(*bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract deploy-mycelium:", err)
		if !strings.HasPrefix(*bin, "/") && !strings.Contains(*bin, ":") {
			// Relative path: suggest the exact generation command from the repo root.
			fmt.Fprintf(os.Stderr, "  generate it from the repo root:\n    %s\n", evm.GenerationCodeHint)
		}
		os.Exit(2)
	}

	b := evm.NewBackend(*rpc, "evm", "")
	var priceOverride *big.Int
	if *gasPriceWei != "" {
		p, ok := new(big.Int).SetString(*gasPriceWei, 10)
		if !ok {
			fmt.Fprintln(os.Stderr, "contract deploy-mycelium: -gas-price must be decimal wei")
			os.Exit(2)
		}
		priceOverride = p
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *wait > 0 {
		var cancelWait context.CancelFunc
		ctx, cancelWait = context.WithTimeout(ctx, *wait)
		defer cancelWait()
	}

	res, err := b.DeployContractEIP155(ctx, keyHex, code, priceOverride)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract deploy-mycelium:", err)
		os.Exit(1)
	}
	fmt.Printf("tx hash:        %s\n", res.TxHash)
	fmt.Printf("contract addr:  %s\n", res.Addr)
	fmt.Printf("code verified:  yes (eth_getCode non-empty)\n\n")
	fmt.Printf("use it:\n  spore msg send-e2 -chain evm ... -mailbox %s\n", res.Addr)
	fmt.Printf("  (or set -mailbox on `spore msg recv -chain evm` / `spore mailbox run -chain evm`)\n")
}

// contractEstimate implements `spore contract estimate`: the funding math
// for docs/LIVE_NODES.md §3 Phase B step 1 ("Measure first") as one command.
// Deploy gas uses the exact param shape deploy-mycelium will send; deliver
// gas uses the exact calldata PostPayload sends on the contract path; burn
// falls back to a labeled constant when the node refuses to estimate it
// against an empty slot. Costs are priced at the live eth_gasPrice (or the
// -gas-price override) and the run-time rule is restated in the output.
func contractEstimate(args []string) {
	fs := flag.NewFlagSet("contract estimate", flag.ExitOnError)
	rpc := fs.String("rpc", "", "EVM JSON-RPC endpoint (e.g. https://mainnet.base.org)")
	from := fs.String("from", "", "sender address to quote estimates for (the funded key you will deploy with; default: from-less estimate)")
	bin := fs.String("bin", "tools/mycelium.bin", "solc --bin creation bytecode file (same default as deploy-mycelium)")
	mailbox := fs.String("mailbox", "", "already-deployed MyceliumMailbox address (adds deliver/burn rows)")
	to := fs.String("to", "", "deliver recipient address (default: synthetic — gas does not depend on the value)")
	payloadBytes := fs.Int("payload-bytes", evm.EstimatePayloadBytes, "deliver payload size in bytes to price (canonical E2 pointer = 116)")
	rounds := fs.Int("rounds", 12, "deliver+burn rounds to total")
	gasPriceWei := fs.String("gas-price", "", "gas price override in wei (default: live eth_gasPrice)")
	_ = fs.Parse(args)

	if *rpc == "" {
		fmt.Fprintln(os.Stderr, "contract estimate: -rpc required")
		fs.Usage()
		os.Exit(2)
	}
	if *payloadBytes < 1 || *payloadBytes > 48000 {
		fmt.Fprintln(os.Stderr, "contract estimate: -payload-bytes must be 1..48000 (a pointer is 116; keeps the estimate inside any single-tx calldata limit)")
		os.Exit(2)
	}
	if *rounds < 1 || *rounds > 100000 {
		fmt.Fprintln(os.Stderr, "contract estimate: -rounds must be 1..100000")
		os.Exit(2)
	}

	code, err := evm.LoadCreationCode(*bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract estimate:", err)
		if !strings.HasPrefix(*bin, "/") && !strings.Contains(*bin, ":") {
			fmt.Fprintf(os.Stderr, "  generate it from the repo root:\n    %s\n", evm.GenerationCodeHint)
		}
		os.Exit(2)
	}

	recipient := strings.TrimSpace(*to)
	if recipient == "" {
		recipient = evm.SyntheticRecipient
	}

	b := evm.NewBackend(*rpc, "evm", strings.TrimSpace(*from))
	var priceOverride *big.Int
	if *gasPriceWei != "" {
		p, ok := new(big.Int).SetString(*gasPriceWei, 10)
		if !ok {
			fmt.Fprintln(os.Stderr, "contract estimate: -gas-price must be decimal wei")
			os.Exit(2)
		}
		priceOverride = p
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	est, err := b.EstimateMyceliumCostsPriced(ctx, recipient, *mailbox, code, *payloadBytes, priceOverride)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract estimate:", err)
		os.Exit(1)
	}
	price := est.GasPriceWei // non-nil whenever the method returned nil error

	deploy, deliver, burn := est.DeployGas, est.DeliverGas, est.BurnGas

	type row struct {
		label string
		gas   uint64
	}

	fmt.Printf("chain:           %s", rpcChainID(est))
	if cid := est.ChainID; cid != nil {
		fmt.Printf(" (chainid %s)", cid)
	}
	fmt.Printf("\n")
	fmt.Printf("gas price:       %s wei (%s)%s\n", price.String(), evm.FormatWei(price), priceSourceLabel(est))
	fmt.Printf("payload priced:  %d bytes\n", *payloadBytes)
	fmt.Printf("\n")
	rows := []row{{"deploy", deploy}}
	if deliver > 0 {
		rows = append(rows, row{"deliver", deliver})
	}
	if burn > 0 {
		rows = append(rows, row{"burn", burn})
	}
	for _, r := range rows {
		fmt.Printf("%-16s %10s gas   %s\n", r.label, commas(r.gas), evm.FormatWei(new(big.Int).Mul(new(big.Int).SetUint64(r.gas), price)))
	}
	if deliver > 0 && burn > 0 {
		round := deliver + burn
		fmt.Printf("%-16s %10s gas   %s\n", "deliver+burn", commas(round), evm.FormatWei(new(big.Int).Mul(new(big.Int).SetUint64(round), price)))
	}
	fmt.Printf("\n")
	if est.From != "" {
		fmt.Printf("estimates sent from %s (the funded key you would deploy with)\n", est.From)
	}
	if est.BurnMode != "" {
		fmt.Printf("burn mode:       %s\n", est.BurnMode)
	}
	if deliver == 0 {
		fmt.Printf("deliver/burn:    not priced — pass -mailbox after `spore contract deploy-mycelium` to add those rows\n")
	}
	for _, n := range est.Notes {
		fmt.Printf("note:            %s\n", n)
	}
	if total := est.TotalWei(*rounds); total != nil {
		fmt.Printf("\nfunding total:   %s deploy + %d × (deliver+burn) = %s\n", evm.FormatWei(est.DeployWei()), *rounds, evm.FormatWei(total))
	} else {
		fmt.Printf("\nfunding total:   not computable (see notes above) — price the missing rows and re-run\n")
	}
	fmt.Printf("gas prices move: re-run this command at deploy time; never fund from a stale number\n")
}

// rpcChainID renders the chain id from the estimate, or a dash.
func rpcChainID(est *evm.GasEstimate) string {
	if est.ChainID == nil {
		return "-"
	}
	return est.ChainID.String()
}

// priceSourceLabel annotates the gas-price line with where the number came
// from and what the burn fallback means for it.
func priceSourceLabel(est *evm.GasEstimate) string {
	if est.GasPriceOverride {
		return " [from -gas-price]"
	}
	return " [live eth_gasPrice]"
}

// commas formats a uint64 with thousands separators.
func commas(v uint64) string {
	s := strconv.FormatUint(v, 10)
	start := 0
	if v >= 1000 {
		parts := []string{}
		for i := len(s); i > 0; i -= 3 {
			lo := i - 3
			if lo < 0 {
				lo = 0
			}
			parts = append([]string{s[lo:i]}, parts...)
			if lo == 0 {
				start = 1
				break
			}
		}
		_ = start
		return strings.Join(parts, ",")
	}
	return s
}
