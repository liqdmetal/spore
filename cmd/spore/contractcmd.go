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
	case "-h", "--help", "help":
		contractUsage()
	default:
		fmt.Fprintf(os.Stderr, "contract: unknown subcommand %q (want deploy-mycelium)\n", args[0])
		contractUsage()
		os.Exit(2)
	}
}

func contractUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  spore contract deploy-mycelium -rpc URL -private-key HEX -bin FILE [-gas-price WEI] [-wait 2m]
        deploy contracts/MyceliumMailbox.sol from a funded local key.
        -rpc          EVM JSON-RPC endpoint (e.g. http://127.0.0.1:8545)
        -private-key  32-byte hex secp256k1 key, FUNDED on the target chain
                      (prefer SPORE_EVM_PRIVATE_KEY so the key stays out of
                      shell history)
        -bin          solc creation bytecode (solc --bin); default
                      tools/mycelium.bin — generate it with:
                        solc --bin contracts/MyceliumMailbox.sol | tail -1 > tools/mycelium.bin
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
