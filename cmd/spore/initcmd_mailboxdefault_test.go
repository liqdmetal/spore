package main

// Tests for the v0.9.0 pre-stage: `spore init` resolving the shipped
// per-chain default mailbox address (must-do #3). The registry ships EMPTY
// (no receipt yet), so the shipped-default branch is exercised by injecting
// a fake entry — with t.Cleanup restoring emptiness so the receipt-gate test
// in internal/evm stays vacuously true.
import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/evm"
)

// withShippedBaseDefault injects a Base-mainnet entry into the shipped
// registry for the duration of one test and restores emptiness after.
func withShippedBaseDefault(t *testing.T, addr string) {
	t.Helper()
	evm.KnownMailboxDeployments["8453"] = evm.MailboxDeployment{
		ChainID:    8453,
		Address:    addr,
		Default:    "vTEST",
		ReceiptRef: "test-only (injected)",
	}
	t.Cleanup(func() { delete(evm.KnownMailboxDeployments, "8453") })
}

func initIntoTempHome(t *testing.T, args ...string) *Config {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	initcmd(append([]string{"-dir", home, "-opks", "2"}, args...))
	cfg, err := LoadConfig(filepath.Join(home, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("init wrote no config")
	}
	return cfg
}

func TestInitShipsDefaultMailboxForEVMWhenRegistryHasOne(t *testing.T) {
	const shipped = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	withShippedBaseDefault(t, shipped)
	cfg := initIntoTempHome(t, "-chain", "evm")
	if cfg.EVMMailbox != shipped {
		t.Fatalf("init -chain evm did not pick up the shipped default: got %q", cfg.EVMMailbox)
	}

	// An explicit -mailbox-contract always wins over the shipped default.
	const mine = "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	cfg = initIntoTempHome(t, "-chain", "evm", "-mailbox-contract", mine)
	if cfg.EVMMailbox != mine {
		t.Fatalf("explicit -mailbox-contract must win over the shipped default: got %q", cfg.EVMMailbox)
	}

	// The explicit-EMPTY opt-out ships no address: an operator on their own
	// deployment must be able to refuse the project's default.
	cfg = initIntoTempHome(t, "-chain", "evm", "-mailbox-contract=", "")
	if cfg.EVMMailbox != "" {
		t.Fatalf("-mailbox-contract= must opt out of the shipped default: got %q", cfg.EVMMailbox)
	}
}

func TestInitNeverShipsDefaultForNonEVMChains(t *testing.T) {
	withShippedBaseDefault(t, "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	cfg := initIntoTempHome(t) // default -chain dero
	if cfg.EVMMailbox != "" {
		t.Fatalf("non-EVM chain must never get an evm_mailbox default: got %q", cfg.EVMMailbox)
	}
}

func TestInitShipsNothingWhileRegistryIsEmpty(t *testing.T) {
	// Current reality: no receipt, empty registry, evm init behaves exactly
	// as before this pre-stage (no silent claims).
	cfg := initIntoTempHome(t, "-chain", "evm")
	if cfg.EVMMailbox != "" {
		t.Fatalf("empty registry must ship no default: got %q", cfg.EVMMailbox)
	}
}

// The resolver seam is the other half: whatever init wrote must flow back
// out of mailboxContractOrDefault on the E2 flag surface. The generic case
// is covered in mailbox_config_test.go; here we pin it for the injected
// shipped default specifically.
func TestShippedDefaultFlowsThroughResolver(t *testing.T) {
	const shipped = "0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
	withShippedBaseDefault(t, shipped)

	home := filepath.Join(t.TempDir(), "home")
	initcmd([]string{"-dir", home, "-opks", "2", "-chain", "evm"})
	cfgPath := filepath.Join(home, "config.json")

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	e2Common(fs)
	if err := fs.Parse([]string{"-config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if got := mailboxContractOrDefault(fs); got != shipped {
		t.Fatalf("shipped default did not resolve through the E2 funnel: got %q", got)
	}
}

// InitWritingConfigShapeIsStable guards against config regressions: the
// evm_mailbox key must round-trip through LoadConfig's
// DisallowUnknownFields decoder (a renamed field would silently drop the
// default for every existing config file).
func TestInitWritingConfigShapeIsStable(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	initcmd([]string{"-dir", home, "-opks", "2", "-chain", "evm", "-mailbox-contract", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	raw, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"evm_mailbox"`) {
		t.Fatalf("config.json lost the evm_mailbox key: %s", raw)
	}
}
