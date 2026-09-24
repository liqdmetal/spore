package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

const (
	testConfigMailbox = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	testFlagMailbox   = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testInitMailbox   = "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

func newE2TestFlagset(t *testing.T, cfgPath string, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	e2Common(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if cfgPath != "" {
		if err := fs.Set("config", cfgPath); err != nil {
			t.Fatal(err)
		}
	}
	return fs
}

func TestMailboxContractOrDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{"evm_mailbox":"` + testConfigMailbox + `"}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// The config default applies when the command has a -mailbox flag but
	// the user left it empty.
	fs := newE2TestFlagset(t, cfgPath)
	if got := mailboxContractOrDefault(fs); got != testConfigMailbox {
		t.Fatalf("config default not applied: got %q", got)
	}

	// An explicit -mailbox flag always wins over config.
	fs = newE2TestFlagset(t, cfgPath, "-mailbox", testFlagMailbox)
	if got := mailboxContractOrDefault(fs); got != testFlagMailbox {
		t.Fatalf("explicit flag must win: got %q", got)
	}

	// No config file: empty, not an error (fully flag-driven commands keep
	// working without a config).
	fs = newE2TestFlagset(t, filepath.Join(dir, "absent.json"))
	if got := mailboxContractOrDefault(fs); got != "" {
		t.Fatalf("missing config must resolve empty, got %q", got)
	}

	// No -mailbox flag registered at all, but a config flag is: the default
	// still resolves — funnel callers (msgBackend) without e2Common's full
	// flag surface must not silently lose the contract address.
	fsNoMailbox := flag.NewFlagSet("t", flag.ContinueOnError)
	fsNoMailbox.String("config", "", "")
	if err := fsNoMailbox.Parse([]string{"-config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	if got := mailboxContractOrDefault(fsNoMailbox); got != testConfigMailbox {
		t.Fatalf("config default lost without a -mailbox flag: got %q", got)
	}
}

func TestMailboxContractDefaultNeverAutoFillsURLCommands(t *testing.T) {
	// The URL-flavored -mailbox commands (prekeybatch/invite) share the flag
	// NAME but not the semantics; a config evm_mailbox must never leak into
	// their flagValues() defaults. loadConfigForFlags -> applyConfigDefaults
	// has no "mailbox" entry by construction: assert it.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"evm_mailbox":"`+testConfigMailbox+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("mailbox", "", "prekey/base URL flavor")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigForFlags(fs); err != nil {
		t.Fatal(err)
	}
	if got := fs.Lookup("mailbox").Value.String(); got != "" {
		t.Fatalf("evm_mailbox leaked into a URL-flavored -mailbox default: %q", got)
	}
}

func TestInitWritesEVMMailboxDefault(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	initcmd([]string{"-dir", home, "-mailbox-contract", testInitMailbox})
	cfg, err := LoadConfig(filepath.Join(home, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || cfg.EVMMailbox != testInitMailbox {
		t.Fatalf("init did not write evm_mailbox: %+v", cfg)
	}

	// And the written default flows back out of the resolver.
	fs := newE2TestFlagset(t, filepath.Join(home, "config.json"))
	if got := mailboxContractOrDefault(fs); got != testInitMailbox {
		t.Fatalf("resolver did not pick up the init-written default: %q", got)
	}
}
