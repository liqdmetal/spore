package main

import (
	"strings"
	"testing"

	"github.com/liqdmetal/spore/internal/evm"
)

// shippedMailbox registers a temporary shipped default so the status line can
// be exercised against a real registry entry without a live deployment. It is
// restored (or deleted) when the test ends.
func shippedMailbox(t *testing.T, key string, d evm.MailboxDeployment) {
	t.Helper()
	prev, had := evm.KnownMailboxDeployments[key]
	evm.KnownMailboxDeployments[key] = d
	t.Cleanup(func() {
		if had {
			evm.KnownMailboxDeployments[key] = prev
		} else {
			delete(evm.KnownMailboxDeployments, key)
		}
	})
}

func TestMailboxStatusLineShippedDefault(t *testing.T) {
	const addr = "0x1234567890ABCDEF1234567890abcdef12345678"
	shippedMailbox(t, "8453", evm.MailboxDeployment{
		ChainID: 8453, Address: addr, Default: "v0.9.0",
		ReceiptRef: "docs/LIVE_NODES.md §3",
	})

	line := mailboxStatusLine(addr, 8453, true)
	for _, want := range []string{"chain=8453", "shipped default", "v0.9.0"} {
		if !strings.Contains(line, want) {
			t.Fatalf("shipped-default line missing %q: %q", want, line)
		}
	}
	if strings.Contains(line, "user override") {
		t.Fatalf("a registry-backed address must not read as a user override: %q", line)
	}
	if strings.Contains(line, "⚠") {
		t.Fatalf("a shipped default on its own chain must not warn: %q", line)
	}
}

func TestMailboxStatusLineShippedDefaultChainMismatch(t *testing.T) {
	const addr = "0x1234567890ABCDEF1234567890abcdef12345678"
	shippedMailbox(t, "8453", evm.MailboxDeployment{
		ChainID: 8453, Address: addr, Default: "v0.9.0",
		ReceiptRef: "docs/LIVE_NODES.md §3",
	})

	// Same address, but the RPC is on Base Sepolia (84532) — the foot-gun the
	// registry exists to catch.
	line := mailboxStatusLine(addr, 84532, true)
	if !strings.Contains(line, "chain=8453") || !strings.Contains(line, "connected chain is 84532") {
		t.Fatalf("registry chain id and a differing connected chain must both show: %q", line)
	}
}

func TestMailboxStatusLineUserOverride(t *testing.T) {
	// A made-up address is nobody's shipped default — the operator's own.
	line := mailboxStatusLine("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", 31337, true)
	if !strings.Contains(line, "user override") || !strings.Contains(line, "chain=31337") {
		t.Fatalf("user-override line wrong: %q", line)
	}
	if strings.Contains(line, "shipped default") {
		t.Fatalf("an unknown address must not read as a shipped default: %q", line)
	}
}

func TestMailboxStatusLineUserOverrideUnknownChain(t *testing.T) {
	line := mailboxStatusLine("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD", 0, false)
	if !strings.Contains(line, "user override") || !strings.Contains(line, "chain=unknown") {
		t.Fatalf("an override whose chain cannot be read must say unknown: %q", line)
	}
}

func TestMailboxStatusLineNoneConfigured(t *testing.T) {
	line := mailboxStatusLine("", 8453, true)
	if !strings.Contains(line, "none configured") {
		t.Fatalf("no-mailbox line wrong: %q", line)
	}
	if strings.Contains(line, "user override") || strings.Contains(line, "shipped default") {
		t.Fatalf("a missing mailbox must not claim a source: %q", line)
	}
}
