package evm

// The receipt gate: every shipped default-mailbox entry must cite a
// LIVE_NODES §3 receipt that exists, and every receipt citation must cite a
// shipped entry. This is the honesty bar the DERO and Solana "live" rows
// hold: a default address and its published receipt can never drift apart.
// Until the Phase B deployment lands, the registry is empty and this test
// vacuously passes; deployment day flips both sides in one commit.
import (
	"os"
	"strings"
	"testing"
)

func TestShippedMailboxDefaultsCarryReceipts(t *testing.T) {
	raw, err := os.ReadFile("../../docs/LIVE_NODES.md")
	if err != nil {
		t.Fatalf("LIVE_NODES.md unreadable: %v", err)
	}
	doc := string(raw)

	for chainID, d := range KnownMailboxDeployments {
		if !strings.HasPrefix(d.Address, "0x") || len(d.Address) != 42 {
			t.Errorf("chain %s: address %q is not 0x+40-hex", chainID, d.Address)
		}
		if d.Default == "" {
			t.Errorf("chain %s: Default (releasing version) is empty", chainID)
		}
		if d.ReceiptRef == "" {
			t.Errorf("chain %s: ReceiptRef is empty — a shipped default without a receipt is a silent claim", chainID)
			continue
		}
		// The receipt must cite the exact address in the STATUS block the
		// tag message and docs copy from.
		if !strings.Contains(doc, d.Address) {
			t.Errorf("chain %s: address %s is not cited anywhere in docs/LIVE_NODES.md — publish the §3 receipt BEFORE wiring the default", chainID, d.Address)
		}
	}

	// Cross-check in the other direction: the §3 STATUS block's
	// "shipped in" line must not name a release for a deployment that has
	// no shipped entry (drift in the docs-away direction).
	const marker = "Default `-mailbox` (config `evm_mailbox`) shipped in:"
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatalf("docs/LIVE_NODES.md lost its %q STATUS line — restore it", marker)
	}
	rest := doc[i+len(marker):]
	nl := strings.Index(rest, "\n")
	if nl >= 0 {
		rest = rest[:nl]
	}
	rest = strings.TrimSpace(rest)
	if len(KnownMailboxDeployments) > 0 && (rest == "" || strings.Contains(rest, "<release>")) {
		t.Errorf("registry has shipped entries but the §3 STATUS line still says %q — fill it with the shipping release", rest)
	}
	if len(KnownMailboxDeployments) == 0 && rest != "<release>" && rest != "" {
		t.Errorf("§3 STATUS claims a shipped default (%q) but the registry is empty — wire the entry or fix the doc", rest)
	}
}

func TestDefaultMailboxContractLookupGuards(t *testing.T) {
	// Empty registry: every lookup is empty, never an error or a placeholder.
	if got := DefaultMailboxContract(8453); got != "" {
		t.Fatalf("empty registry must resolve empty, got %q", got)
	}
	if got := DefaultMailboxContract(0); got != "" {
		t.Fatalf("chain id 0 must resolve empty, got %q", got)
	}
	if _, ok := DefaultMailboxDeployment(84532); ok {
		t.Fatal("empty registry must not claim a Base Sepolia deployment")
	}

	// A populated entry resolves by decimal string key, address verbatim.
	KnownMailboxDeployments["8453"] = MailboxDeployment{
		ChainID:    8453,
		Address:    "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
		Default:    "vTEST",
		ReceiptRef: "test",
	}
	defer delete(KnownMailboxDeployments, "8453")
	got, ok := DefaultMailboxDeployment(8453)
	if !ok || got.Address != "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01" {
		t.Fatalf("populated entry not returned: %+v ok=%v", got, ok)
	}
	if DefaultMailboxContract(1) != "" {
		t.Fatal("non-deployed chain must resolve empty")
	}
}
