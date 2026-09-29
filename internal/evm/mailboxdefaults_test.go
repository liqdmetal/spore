package evm

// The receipt gate: every shipped default-mailbox entry must cite a
// LIVE_NODES §3 receipt that exists, and every receipt citation must cite a
// shipped entry. This is the honesty bar the DERO and Solana "live" rows
// hold: a default address and its published receipt can never drift apart.
// Until the Phase B deployment lands, the registry is empty and this test
// vacuously passes; deployment day flips both sides in one commit.
//
// The same gate covers the public doc CLAIMS (README chain table, the
// CARRIER_MATRIX EVM row, the LIVE_NODES header): none may flip to "live"
// before the registry does, and all must flip together with it. The
// ready-to-apply flip wording lives in release-designs/ (outside this
// repo); deployment day copies it verbatim.
import (
	"os"
	"strings"
	"testing"
)

// deploymentDayDocClaims are the exact substrings the docs must carry once
// the EVM row flips to live — the same strings the ready-to-apply patch in
// release-designs/ applies. Each is checked both ways: forbidden while the
// registry is empty, required once it is not.
var deploymentDayDocClaims = map[string]string{
	"README.md":              "live on Base; deployment receipt published",
	"docs/CARRIER_MATRIX.md": "live; Base deployment receipt published",
	"docs/LIVE_NODES.md":     "live on Base (chain 8453); deployment receipt published",
	"docs/ONBOARDING.md":     "✅ live on Base (deployment receipt: LIVE_NODES.md §3)",
}

// oldEVMRowClaims are the pre-deployment placeholder claims that must be
// GONE once the registry ships — guards against a partial flip that edits
// one doc and leaves another claiming "deployment pending".
var oldEVMRowClaims = []string{
	"deployment pending",
	"anvil-verified",
}

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

// TestDocClaimsMatchRegistryState extends the receipt gate to the public
// docs: the EVM rows must stay honest in BOTH directions. While the
// registry is empty, no doc may claim the deployment is live; once it
// ships, every doc must carry the flipped claim and none may keep the
// "deployment pending" placeholder. Run after reading each doc; a missing
// doc file fails (docs are load-bearing, not optional).
func TestDocClaimsMatchRegistryState(t *testing.T) {
	registryShipped := len(KnownMailboxDeployments) > 0
	read := func(rel string) string {
		raw, err := os.ReadFile("../../" + rel)
		if err != nil {
			t.Fatalf("%s unreadable: %v", rel, err)
		}
		return string(raw)
	}
	for rel, flippedClaim := range deploymentDayDocClaims {
		doc := read(rel)
		if registryShipped && !strings.Contains(doc, flippedClaim) {
			t.Errorf("%s: registry ships a deployment but the doc never claims %q — apply the ready-to-apply flip (release-designs/) or update the wording there and here together", rel, flippedClaim)
		}
		if !registryShipped && strings.Contains(doc, flippedClaim) {
			t.Errorf("%s: claims %q but the registry is empty — a doc must never flip before the receipt-backed entry exists", rel, flippedClaim)
		}
		for _, stale := range oldEVMRowClaims {
			if registryShipped && strings.Contains(doc, stale) {
				t.Errorf("%s: still carries the pre-deployment claim %q after the registry shipped — finish the flip", rel, stale)
			}
		}
	}
}

// releasePrepDrain is the post-flip prose drain for the three narrative
// docs. The four operator-facing surfaces are gated above; these files
// carry the same honesty bar but are allowed to keep release HISTORY:
// ROADMAP's titlecase "Anvil" mentions describe the local-node arc that was
// actually proven, so they stay — history stays, current-state claims go.
// VISION and design lose every mention; ROADMAP only the exact current-state
// phrases the v0.9.0 release-prep pass rewrites.
var releasePrepDrain = []struct {
	rel         string
	tokens      []string // case-sensitive tokens forbidden once the registry ships
	lowerTokens []string // case-insensitive tokens forbidden once the registry ships
}{
	{"VISION.md", []string{"deployment pending"}, []string{"anvil"}},
	{"design.md", []string{"deployment pending"}, []string{"anvil"}},
	{"ROADMAP.md", []string{"deployment pending", "verified on anvil"}, nil},
}

// TestReleasePrepProseDrainedAfterFlip extends the doc gate to the narrative
// files — in ONE direction only: it stays vacuous until the registry ships,
// then fails while any anvil-era current-state wording survives. This is the
// release-prep prose drain made mechanical, the same bar as the DERO and
// Solana rows: the narrative must match the published chain status.
func TestReleasePrepProseDrainedAfterFlip(t *testing.T) {
	if len(KnownMailboxDeployments) == 0 {
		return // pre-flip: the narrative may still describe the local-node era
	}
	for _, d := range releasePrepDrain {
		raw, err := os.ReadFile("../../" + d.rel)
		if err != nil {
			t.Fatalf("%s unreadable: %v", d.rel, err)
		}
		doc := string(raw)
		for _, tok := range d.tokens {
			if strings.Contains(doc, tok) {
				t.Errorf("%s: still carries anvil-era current-state wording %q after the registry shipped — apply the release-prep prose drain (ready-to-apply Patch 6 in release-designs/)", d.rel, tok)
			}
		}
		lower := strings.ToLower(doc)
		for _, tok := range d.lowerTokens {
			if strings.Contains(lower, tok) {
				t.Errorf("%s: still carries anvil-era current-state wording %q (case-insensitive) after the registry shipped — apply the release-prep prose drain (ready-to-apply Patch 6 in release-designs/)", d.rel, tok)
			}
		}
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
