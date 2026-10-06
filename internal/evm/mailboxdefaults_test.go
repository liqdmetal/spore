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
	"fmt"
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
		if !strings.Contains(doc, d.Address) {
			t.Errorf("chain %s: address %s is not cited anywhere in docs/LIVE_NODES.md — publish the §3 receipt BEFORE wiring the default", chainID, d.Address)
		}
	}

	const marker = "Default `-mailbox` (config `evm_mailbox`) shipped in:"
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatalf("docs/LIVE_NODES.md lost its %q STATUS line — restore it", marker)
	}
	rest := doc[i+len(marker):]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
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

// releasePrepDrain covers Patch 6's narrative trio and Patch 7's uncovered
// runbook, overview, diagram, and release-pointer surfaces. The four
// registry-backed status rows are gated separately above. Match specific
// stale claims, not every mention of Anvil: dated local proof and local-dev
// instructions are valid evidence and must remain.
type releasePrepDocGate struct {
	rel            string
	forbidden      []string
	forbiddenLower []string
	alwaysRequired []string
	requiredClaims []string
}

var releasePrepDrain = []releasePrepDocGate{
	{
		rel:            "VISION.md",
		forbidden:      []string{"deployment pending"},
		forbiddenLower: []string{"anvil"},
		requiredClaims: []string{"EVM (live on Base, receipt in docs/LIVE_NODES.md"},
	},
	{
		rel:            "design.md",
		forbidden:      []string{"deployment pending"},
		forbiddenLower: []string{"anvil"},
		requiredClaims: []string{"live on Base** (chain 8453): `MyceliumMailbox.sol`"},
	},
	{
		rel: "ROADMAP.md",
		forbidden: []string{
			"deployment pending",
			"verified on anvil",
			"**Goal:**",
			"The real-chain deployment below slipped to v0.9.0; v0.8.0 ships everything",
			"addresses to fill in at",
			"The raw-calldata path stays the default and the payable one;",
			"Everything hard about this is already built and pinned; what remains is",
			"Only remaining dependency: a funded EVM account on a real chain.",
			"**v0.9.0 must do:**",
			"**Done when:**",
			"Still gated on: a funded EVM account on a real chain.",
			"**v0.9.0 target — detailed plan in the subsection above.**",
			"1. **Deploy for real.** Choose the chain",
			"2. **Two-party E2E on the deployed mailbox.**",
			"ship default contract addresses per supported chain",
			"Document per-chain gas reality for deliver/burn",
			"- [ ] `MyceliumMailbox` deployed on a real EVM chain;",
			"- [ ] Two-party `send-e2` → receive → auto-burn proven against that",
			"- [ ] Default `-mailbox` address wired into per-chain config defaults.",
			"- [ ] CARRIER_MATRIX + README EVM rows updated to \"live\"",
		},
		requiredClaims: []string{
			"EVM live on Base with the deployment receipt published",
			"carrier-matrix EVM row now reads \"live; Base deployment receipt",
			"At v0.8.0 release time, the real-chain deployment was still planned for",
			"the Base address later shipped in v0.9.0",
			"the shipped Base config default selects",
			"**Shipped on Base (chain 8453):**",
			"The Base deployment, two-party proof, and receipt-backed default shipped in v0.9.0; their canonical evidence is in",
			"Fee and limit notes are documented separately in\n   the v0.9.0 fee-notes patch using deployment-day estimator output.",
			"Base deployment receipt and address:",
			"**v0.9.0 deployment status:**",
			"1. **Deployed on Base (chain 8453).**",
			"2. **Two-party E2E proven on Base.**",
			"3. **Default mailbox address shipped.**",
			"4. **Honest fee + limit notes:** a separate release-prep deliverable;",
			"**Done in v0.9.0:**",
			"- [x] `MyceliumMailbox` deployed on a real EVM chain;",
			"- [x] Two-party `send-e2` → receive → auto-burn proven against that",
			"- [x] Default `-mailbox` address wired into per-chain config defaults.",
			"- [x] CARRIER_MATRIX + README EVM rows updated to \"live\"",
			"Deployed on Base; receipt and two-party proof are in",
			"**Shipped on Base (v0.9.0).**",
		},
	},
	{
		rel: "README.md",
		forbidden: []string{
			"Pointing the carrier at a real chain moves to v0.9.0.",
			"and real-chain EVM deployment.",
		},
		requiredClaims: []string{
			"At v0.8.0 release time, the Base deployment was planned for v0.9.0; the Base EVM deployment later shipped in v0.9.0 (receipt:",
			"documentation cleanup following the v0.9.0 Base EVM deployment (receipt:",
		},
	},
	{
		rel: "docs/ONBOARDING.md",
		forbidden: []string{
			"EVM carrier for the wire: local EIP-155 signing, the loopback `evm-proxy`,",
			"| EVM | 🧪 dev (anvil-verified; mailbox contract deployment pending) |",
			"the current release (2026-09-27)",
			"For the current release, `vTAG` is `v0.8.0`.",
		},
		requiredClaims: []string{
			"The Base EVM deployment shipped later in v0.9.0 (receipt: `LIVE_NODES.md` §3).",
			"For the v0.8.0 example above, `vTAG` is `v0.8.0`; substitute the version you're verifying.",
		},
	},
	{
		rel: "ROADMAP-PRODUCTION.md",
		forbidden: []string{
			"**Mailbox deploy + gas-sponsored delivery.** Makes the EVM path",
			"Dependent on the mailbox actually burning correctly (P0-3)",
		},
		requiredClaims: []string{
			"**Gas-sponsored EVM mailbox delivery.** The Base MyceliumMailbox",
			"deployment and recipient-paid burn proof shipped in v0.9.0",
		},
	},
	{
		rel: "docs/LIVE_NODES.md",
		forbidden: []string{
			"# Live-node spec — verify EVM + Solana + XMR for real",
			"This spec tracks the live nodes that prove each for real, on the Hetzner box",
			"(YOUR-NODE-HOST) where the DERO node already lives.",
			"### STATUS: EVM backend LIVE-VERIFIED — 2026-09-05",
			"Then, to prove it against a **real** EVM chain, swap in a funded account later.",
			"### STATUS: MyceliumMailbox on Base — PENDING",
			"## Not live-verified: what that means",
			"EVM and Solana are live-verified (anvil / mainnet above).",
			"the anvil-era current-state prose in VISION/design/ROADMAP is drained to",
		},
		forbiddenLower: []string{"**internal/evm is now live-verified**"},
		alwaysRequired: []string{"Patches 6 and 7 drain the narrative and remaining audited-document"},
		requiredClaims: []string{
			"# Live-chain receipt ledger — EVM, Solana, and XMR",
			"This file holds the EVM deployment receipt and runbook, plus the local-node",
			"This is a reproducible local dev smoke test, not a deployment prerequisite",
			"### Historical evidence: local EVM backend smoke on Anvil — 2026-09-05",
			"## Remaining unverified backend",
			"EVM MyceliumMailbox is live on Base (chain 8453; deployment and two-party",
		},
	},
	{
		rel: "docs/PEER_SETUP.md",
		forbidden: []string{
			"EVM and Solana backends are live-verified; see",
		},
		forbiddenLower: []string{
			"evm and solana are\n> live-verified",
			"evm and solana backends are live-verified; see",
		},
		requiredClaims: []string{
			"EVM MyceliumMailbox is live on Base",
			"live-verified on mainnet for self-messaging",
			"EVM MyceliumMailbox is live on Base (receipt in",
		},
	},
	{
		rel:            "docs/FULL_PICTURE.md",
		forbiddenLower: []string{"anvil + myceliummailbox contract", "live-verified against anvil"},
		requiredClaims: []string{
			"**EVM MyceliumMailbox is live on Base as of v0.9.0**",
			"The Base EVM delivery → receive → burn →",
			"`docs/LIVE_NODES.md` §3",
		},
	},
	{
		rel:            "docs/RATCHET.md",
		forbiddenLower: []string{"anvil-verified with deployment pending"},
		requiredClaims: []string{"EVM MyceliumMailbox is live on Base; two-party proof"},
	},
	{
		rel:            "docs/SPORE-FLOW.html",
		forbiddenLower: []string{"evm anvil+contract"},
		requiredClaims: []string{"EVM Base 8453 live · receipt: LIVE_NODES §3"},
	},
	{
		rel:            "docs/SPORE-FLOW.svg",
		forbiddenLower: []string{"evm anvil+contract"},
		requiredClaims: []string{"EVM Base 8453 live · receipt: LIVE_NODES §3"},
	},
}

func releasePrepDocViolations(d releasePrepDocGate, doc string, registryShipped bool) []string {
	var violations []string
	for _, claim := range d.alwaysRequired {
		if !strings.Contains(doc, claim) {
			violations = append(violations, fmt.Sprintf("missing required release-process claim %q", claim))
		}
	}
	if !registryShipped {
		for _, claim := range d.requiredClaims {
			if strings.Contains(doc, claim) {
				violations = append(violations, fmt.Sprintf("premature post-flip claim %q while the registry is empty", claim))
			}
		}
		return violations
	}
	for _, tok := range d.forbidden {
		if strings.Contains(doc, tok) {
			violations = append(violations, fmt.Sprintf("stale EVM status %q after registry shipped", tok))
		}
	}
	lower := strings.ToLower(doc)
	for _, tok := range d.forbiddenLower {
		if strings.Contains(lower, tok) {
			violations = append(violations, fmt.Sprintf("stale EVM status %q (case-insensitive) after registry shipped", tok))
		}
	}
	for _, claim := range d.requiredClaims {
		if !strings.Contains(doc, claim) {
			violations = append(violations, fmt.Sprintf("missing post-flip status claim %q", claim))
		}
	}
	return violations
}

// TestReleasePrepProseDrainedAfterFlip keeps the release-prep surfaces
// receipt-honest in both directions: post-flip claims are forbidden while the
// registry is empty and required once a deployment is shipped.
func TestReleasePrepProseDrainedAfterFlip(t *testing.T) {
	registryShipped := len(KnownMailboxDeployments) > 0
	for _, d := range releasePrepDrain {
		raw, err := os.ReadFile("../../" + d.rel)
		if err != nil {
			t.Fatalf("%s unreadable: %v", d.rel, err)
		}
		for _, violation := range releasePrepDocViolations(d, string(raw), registryShipped) {
			t.Errorf("%s: %s — apply the relevant release-prep patch", d.rel, violation)
		}
	}
}

// TestReleasePrepDrainGatePolarity rehearses both registry states against
// synthetic document text so the populated-registry rules are tested without
// adding a fake address or editing the live docs.
func TestReleasePrepDrainGatePolarity(t *testing.T) {
	for _, d := range releasePrepDrain {
		d := d
		t.Run(d.rel, func(t *testing.T) {
			goodClaims := append([]string{}, d.alwaysRequired...)
			goodClaims = append(goodClaims, d.requiredClaims...)
			goodDoc := strings.Join(goodClaims, "\n")
			if violations := releasePrepDocViolations(d, goodDoc, true); len(violations) > 0 {
				t.Fatalf("populated-registry fixture rejected: %s", strings.Join(violations, "; "))
			}
			if len(d.requiredClaims) > 0 {
				if violations := releasePrepDocViolations(d, goodDoc, false); len(violations) == 0 {
					t.Error("post-flip claims were not rejected while the registry was empty")
				}
			}

			staleClaims := append([]string{}, d.forbidden...)
			staleClaims = append(staleClaims, d.forbiddenLower...)
			if len(staleClaims) == 0 {
				return
			}
			for _, stale := range staleClaims {
				testStale := stale
				if strings.Contains(strings.Join(d.forbiddenLower, "\n"), stale) {
					testStale = strings.ToUpper(stale)
				}
				preFlipDoc := strings.Join(d.alwaysRequired, "\n") + "\n" + testStale
				if violations := releasePrepDocViolations(d, preFlipDoc, false); len(violations) > 0 {
					t.Fatalf("pre-flip fixture rejected historical wording %q: %s", testStale, strings.Join(violations, "; "))
				}
				docWithStale := goodDoc + "\n" + testStale
				violations := releasePrepDocViolations(d, docWithStale, true)
				rejectedStale := false
				for _, violation := range violations {
					if strings.Contains(violation, "stale EVM status") {
						rejectedStale = true
						break
					}
				}
				if !rejectedStale {
					t.Errorf("populated-registry fixture did not reject stale wording %q: %s", testStale, strings.Join(violations, "; "))
				}
			}
		})
	}
}

// TestMailboxDeploymentByAddress covers the reverse lookup the status HUD
// uses to tell a shipped default from an operator override.
func TestMailboxDeploymentByAddress(t *testing.T) {
	const addr = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
	if _, ok := MailboxDeploymentByAddress(addr); ok {
		t.Fatal("the empty shipped registry must match nothing")
	}
	if _, ok := MailboxDeploymentByAddress(""); ok {
		t.Fatal("an empty address must never match")
	}

	KnownMailboxDeployments["8453"] = MailboxDeployment{
		ChainID: 8453, Address: addr, Default: "vTEST", ReceiptRef: "test",
	}
	t.Cleanup(func() { delete(KnownMailboxDeployments, "8453") })

	got, ok := MailboxDeploymentByAddress(addr)
	if !ok || got.ChainID != 8453 || got.Default != "vTEST" {
		t.Fatalf("address lookup returned %+v ok=%v", got, ok)
	}
	if _, ok := MailboxDeploymentByAddress(strings.ToLower(addr)); !ok {
		t.Fatal("address lookup must be case-insensitive")
	}
	if _, ok := MailboxDeploymentByAddress("  0xAbCdEf0123456789AbCdEf0123456789AbCdEf01  "); !ok {
		t.Fatal("address lookup must tolerate surrounding whitespace")
	}
	if _, ok := MailboxDeploymentByAddress("0x0000000000000000000000000000000000000000"); ok {
		t.Fatal("an unknown address must not match a shipped default")
	}
}

func TestDefaultMailboxContractLookupGuards(t *testing.T) {
	if shipped, ok := KnownMailboxDeployments["8453"]; ok {
		if got := DefaultMailboxContract(8453); got != shipped.Address {
			t.Fatalf("Base lookup must return its shipped address %q, got %q", shipped.Address, got)
		}
	} else if got := DefaultMailboxContract(8453); got != "" {
		t.Fatalf("empty registry must resolve empty, got %q", got)
	}
	if got := DefaultMailboxContract(0); got != "" {
		t.Fatalf("chain id 0 must resolve empty, got %q", got)
	}
	if _, ok := DefaultMailboxDeployment(84532); ok {
		t.Fatal("registry must not claim a Base Sepolia deployment")
	}

	previous, hadPrevious := KnownMailboxDeployments["8453"]
	KnownMailboxDeployments["8453"] = MailboxDeployment{
		ChainID:    8453,
		Address:    "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01",
		Default:    "vTEST",
		ReceiptRef: "test",
	}
	t.Cleanup(func() {
		if hadPrevious {
			KnownMailboxDeployments["8453"] = previous
		} else {
			delete(KnownMailboxDeployments, "8453")
		}
	})
	if got := DefaultMailboxContract(8453); got != KnownMailboxDeployments["8453"].Address {
		t.Fatalf("Base lookup must return the populated address, got %q", got)
	}
	got, ok := DefaultMailboxDeployment(8453)
	if !ok || got.Address != "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01" {
		t.Fatalf("populated entry not returned: %+v ok=%v", got, ok)
	}
	if DefaultMailboxContract(1) != "" {
		t.Fatal("non-deployed chain must resolve empty")
	}
}
