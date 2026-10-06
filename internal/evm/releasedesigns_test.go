package evm

// The release-designs drift guard: the vendored v0.9.0 flip patch is applied by
// hand on deployment day, so nothing at runtime notices when the receipt gate's
// required wording moves ahead of it. This test pins the two together — every
// claim the gate requires (deploymentDayDocClaims, releasePrepDrain's
// requiredClaims and alwaysRequired) must be stated verbatim in the vendored
// patch, and the registry entry it installs must be documented.
//
// Whitespace is normalized before matching: the patch is prose that wraps at
// ~80 columns, and the "one physical line" rule applies to the DOC after the
// patch is applied — not to the patch text itself. A failure here means the
// gate and the patch have drifted, so release day would fail mid-apply with no
// warning until the flip commit.
import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const releaseDesignsFlips = "../../release-designs/v0.9.0-doc-flips.md"

// normalizeWS collapses every run of whitespace to one space, so a claim that
// the patch wraps across lines still matches.
func normalizeWS(s string) string { return strings.Join(strings.Fields(s), " ") }

func loadReleaseDesignsFlips(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(releaseDesignsFlips)
	if err != nil {
		t.Fatalf("the vendored flip patch is unreadable (%v) — release day would have no ready-to-apply wording", err)
	}
	return normalizeWS(string(raw))
}

// TestReleaseDesignsPatchCarriesGateClaims is the drift guard proper.
func TestReleaseDesignsPatchCarriesGateClaims(t *testing.T) {
	patch := loadReleaseDesignsFlips(t)

	var missing []string
	for rel, claim := range deploymentDayDocClaims {
		if !strings.Contains(patch, normalizeWS(claim)) {
			missing = append(missing, rel+" :: "+claim)
		}
	}
	for _, d := range releasePrepDrain {
		claims := append(append([]string{}, d.alwaysRequired...), d.requiredClaims...)
		for _, claim := range claims {
			if !strings.Contains(patch, normalizeWS(claim)) {
				missing = append(missing, d.rel+" :: "+claim)
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		for _, m := range missing {
			t.Errorf("the vendored patch never states the gate's required claim — %s", m)
		}
		t.Errorf("%d claim(s) missing: update release-designs/v0.9.0-doc-flips.md so it applies the wording the gate actually requires", len(missing))
	}
}

// TestReleaseDesignsPatchDocumentsRegistryEntry checks the code half of the
// flip is in the patch too, not just the prose half.
func TestReleaseDesignsPatchDocumentsRegistryEntry(t *testing.T) {
	patch := loadReleaseDesignsFlips(t)
	for _, want := range []string{
		`"8453": {`,
		`Default: "v0.9.0"`,
		`ReceiptRef: "docs/LIVE_NODES.md §3 STATUS / Base mainnet"`,
	} {
		if !strings.Contains(patch, want) {
			t.Errorf("the vendored patch does not document the registry entry field %q", want)
		}
	}
}

// TestReleaseDesignsSetIsComplete keeps the whole release-day input in-tree:
// the flip patch is useless without the checklist, the fee notes, the tag
// message, and the landing copy that the runbook walks through in order.
func TestReleaseDesignsSetIsComplete(t *testing.T) {
	for _, name := range []string{
		"README.md",
		"v0.9.0-pretag-checklist.md",
		"v0.9.0-doc-flips.md",
		"v0.9.0-doc-flips.patch",
		"v0.9.0-fee-notes.md",
		"v0.9.0-tag-message.txt",
		"v0.9.0-landing-card.md",
	} {
		if _, err := os.Stat("../../release-designs/" + name); err != nil {
			t.Errorf("release-designs/%s is missing from the repo (%v) — the release-prep set must stay self-contained", name, err)
		}
	}
}

// The executable half of the flip. release-designs/v0.9.0-doc-flips.md is the
// proposal a human reads; release-designs/v0.9.0-doc-flips.patch is what release
// day runs (`git apply`). The test above proves the .md *states* the gate's
// claims somewhere — which it would also do if the claim appeared only in its
// own commentary. This one proves the claims are in the patch's added text for
// the right file, matched raw, exactly as the gate matches it.
const releaseDesignsPatchFile = "../../release-designs/v0.9.0-doc-flips.patch"

// patchNewRegions returns, per target file, the post-apply text of every hunk's
// changed region, in order: context and added lines kept, removed lines
// dropped. That is the same text `git apply` leaves on disk, so a claim that
// occurs here occurs in the flipped doc too.
func patchNewRegions(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(releaseDesignsPatchFile)
	if err != nil {
		t.Fatalf("the executable flip patch is unreadable (%v) — release day would have nothing to apply", err)
	}

	regions := map[string]string{}
	var cur strings.Builder
	path := ""
	flush := func() {
		if path != "" {
			regions[path] += cur.String()
		}
		path = ""
		cur.Reset()
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "+++ ") {
			flush()
			path = strings.TrimPrefix(strings.TrimPrefix(ln, "+++ "), "b/")
			continue
		}
		if path == "" || ln == "" {
			continue
		}
		switch ln[0] {
		case '+', ' ':
			cur.WriteString(ln[1:])
			cur.WriteByte('\n')
		}
	}
	flush()
	return regions
}

// TestReleaseDesignsExecutablePatchDeliversGateClaims is the drift guard on the
// artifact release day actually runs. A failure here means the flip would fail
// mid-apply, or apply cleanly and then be rejected by the receipt gate.
func TestReleaseDesignsExecutablePatchDeliversGateClaims(t *testing.T) {
	regions := patchNewRegions(t)

	var bad []string

	// The gate's flip-gated claims (deploymentDayDocClaims, requiredClaims) are
	// forbidden before the registry ships, so the patch is the only place they
	// can come from — matched raw, because that is how the gate matches them.
	checkAdded := func(rel, text, origin string) {
		region, ok := regions[rel]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s :: the patch never touches this file, so the gate's claim %q can never appear — %s", rel, text, origin))
			return
		}
		if strings.Contains(region, text) {
			return
		}
		if strings.Contains(normalizeWS(region), normalizeWS(text)) {
			bad = append(bad, fmt.Sprintf("%s :: WRAPPED — the patch produces the claim, but split across lines; the gate matches raw text, so move it onto one line — %s", rel, origin))
			return
		}
		bad = append(bad, fmt.Sprintf("%s :: the patch's added text never produces the gate's claim %q — %s", rel, text, origin))
	}
	for rel, text := range deploymentDayDocClaims {
		checkAdded(rel, text, "deploymentDayDocClaims")
	}
	for _, d := range releasePrepDrain {
		for _, text := range d.requiredClaims {
			checkAdded(d.rel, text, "releasePrepDrain.requiredClaims")
		}
		// alwaysRequired claims hold in both registry states, so they may
		// already be on the tree; what matters is that the flip keeps them.
		for _, text := range d.alwaysRequired {
			if strings.Contains(regions[d.rel], text) {
				continue
			}
			live, err := os.ReadFile("../../" + d.rel)
			if err != nil {
				bad = append(bad, fmt.Sprintf("%s :: unreadable (%v), cannot confirm the release-process claim %q survives the flip", d.rel, err, text))
				continue
			}
			if !strings.Contains(string(live), text) {
				bad = append(bad, fmt.Sprintf("%s :: neither the patch nor the tree carries the release-process claim %q, which the flip must keep — releasePrepDrain.alwaysRequired", d.rel, text))
			}
		}
	}

	// The patch touching a tracked file no gate covers is how a silent claim
	// ships: the wording changes, nothing checks it. Keep the two sets equal.
	gated := map[string]bool{}
	for rel := range deploymentDayDocClaims {
		gated[rel] = true
	}
	for _, d := range releasePrepDrain {
		gated[d.rel] = true
	}
	gated["internal/evm/mailboxdefaults.go"] = true // the registry entry, gated by TestShippedMailboxDefaultsCarryReceipts
	for rel := range regions {
		if !gated[rel] {
			bad = append(bad, fmt.Sprintf("%s :: the executable patch edits a file no gate in this package covers — add it to deploymentDayDocClaims or releasePrepDrain, or record in the patch why it is deliberately ungated", rel))
		}
	}

	// The registry entry is Go source, so check per line: alignment pads the
	// field names, and a `Default: "v0.9.0"` substring test would miss
	// `Default:    "v0.9.0"`.
	regionsByLine := map[string][]string{}
	for rel, region := range regions {
		regionsByLine[rel] = strings.Split(region, "\n")
	}
	hasLine := func(rel string, parts ...string) bool {
		for _, ln := range regionsByLine[rel] {
			hit := true
			for _, p := range parts {
				if !strings.Contains(ln, p) {
					hit = false
					break
				}
			}
			if hit {
				return true
			}
		}
		return false
	}
	if !hasLine("internal/evm/mailboxdefaults.go", `"8453": {`) {
		bad = append(bad, `internal/evm/mailboxdefaults.go :: the patch does not install the "8453" registry entry`)
	}
	if !hasLine("internal/evm/mailboxdefaults.go", "Default:", `"v0.9.0"`) {
		bad = append(bad, `internal/evm/mailboxdefaults.go :: the patch's registry entry does not record Default: "v0.9.0"`)
	}
	if !hasLine("internal/evm/mailboxdefaults.go", "ReceiptRef:", "docs/LIVE_NODES.md §3 STATUS / Base mainnet") {
		bad = append(bad, "internal/evm/mailboxdefaults.go :: the patch's registry entry does not cite its receipt (docs/LIVE_NODES.md §3 STATUS / Base mainnet)")
	}

	if len(bad) > 0 {
		sort.Strings(bad)
		for _, b := range bad {
			t.Errorf("executable flip patch: %s", b)
		}
		t.Errorf("%d defect(s) in %s — release day applies this file byte for byte", len(bad), releaseDesignsPatchFile)
	}
}
