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
		"v0.9.0-fee-notes.md",
		"v0.9.0-tag-message.txt",
		"v0.9.0-landing-card.md",
	} {
		if _, err := os.Stat("../../release-designs/" + name); err != nil {
			t.Errorf("release-designs/%s is missing from the repo (%v) — the release-prep set must stay self-contained", name, err)
		}
	}
}
