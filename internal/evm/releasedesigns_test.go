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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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

// TestReleaseDesignsNamesResolveInRepo guards the release paperwork as a
// document, not as a patch. It names scripts, docs, contracts, packages, and
// tests by name, and those instructions are read by a human under time
// pressure on the one day the repository must not lie. A rename anywhere else
// silently turns them into fiction, and nothing else reads them: the receipt
// gate checks claims about the deployment, not whether `scripts/foo.sh` still
// exists. Every name the six files use has to resolve here.
func TestReleaseDesignsNamesResolveInRepo(t *testing.T) {
	repo := "../.."

	// The one name that is deliberately absent: it is created at tag time by
	// scripts/release-tag-message.sh --write, as the last action. Keep this in
	// step with NOT_YET in scripts/release-designs-check.sh.
	notYet := map[string]bool{"v0.9.0-tag-message-final.txt": true}

	// pathRe matches repository paths (packages included, so a moved package is
	// caught too); bareRe matches a document named without a directory.
	pathRe := regexp.MustCompile(`(?:scripts|docs|internal|cmd|contracts|tools)/[A-Za-z0-9_./-]*[A-Za-z0-9_]`)
	// The leading class excludes a path separator and the ellipsis: the drafts
	// write shorthand like "`…final.txt`" for a long name, and that tail is not
	// a filename anybody has to resolve.
	bareRe := regexp.MustCompile(`(?:^|[^/A-Za-z0-9_.\-…])([A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:md|txt|patch))`)
	testRe := regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*\b`)

	var texts []string
	for _, name := range []string{
		"README.md", "v0.9.0-pretag-checklist.md", "v0.9.0-doc-flips.md",
		"v0.9.0-fee-notes.md", "v0.9.0-tag-message.txt", "v0.9.0-landing-card.md",
	} {
		raw, err := os.ReadFile("../../release-designs/" + name)
		if err != nil {
			t.Fatalf("release-designs/%s unreadable: %v", name, err)
		}
		texts = append(texts, string(raw))
	}

	// Test names live in _test.go files, and only under these two trees.
	declaredTests := map[string]bool{}
	for _, root := range []string{"../../internal", "../../cmd"} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			s := string(b)
			for _, m := range testRe.FindAllString(s, -1) {
				if strings.Contains(s, "func "+m+"(") {
					declaredTests[m] = true
				}
			}
			return nil
		})
	}

	var bad []string
	seen := map[string]bool{}
	note := func(kind, name string) {
		key := kind + " " + name
		if seen[key] {
			return
		}
		seen[key] = true
		bad = append(bad, kind+" "+name)
	}

	for _, s := range texts {
		for _, raw := range pathRe.FindAllString(s, -1) {
			p := strings.TrimRight(raw, ".-/")
			if p == "" || notYet[filepath.Base(p)] {
				continue
			}
			if _, err := os.Stat(filepath.Join(repo, p)); err != nil {
				note("PATH", p+" is named by the release drafts but does not exist")
			}
		}
		for _, m := range bareRe.FindAllStringSubmatch(s, -1) {
			name := strings.TrimRight(m[1], ".-")
			if notYet[name] {
				continue
			}
			found := false
			for _, dir := range []string{"", "docs/", "release-designs/"} {
				if _, err := os.Stat(filepath.Join(repo, dir+name)); err == nil {
					found = true
					break
				}
			}
			if !found {
				note("DOC", name+" is named by the release drafts but is not at the repo root, docs/, or release-designs/")
			}
		}
		for _, name := range testRe.FindAllString(s, -1) {
			if !declaredTests[name] {
				note("TEST", name+" is named by the release drafts but no _test.go under internal/ or cmd/ declares it")
			}
		}
	}

	if len(bad) > 0 {
		sort.Strings(bad)
		for _, b := range bad {
			t.Errorf("release paperwork names something that is not there: %s", b)
		}
		t.Errorf("%d stale reference(s) — a renamed file makes release day read instructions that cannot be followed", len(bad))
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
		"v0.9.0-fee-notes.patch",
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
const (
	releaseDesignsPatchFile  = "../../release-designs/v0.9.0-doc-flips.patch"
	releaseFeeNotesPatchFile = "../../release-designs/v0.9.0-fee-notes.patch"
)

// patchNewRegions returns, per target file, the post-apply text of every hunk's
// changed region, in order: context and added lines kept, removed lines
// dropped. That is the same text `git apply` leaves on disk, so a claim that
// occurs here occurs in the flipped doc too.
func patchNewRegions(t *testing.T) map[string]string {
	t.Helper()
	return patchNewRegionsFrom(t, releaseDesignsPatchFile)
}

func patchNewRegionsFrom(t *testing.T, file string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(file)
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

// TestReleaseFeeNotesPatchStaysOffTheGatedLines guards the second release-day
// pass, whose whole safety argument is "these fee patches touch only DIFFERENT
// lines of the same files". The receipt gate cannot check that promise by
// itself: it only sees the tree after both passes. So check the promise
// directly — the fee wording may not introduce a claim the gate forbids, may
// not be aimed at a file the gate pins that the draft deliberately excludes,
// and must be the four files the draft names, in the draft's order.
func TestReleaseFeeNotesPatchStaysOffTheGatedLines(t *testing.T) {
	regions := patchNewRegionsFrom(t, releaseFeeNotesPatchFile)

	// The draft rules the README cell out by name: the gate pins it to the
	// exact flipped string, so fee text belongs in LIVE_NODES §3.
	if _, ok := regions["README.md"]; ok {
		t.Errorf("the fee-notes patch edits README.md, whose EVM cell the receipt gate pins to the flipped string — the draft keeps fee text in LIVE_NODES §3")
	}

	gated := map[string]bool{}
	for rel := range deploymentDayDocClaims {
		gated[rel] = true
	}
	for _, d := range releasePrepDrain {
		gated[d.rel] = true
	}
	for _, want := range []string{"docs/LIVE_NODES.md", "docs/CARRIER_MATRIX.md", "docs/ONBOARDING.md", "ROADMAP.md"} {
		if _, ok := regions[want]; !ok {
			t.Errorf("the fee-notes patch does not touch %s, which the draft's patch list names", want)
		}
	}
	for rel := range regions {
		if !gated[rel] {
			t.Errorf("%s :: the fee-notes patch edits a file no gate in this package covers", rel)
		}
	}

	// A forbidden token in the added text is a claim the flip just removed
	// coming back in the release-prep pass; no fee edit legitimately needs one.
	for _, d := range releasePrepDrain {
		region, ok := regions[d.rel]
		if !ok {
			continue
		}
		lower := strings.ToLower(region)
		for _, tok := range d.forbidden {
			if strings.Contains(region, tok) {
				t.Errorf("%s :: the fee-notes patch reintroduces the stale claim %q, which the flip removed", d.rel, tok)
			}
		}
		for _, tok := range d.forbiddenLower {
			if strings.Contains(lower, tok) {
				t.Errorf("%s :: the fee-notes patch reintroduces the stale claim %q (case-insensitive)", d.rel, tok)
			}
		}
	}
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
