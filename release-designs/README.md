# release-designs — the v0.9.0 release-prep set

Ready-to-apply drafts for the v0.9.0 "deploy the EVM mailbox on Base" release,
vendored in-tree on 2026-10-06 from the release working area that lived
*outside* version control. Release day must not depend on an uncommitted
directory, so these live here now, next to the code and doc surfaces they patch.

**Status: NOT applied.** Every `<<…>>` / `<release>` placeholder is still
unfilled — these are the instructions, not the result. Applying them is the
deployment-day commit described in
[`../docs/LIVE_NODES.md`](../docs/LIVE_NODES.md) §3.

## The set

| File | What it is | When it is used |
|---|---|---|
| [`v0.9.0-pretag-checklist.md`](v0.9.0-pretag-checklist.md) | The release-day orchestrator — the ordered steps (decide → gates → flip → fee notes → version → tag → push → verify). | Read first, top to bottom. |
| [`v0.9.0-doc-flips.md`](v0.9.0-doc-flips.md) | The receipt-backed flip patches: the registry entry, the four operator-facing rows, and the narrative/status drain across 14 files. | Read it to understand the flip. Carries an inline provenance header and the line-wrap invariants the dry-run rehearsal found. |
| [`v0.9.0-doc-flips.patch`](v0.9.0-doc-flips.patch) | The same flip in its **executable** form: the byte-exact `git apply` artifact, frozen from the dry-run commit and machine-checked against the gate. | The flip commit — apply it, don't retype it. |
| [`v0.9.0-fee-notes.md`](v0.9.0-fee-notes.md) | The measured fee + limit notes: per-chain gas reality and the not-payable contract path. | Read it to understand the pass. |
| [`v0.9.0-fee-notes.patch`](v0.9.0-fee-notes.patch) | The same pass in **executable** form. Its base is the tree the flip patch produces, so it can only land second. | The release-prep pass, **after** the real numbers exist. |
| [`v0.9.0-tag-message.txt`](v0.9.0-tag-message.txt) | The signed-tag message draft, with `<<FILL:…>>` fields and a strip marker. | Last: fill → `scripts/release-tag-message.sh --write` → `git tag -s`. |
| [`v0.9.0-landing-card.md`](v0.9.0-landing-card.md) | The release narrative / landing copy: what landed, the done-bar, the first move. | With the announcement. |

## Conventions

- **The `.txt` tag message is byte-exact on purpose.** It is consumed verbatim
  by `git tag -s v0.9.0 -F …`, so it carries no provenance header; its
  instructions are in its own comment block, which is stripped before signing
  (see its "strip EVERYTHING above this line" marker). The `.md` drafts carry a
  provenance header instead.
- **Find every placeholder** with:
  `grep -n '<<' release-designs/v0.9.0-*.md release-designs/v0.9.0-tag-message.txt`
- **The referee is `internal/evm/mailboxdefaults_test.go`** (the receipt gate):
  it fails if a doc claims the deployment is live while the registry is empty,
  and if the registry ships without every doc claim —
  `go test ./internal/evm ./cmd/spore -count=1`.
- These files are release paperwork, not build inputs: nothing here is compiled
  or shipped in a binary.

## Guards (they keep this set from rotting)

- **`TestReleaseDesignsPatchCarriesGateClaims`** (`internal/evm/releasedesigns_test.go`)
  pins the flip patch to the receipt gate: every claim the gate requires must be
  stated in `v0.9.0-doc-flips.md`, and the registry entry it installs must be
  documented. Change the gate's required wording without updating the patch and
  this test fails — instead of release day failing mid-apply.
- **`TestReleaseDesignsExecutablePatchDeliversGateClaims`** covers the artifact
  release day actually runs. It reconstructs every hunk's post-apply text from
  `v0.9.0-doc-flips.patch` and requires each gated claim to appear **raw** in
  the right file — so a claim the patch wraps across two lines fails here in a
  second, with `WRAPPED`, instead of failing the gate mid-apply. It also fails
  if the patch edits a file no gate covers (a silent claim).
- **`TestReleaseFeeNotesPatchStaysOffTheGatedLines`** guards the second pass,
  whose entire safety argument is "these fee patches touch only *different*
  lines of the same files". It fails if the fee patch reintroduces a claim the
  flip removed, or edits README (whose EVM cell the gate pins to the flipped
  string; the draft keeps fee text in LIVE_NODES §3).
- **`scripts/release-day-rehearsal.sh`** is the end-to-end proof of the pair,
  in order: it extracts HEAD into a scratch tree, applies the flip, applies the
  fees on top, runs the referee, then un-does **only** the registry entry and
  requires the referee to fail. It also lists every marker release day still
  has to fill, read out of the applied tree, and asserts the sweep below is not
  blind.

  ```bash
  bash scripts/release-day-rehearsal.sh            # flip + fees green, negative control red
  bash scripts/release-day-rehearsal.sh --check    # only: both passes still apply in order
  bash scripts/release-day-rehearsal.sh --flip-only
  bash scripts/release-designs-check.sh --status   # what is still unfilled
  ```

  It runs on every push (CI job `release-rehearsal`), so doc drift breaks the
  build weeks before the deployment. Line endings are forced to LF: on a
  Windows box with `core.autocrlf=true`, git would otherwise rewrite the docs
  to CRLF and the fee-notes claim — which needs a literal newline plus exactly
  three spaces — would fail an otherwise perfect flip.
- **`scripts/release-placeholders.sh`** is the last check before the tag, and
  the one nothing else replaces. Both patches ship *markers* (the dry run's
  synthetic receipt values and its `0x000…8453` address; the unfilled measured
  numbers) because they must be appliable before the deployment exists. A
  forgotten placeholder address still satisfies the receipt gate — it is `0x` +
  40 hex, and the flip still cites it in LIVE_NODES §3 — so it would ship as the
  default mailbox for every user. The sweep derives its file list from the
  patches, passes on a clean tree, and exits 1 while any marker remains; it runs
  in `gates.sh` and in CI, which is what makes "replace them first" a command
  rather than an instruction. The rehearsal asserts the failing direction, so
  the sweep cannot quietly go blind. `<release>` is deliberately not swept — the
  docs name that marker in their own instructions, and the receipt gate already
  owns it.
- **`scripts/release-tag-message.sh`** is the tag pass, executable — the last
  release-day step and the only artifact the receipt gate never reads. `--check`
  (run in `gates.sh`) validates the draft's structure on any tree: the strip
  marker appears exactly once, the body after it is non-empty, every marker in
  the body is a `<<FILL: …>>` field, and no stale `-final.txt` from the dry run
  is sitting there. `--write` fills that in: it refuses while any field is
  unfilled (a tag is immutable once pushed), then strips, then validates the
  body — no markers, no rehearsal values, a citation of `docs/LIVE_NODES.md` §3,
  and the draft's own title as the first line. `--self-test` proves both
  directions on a synthetically filled copy, because the draft cannot be filled
  and still be a draft. The rehearsal runs all three on every push.
- **`scripts/release-readiness.sh`** is what release day reads to answer "am I
  done?". It composes the checks above rather than re-deriving them — set
  integrity, tag-draft structure, tag fields, the marker sweep, the registry's
  own state, and whether both frozen passes still land — and exits 1 while
  anything is outstanding, naming each blocker with the command that clears it.
  It also prints the checklist steps it does **not** cover, so a green run is
  never mistaken for "the deployment happened". It is expected to exit 1 until
  release day, so it is not a pre-push gate; the rehearsal asserts it is
  blocked on the released-shape tree.
- **`scripts/release-designs-check.sh`** (wired into `scripts/gates.sh`) fails
  when a draft is missing or a tracked file points at a `release-designs/`
  artifact that does not exist.

## Provenance

Copied byte-for-byte on 2026-10-06 from the release working area one level above
the repository root (under no version control). The flip patch was rehearsed
green on branch `dryrun/deploy-day-publish` before vendoring and carries the
wrap-constraint annotations from that run; the other four are unmodified copies.
`v0.9.0-doc-flips.patch` is the committed diff of that rehearsal commit, so it
is the *verified* shape rather than a retyped one — the only thing release day
changes is the placeholder address and the receipt values it fills in first.
`v0.9.0-fee-notes.patch` has no such ancestry: it is the draft's patches 1a,
1b, 2, 3, 4a and 4b applied by hand to a flipped tree and frozen, and its
header records the four judgement calls that took (the conditional stub
footnote is not carried; 1a and 1b target the same bullet; 4b's quoted anchor
was replaced by the flip, so its sentence lands on the post-flip item 4; and
4a's box text is byte-exact from the flip).
