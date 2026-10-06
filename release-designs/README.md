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
| [`v0.9.0-doc-flips.md`](v0.9.0-doc-flips.md) | The receipt-backed flip patches: the registry entry, the four operator-facing rows, and the narrative/status drain across 14 files. | The flip commit. Carries an inline provenance header and the line-wrap invariants the dry-run rehearsal found. |
| [`v0.9.0-fee-notes.md`](v0.9.0-fee-notes.md) | The measured fee + limit notes: per-chain gas reality and the not-payable contract path. | The release-prep pass, **after** the real numbers exist. |
| [`v0.9.0-tag-message.txt`](v0.9.0-tag-message.txt) | The signed-tag message draft, with `<<FILL:…>>` fields and a strip marker. | Last: fill → strip into `v0.9.0-tag-message-final.txt` → `git tag -s`. |
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
- **`scripts/release-designs-check.sh`** (wired into `scripts/gates.sh`) fails
  when a draft is missing or a tracked file points at a `release-designs/`
  artifact that does not exist. `--status` prints what is still unfilled:

  ```bash
  bash scripts/release-designs-check.sh --status
  ```

## Provenance

Copied byte-for-byte on 2026-10-06 from the release working area one level above
the repository root (under no version control). The flip patch was rehearsed
green on branch `dryrun/deploy-day-publish` before vendoring and carries the
wrap-constraint annotations from that run; the other four are unmodified copies.
