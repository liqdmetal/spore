#!/usr/bin/env bash
# release-day-rehearsal.sh — prove TODAY that release day is executable.
#
# Release day is two ordered passes, and no test applies either of them:
#
#   1. the flip  (release-designs/v0.9.0-doc-flips.patch)  — receipt, registry
#      entry, the four operator-facing rows, and the narrative prose drain.
#   2. the fees  (release-designs/v0.9.0-fee-notes.patch)  — measured fee and
#      limit notes, whose base is the tree pass 1 produced.
#
# This script runs both against a scratch tree and then runs the referee. The
# second patch's base IS the first patch's output, so the pair can only be
# rehearsed in order — and that order, plus the fact that the fee wording does
# not eat a line the receipt gate checks, is exactly what nobody had proven
# together.
#
# Then it proves the check has teeth: undoing ONLY the registry entry (so the
# docs claim a live deployment the registry does not back) must make the gate
# fail. A gate that passes on both a released and an unreleased tree would
# prove nothing.
#
#   bash scripts/release-day-rehearsal.sh              # full rehearsal
#   bash scripts/release-day-rehearsal.sh --check      # both passes apply in order, nothing run
#   bash scripts/release-day-rehearsal.sh --flip-only  # rehearse pass 1 alone
#   bash scripts/release-day-rehearsal.sh --sabotage-only
#   bash scripts/release-day-rehearsal.sh -s           # self-skip when go is absent
#   bash scripts/release-day-rehearsal.sh --keep       # leave the scratch tree for inspection
#
# Exit codes: 0 green (or already applied / self-skipped), 1 the rehearsal
# failed, 2 cannot check (missing tool or patch), 3 usage, 130 interrupted.
#
# Line endings are forced to LF for BOTH the extraction and the applies. On a
# Windows box whose system gitconfig sets core.autocrlf=true, git would
# otherwise rewrite every doc to CRLF, and the gate's fee-notes claim — which
# requires a literal newline followed by exactly three spaces — would fail on
# an otherwise perfect flip. The rehearsal must fail for real reasons only.
set -euo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-day-rehearsal: not inside a git repository" >&2
  exit 2
}
cd "$top"

PATCH_FLIP="release-designs/v0.9.0-doc-flips.patch"
PATCH_FEE="release-designs/v0.9.0-fee-notes.patch"

CHECK_ONLY=0
SABOTAGE_ONLY=0
FLIP_ONLY=0
SELF_SKIP=0
KEEP=0
usage() {
  cat <<'USAGE'
usage: bash scripts/release-day-rehearsal.sh [--check] [--flip-only] [--sabotage-only] [-s] [--keep]

  --check          only confirm the flip and the fee patches still apply, in order
  --flip-only      rehearse the flip pass alone (skip the fee pass)
  --sabotage-only  only run the negative phase (flip + fees minus the registry entry)
  -s               self-skip (exit 0) when the Go toolchain is unavailable
  --keep           keep the scratch tree and print its path
  -h, --help       this message
USAGE
}
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    --flip-only) FLIP_ONLY=1 ;;
    --sabotage-only) SABOTAGE_ONLY=1 ;;
    -s | --self-skip) SELF_SKIP=1 ;;
    --keep) KEEP=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "release-day-rehearsal: unknown argument: $a" >&2
      usage >&2
      exit 3
      ;;
  esac
done
if ((FLIP_ONLY)) && ((SABOTAGE_ONLY)); then
  echo "release-day-rehearsal: --flip-only and --sabotage-only are contradictory" >&2
  exit 3
fi

# ---- preconditions ---------------------------------------------------------
for tool in git tar mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "release-day-rehearsal: $tool not found — cannot check" >&2
    exit 2
  }
done
# The Go check comes AFTER the scratch tree is built: --check only runs
# `git apply --check`, so requiring a toolchain for it would block the callers
# that just want to know whether the passes still land (release-readiness.sh).
for p in "$PATCH_FLIP" "$PATCH_FEE"; do
  [ -f "$p" ] || {
    echo "release-day-rehearsal: $p is missing — release day has no executable pass" >&2
    exit 2
  }
done

# gitx pins line endings on every git call: the repository is stored LF, and the
# rehearsal must see the same bytes CI sees, whatever core.autocrlf says.
gitx() { git -c core.autocrlf=false -c core.eol=lf "$@"; }

# The flip already being in this tree is the release-day state, not a failure:
# there is nothing left to rehearse.
if gitx apply --reverse --check "$PATCH_FLIP" >/dev/null 2>&1; then
  echo "release-day-rehearsal: the flip is already applied to this tree — nothing to rehearse"
  exit 0
fi

sha=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
echo "== release-day rehearsal: v0.9.0 flip + fees, applied to a throwaway tree =="
echo "pass 1: $PATCH_FLIP"
echo "pass 2: $PATCH_FEE"
echo "tree:   HEAD $sha (committed state; the working tree is not used)"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/spore-release-rehearsal.XXXXXX")
cleanup() {
  if ((KEEP)); then
    echo "scratch tree kept: $tmp"
  else
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

work="$tmp/tree"
mkdir -p "$work"
gitx archive HEAD | tar -x -C "$work"
# The scratch is its own repository so that `git apply` cannot walk up out of
# it into the real checkout and patch the wrong tree.
git init -q "$work"

cd "$work"

echo
echo "-- pass 1: the flip still applies to HEAD"
if ! gitx apply --check "$top/$PATCH_FLIP" 2>"$tmp/apply.log"; then
  echo "REHEARSAL FAILED: the frozen flip no longer applies to HEAD." >&2
  echo "The docs moved under it. Re-derive release-designs/v0.9.0-doc-flips.patch" >&2
  echo "from the current tree (see the provenance header) and re-run." >&2
  sed 's/^/  /' "$tmp/apply.log" >&2
  exit 1
fi
gitx apply "$top/$PATCH_FLIP"
echo "   ok"

if ((FLIP_ONLY == 0)); then
  echo
  echo "-- pass 2: the fee notes still apply on top of the flip"
  # The fee patch's base IS the flipped tree, so this also asserts the pass
  # order: against unflipped HEAD it does not apply at all.
  if ! gitx apply --check "$top/$PATCH_FEE" 2>"$tmp/apply2.log"; then
    echo "REHEARSAL FAILED: the fee-notes patch does not apply on top of the flip." >&2
    echo "Either the flip moved a line the fee patches anchor on, or the fee patch" >&2
    echo "was re-derived against a different base." >&2
    sed 's/^/  /' "$tmp/apply2.log" >&2
    exit 1
  fi
  gitx apply "$top/$PATCH_FEE"
  echo "   ok"
fi

# ---- the fill list: what release day still has to type in ------------------
# Both patches are shape, not content: the receipt values and the measured fee
# numbers stay as markers until the deployment produces them. Report them from
# the APPLIED tree so the list cannot drift from the artifacts.
passes="$top/$PATCH_FLIP"
((FLIP_ONLY)) || passes="$passes $top/$PATCH_FEE"
touched=$(gitx apply --numstat $passes | awk '{print $3}' | sort -u)
markers=$(grep -ohE '<<[A-Za-z0-9 -]*>>|<release>|<DRYRUN-[A-Za-z -]*>' $touched 2>/dev/null | sort | uniq -c | sort -rn || true)
if [ -n "$markers" ]; then
  echo
  echo "-- outstanding on release day (fill from the section-3 receipt + the saved estimator output):"
  printf '%s\n' "$markers" | sed 's/^ *\([0-9]*\) */     \1 x /'
fi

if ((CHECK_ONLY)); then
  echo
  echo "RELEASE-DAY REHEARSAL GREEN (check only) — both passes apply, in order, to HEAD $sha"
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  if ((SELF_SKIP)); then
    echo "SKIP release-day rehearsal: the Go toolchain is not on PATH (self-skip)"
    exit 0
  fi
  echo "release-day-rehearsal: the passes apply, but go is not on PATH for the referee —" >&2
  echo "pass -s to self-skip when run without one" >&2
  exit 2
fi

run_gate() { # run_gate LOGFILE -> runs the referee, returns its status
  go test ./internal/evm ./cmd/spore -count=1 >"$1" 2>&1
}

# The filler cannot be verified here — the rehearsal IS the pre-fill state. What
# must be verified is that the sweep which guards it is not blind, or release
# day would ship a placeholder address that satisfies every other gate.
echo
echo "-- placeholder sweep (must flag THIS tree, which is the unfilled shape)"
if [ ! -f scripts/release-placeholders.sh ]; then
  echo "REHEARSAL FAILED: scripts/release-placeholders.sh is not in the rehearsed tree." >&2
  echo "Rehearsing the committed tree means the sweep must be committed too — without" >&2
  echo "it nothing in CI would notice a shipped placeholder address." >&2
  exit 1
fi
if bash scripts/release-placeholders.sh --quiet; then
  echo "REHEARSAL FAILED: the marker sweep reported a clean tree, but this tree is" >&2
  echo "full of rehearsal markers — it would let a placeholder ship." >&2
  exit 1
fi
# Take the count from the sweep's own summary line rather than counting lines of
# its output, or the message text inflates the number.
n=$(bash scripts/release-placeholders.sh | sed -n 's/^release-placeholders: \([0-9]*\) marker.*/\1/p' || true)
echo "   flagged, as it must be — ${n:-?} marker line(s) in the rehearsed tree (see the fill list above)"

# The tag pass is the one release artifact nothing else reads: the receipt gate
# never looks at the tag body, and a tag is immutable once pushed, so an
# unfilled field or a mis-stripped title would be permanent. Rehearse all three
# directions here — structure, the refusal, and the acceptance.
echo
echo "-- tag pass (draft -> strip at the marker -> signable body)"
if [ ! -f scripts/release-tag-message.sh ]; then
  echo "REHEARSAL FAILED: scripts/release-tag-message.sh is not in the rehearsed tree." >&2
  exit 1
fi
if ! bash scripts/release-tag-message.sh >/dev/null; then
  echo "REHEARSAL FAILED: the tag draft's structure is broken — the strip marker or the" >&2
  echo "body is not where the runbook says it is." >&2
  exit 1
fi
if bash scripts/release-tag-message.sh --write >/dev/null 2>&1; then
  echo "REHEARSAL FAILED: the tag pass stripped an UNFILLED draft. A tag is immutable" >&2
  echo "once pushed, so the placeholders would be signed into it permanently." >&2
  exit 1
fi
if ! bash scripts/release-tag-message.sh --self-test >/dev/null; then
  echo "REHEARSAL FAILED: the tag pass refuses a properly filled draft, so release day" >&2
  echo "would be blocked by the tool instead of by the missing receipt." >&2
  exit 1
fi
echo "   structure ok; refuses the unfilled draft; strips and validates a filled one"

# The readiness aggregator is what release day reads to answer "am I done?".
# It must be blocked on THIS tree — unfilled fields, an empty registry — or it
# would green-light a tag with a placeholder in it.
if [ -f scripts/release-readiness.sh ]; then
  echo
  echo "-- readiness aggregator (must be BLOCKED on this tree, which is not release-ready)"
  if bash scripts/release-readiness.sh --quiet; then
    echo "REHEARSAL FAILED: release-readiness.sh called this tree ready to tag." >&2
    echo "It carries unfilled fields and an empty registry, so the aggregator is blind." >&2
    exit 1
  fi
  nb=$(bash scripts/release-readiness.sh 2>/dev/null | sed -n 's/^NOT READY TO TAG — \([0-9]*\) blocker.*/\1/p' || true)
  echo "   blocked, as it must be — ${nb:-?} blocker(s)"
fi

# ---- phase 1: flip + fees, the gate must pass ------------------------------
# (skipped under --sabotage-only, which exists to show the negative alone)
if ((SABOTAGE_ONLY == 0)); then
  addr=$(grep -oE '"0x[0-9a-fA-F]{40}"' internal/evm/mailboxdefaults.go | head -1 | tr -d '"' || true)
  echo
  echo "-- registry address ${addr:-unknown} (a placeholder, not a real claim)"
  t0=$SECONDS
  if run_gate "$tmp/gate-released.log"; then
    echo "-- receipt gate on the released tree ..... GREEN ($((SECONDS - t0))s) [go test ./internal/evm ./cmd/spore]"
  else
    echo "-- receipt gate on the released tree ..... RED" >&2
    echo "REHEARSAL FAILED: the passes applied but the receipt gate rejects the result." >&2
    grep -E '^(---|    )' "$tmp/gate-released.log" | head -30 >&2
    exit 1
  fi
fi

# ---- phase 2: same tree minus the registry entry, the gate must fail -------
# Undo ONLY internal/evm/mailboxdefaults.go: the docs keep claiming a live Base
# deployment while the registry says none shipped. That is exactly the
# release-day mistake the gate exists to catch, so the gate must reject it.
if ((SABOTAGE_ONLY)); then
  gitx apply "$top/$PATCH_FLIP"
  ((FLIP_ONLY)) || gitx apply "$top/$PATCH_FEE"
fi
echo
echo "-- negative control: the released tree minus the registry entry"
if ! gitx apply --reverse --include='internal/evm/mailboxdefaults.go' "$top/$PATCH_FLIP"; then
  echo "REHEARSAL FAILED: could not undo the registry entry for the negative control" >&2
  exit 1
fi
echo "   registry restored to the empty map; the docs still claim the deployment"
t0=$SECONDS
rc=0
run_gate "$tmp/gate-sabotaged.log" || rc=$?
if ((rc == 0)); then
  echo "   gate stayed GREEN — it cannot tell a released tree from an unreleased one" >&2
  echo "REHEARSAL FAILED: the receipt gate has no teeth; a doc-only flip would pass." >&2
  exit 1
fi
if ! grep -qE '^--- FAIL: (TestShippedMailboxDefaultsCarryReceipts|TestDocClaimsMatchRegistryState|TestReleasePrepProseDrainedAfterFlip)' "$tmp/gate-sabotaged.log"; then
  echo "   gate failed, but not in the receipt gate — the rehearsal proved nothing" >&2
  grep -E '^---' "$tmp/gate-sabotaged.log" | head -20 >&2
  echo "REHEARSAL FAILED: unexpected failure mode under sabotage." >&2
  exit 1
fi
echo "-- negative control ...................... RED as required ($((SECONDS - t0))s)"
grep -E '^--- FAIL: Test' "$tmp/gate-sabotaged.log" | sed 's/^/   /'

echo
if ((FLIP_ONLY)); then
  echo "RELEASE-DAY REHEARSAL GREEN — the flip applies to HEAD $sha and the receipt gate both passes it and rejects a doc-only flip (fee pass not rehearsed)"
else
  echo "RELEASE-DAY REHEARSAL GREEN — flip + fees apply in order to HEAD $sha and the receipt gate both passes them and rejects a doc-only flip"
fi
