#!/usr/bin/env bash
# release-day-rehearsal.sh — prove TODAY that release day is executable.
#
# Release day applies release-designs/v0.9.0-doc-flips.patch to this tree and
# then runs the receipt gate. Nothing in the test suite applies that patch, so
# until now the apply itself was rehearsed exactly once, by hand, on a
# throwaway branch. This script turns that one-off into a command: it extracts
# HEAD into a scratch directory, applies the frozen patch there, and runs the
# referee. If the docs drift, the patch stops applying or stops satisfying the
# gate, and this fails — long before the deployment exists.
#
# Then it proves the check has teeth. Drugging the rehearsal (undoing ONLY the
# registry-entry file after the flip) must make the gate fail: a gate that
# passes on both a flipped and an unflipped tree would prove nothing.
#
#   bash scripts/release-day-rehearsal.sh              # full rehearsal
#   bash scripts/release-day-rehearsal.sh --check      # patch applies cleanly, nothing run
#   bash scripts/release-day-rehearsal.sh --sabotage-only   # only the negative phase
#   bash scripts/release-day-rehearsal.sh -s           # self-skip when go is absent (CI/dev without Go)
#   bash scripts/release-day-rehearsal.sh --keep       # leave the scratch tree for inspection
#
# Exit codes: 0 green (or already applied / self-skipped), 1 the rehearsal
# failed, 2 cannot check (missing tool or patch), 3 usage, 130 interrupted.
#
# Line endings are forced to LF for BOTH the extraction and the apply. On a
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

PATCH="release-designs/v0.9.0-doc-flips.patch"

CHECK_ONLY=0
SABOTAGE_ONLY=0
SELF_SKIP=0
KEEP=0
usage() {
  cat <<'USAGE'
usage: bash scripts/release-day-rehearsal.sh [--check] [--sabotage-only] [-s] [--keep]

  --check          only confirm the frozen patch still applies to HEAD
  --sabotage-only  only run the negative phase (flip minus the registry entry)
  -s               self-skip (exit 0) when the Go toolchain is unavailable
  --keep           keep the scratch tree and print its path
  -h, --help       this message
USAGE
}
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
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

# ---- preconditions ---------------------------------------------------------
for tool in git tar mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "release-day-rehearsal: $tool not found — cannot check" >&2
    exit 2
  }
done
if ! command -v go >/dev/null 2>&1; then
  if ((SELF_SKIP)); then
    echo "SKIP release-day rehearsal: the Go toolchain is not on PATH (self-skip)"
    exit 0
  fi
  echo "release-day-rehearsal: go not found — pass -s to self-skip" >&2
  exit 2
fi
[ -f "$PATCH" ] || {
  echo "release-day-rehearsal: $PATCH is missing — release day has no executable flip" >&2
  exit 2
}

# gitx pins line endings on every git call: the repository is stored LF, and
# the rehearsal must see the same bytes CI sees, whatever core.autocrlf says.
gitx() { git -c core.autocrlf=false -c core.eol=lf "$@"; }

# The flip already being in this tree is the release-day state, not a failure:
# there is nothing left to rehearse.
if gitx apply --reverse --check "$PATCH" >/dev/null 2>&1; then
  echo "release-day-rehearsal: the flip is already applied to this tree — nothing to rehearse"
  exit 0
fi

sha=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
echo "== release-day rehearsal: v0.9.0 flip, applied to a throwaway tree =="
echo "patch: $PATCH"
echo "tree:  HEAD $sha (committed state; the working tree is not used)"

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
echo "-- patch still applies to HEAD"
if ! gitx apply --check "$top/$PATCH" 2>"$tmp/apply.log"; then
  echo "REHEARSAL FAILED: the frozen patch no longer applies to HEAD." >&2
  echo "The docs moved under the patch. Re-derive release-designs/v0.9.0-doc-flips.patch" >&2
  echo "from the current tree (see the provenance header) and re-run." >&2
  sed 's/^/  /' "$tmp/apply.log" >&2
  exit 1
fi
echo "   ok"

if ((CHECK_ONLY)); then
  echo
  echo "RELEASE-DAY REHEARSAL GREEN (check only) — the patch applies to HEAD $sha"
  exit 0
fi

run_gate() { # run_gate LOGFILE -> writes output, returns the gate's status
  go test ./internal/evm ./cmd/spore -count=1 >"$1" 2>&1
}

# ---- phase 1: apply the flip, the gate must pass ---------------------------
# (skipped under --sabotage-only, which exists to show the negative alone)
if ((SABOTAGE_ONLY == 0)); then
  gitx apply "$top/$PATCH"
  addr=$(grep -oE '"0x[0-9a-fA-F]{40}"' internal/evm/mailboxdefaults.go | head -1 | tr -d '"' || true)
  echo
  echo "-- flip applied (registry address ${addr:-unknown}: a placeholder, not a real claim)"
  t0=$SECONDS
  if run_gate "$tmp/gate-flipped.log"; then
    echo "-- receipt gate on the flipped tree ......... GREEN ($((SECONDS - t0))s) [go test ./internal/evm ./cmd/spore]"
  else
    echo "-- receipt gate on the flipped tree ......... RED" >&2
    echo "REHEARSAL FAILED: the flip applied but the receipt gate rejects it." >&2
    grep -E '^(---|    )' "$tmp/gate-flipped.log" | head -30 >&2
    exit 1
  fi
fi

# ---- phase 2: same flip minus the registry entry, the gate must fail -------
# Undo ONLY internal/evm/mailboxdefaults.go: the docs keep claiming a live Base
# deployment while the registry says none shipped. That is exactly the release
# -day mistake the gate exists to catch, so the gate must reject it.
if ((SABOTAGE_ONLY)); then
  gitx apply "$top/$PATCH"
fi
echo
echo "-- negative control: flip minus the registry entry"
if ! gitx apply --reverse --include='internal/evm/mailboxdefaults.go' "$top/$PATCH"; then
  echo "REHEARSAL FAILED: could not undo the registry entry for the negative control" >&2
  exit 1
fi
echo "   registry restored to the empty map; the docs still claim the deployment"
t0=$SECONDS
rc=0
run_gate "$tmp/gate-sabotaged.log" || rc=$?
if ((rc == 0)); then
  echo "   gate stayed GREEN — the gate cannot tell a flipped tree from an unflipped one" >&2
  echo "REHEARSAL FAILED: the receipt gate has no teeth; a doc-only flip would pass." >&2
  exit 1
fi
if ! grep -qE '^--- FAIL: (TestShippedMailboxDefaultsCarryReceipts|TestDocClaimsMatchRegistryState|TestReleasePrepProseDrainedAfterFlip)' "$tmp/gate-sabotaged.log"; then
  echo "   gate failed, but not in the receipt gate — the rehearsal proved nothing" >&2
  grep -E '^---' "$tmp/gate-sabotaged.log" | head -20 >&2
  echo "REHEARSAL FAILED: unexpected failure mode under sabotage." >&2
  exit 1
fi
echo "-- negative control ......................... RED as required ($((SECONDS - t0))s)"
grep -E '^--- FAIL: Test' "$tmp/gate-sabotaged.log" | sed 's/^/   /'

echo
echo "RELEASE-DAY REHEARSAL GREEN — the flip applies to HEAD $sha and the receipt gate both passes it and rejects a doc-only flip"
