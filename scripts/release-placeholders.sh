#!/usr/bin/env bash
# release-placeholders.sh — the last check before the tag: no rehearsal artifact
# may survive into a release.
#
# Release day applies two frozen patches that are deliberately full of markers,
# because they have to be appliable before the deployment exists:
#
#   <DRYRUN-…>   the dry run's synthetic receipt values (addresses, txids, dates)
#   <<…>>        the measured fee numbers and the receipt address the fee block cites
#   0x000…8453   the dry run's placeholder mailbox address
#
# Every one of them must be gone from the release surfaces by tag time. The
# receipt gate CANNOT see this: a placeholder address is still 0x + 40 hex and
# the flip still cites it in LIVE_NODES §3, so a forgotten placeholder satisfies
# every existing check and ships as the default mailbox for every user. This is
# the check that makes "replace them first" a command rather than an instruction.
#
# The STATUS line's `<release>` placeholder is deliberately NOT swept here: the
# release surfaces legitimately NAME that marker in their own instructions (the
# LIVE_NODES §3 runbook and the registry comment both tell you to replace it),
# so a textual sweep for it can never go green. The receipt gate already owns
# it: TestShippedMailboxDefaultsCarryReceipts fails when the registry ships an
# entry while that STATUS line still reads `<release>`.
#
# This script is meant to PASS on a clean tree and fail on a rehearsed one, so
# it is safe as a pre-push gate; the rehearsal asserts the failing direction.
#
#   bash scripts/release-placeholders.sh          # 0 clean, 1 markers remain
#   bash scripts/release-placeholders.sh --quiet  # exit status only
#
# The file list is derived from the two patches, so it cannot rot as they are
# edited: release surfaces are exactly what the patches write, plus the registry.
#
# Exit codes: 0 clean, 1 markers remain (EXPECTED until release day, and the
# rehearsal asserts this script is not blind), 2 cannot check, 3 usage.
set -euo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-placeholders: not inside a git repository" >&2
  exit 2
}
cd "$top"

QUIET=0
case "${1:-}" in
  "") : ;;
  --quiet) QUIET=1 ;;
  -h | --help)
    echo "usage: bash scripts/release-placeholders.sh [--quiet]"
    exit 0
    ;;
  *)
    echo "release-placeholders: unknown argument: $1 (see --help)" >&2
    exit 3
    ;;
esac

PATCHES=(release-designs/v0.9.0-doc-flips.patch release-designs/v0.9.0-fee-notes.patch)
for p in "${PATCHES[@]}"; do
  [ -f "$p" ] || {
    echo "release-placeholders: $p is missing — cannot derive the release surfaces" >&2
    exit 2
  }
done

gitx() { git -c core.autocrlf=false -c core.eol=lf "$@"; }

# The release surfaces: every file either patch writes, plus the registry the
# flip installs the default into (it is in the patch list already, but naming it
# keeps the sweep meaningful if a patch is ever re-derived).
files=$(gitx apply --numstat "${PATCHES[@]}" | awk '{print $3}' | sort -u)
missing=0
list=""
for f in $files; do
  if [ -f "$f" ]; then
    list="$list $f"
  else
    missing=1
  fi
done
if [ "$missing" -eq 1 ]; then
  echo "release-placeholders: a release surface named by the patches is not on this tree" >&2
  echo "  (expected pre-flip only if the patches do not apply yet; check the lists)" >&2
  exit 2
fi
[ -n "$list" ] || {
  echo "release-placeholders: the patches name no files — nothing to sweep" >&2
  exit 2
}

# shellcheck disable=SC2086
hits=$(grep -nHE '<DRYRUN-[A-Za-z0-9 -]*>|<<[A-Za-z0-9 _-]*>>|0x0{30,}' $list || true)

if [ -z "$hits" ]; then
  ((QUIET)) || echo "release-placeholders: clean — no rehearsal markers on the release surfaces"
  exit 0
fi

n=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
if ((QUIET)); then
  # --quiet is exit status only, on BOTH paths: callers that assert the
  # failing direction do not want the listing duplicated into their own output.
  exit 1
fi
echo "release-placeholders: $n marker line(s) still on the release surfaces."
echo "Fill each from the LIVE_NODES section-3 receipt (addresses, txids, dates)"
echo "and the saved deployment-day estimator output (the measured numbers), then"
echo "re-run. A placeholder that ships is a false claim, not a cosmetic bug."
echo
printf '%s\n' "$hits"
exit 1
