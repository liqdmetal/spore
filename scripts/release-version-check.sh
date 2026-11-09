#!/usr/bin/env bash
# release-version-check.sh — one release version, everywhere it is pinned.
#
# Every release bumps the same version in five places by hand: the newest
# heading in docs/RELEASES.md, the bolded row and the `SPORE_RELEASE` /
# `--source-tag` pins in README.md, and the `SPORE_RELEASE` plus `vTAG` pins in
# docs/ONBOARDING.md. v0.11.1 proved how quiet a half-bump is: the notes landed,
# the commit succeeded, and README plus both onboarding pins still said v0.11.0
# because an in-place edit wrote nothing and exited 0. Nothing in the suite
# noticed, because every gate reads its own file.
#
# The newest RELEASES.md heading is the reference: a release is defined by its
# notes. If the pins disagree with it — in either direction, a stale pin or notes
# written before the bump — this fails and names every disagreeing line.
#
#   bash scripts/release-version-check.sh           # report mismatches
#   bash scripts/release-version-check.sh --quiet   # exit status only
#
# Exit codes: 0 every pin names the newest release, 1 a pin disagrees (or a pin
# is missing entirely), 2 cannot check (no git repo, no RELEASES.md heading),
# 3 usage.
set -euo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-version-check: not inside a git repository" >&2
  exit 2
}
cd "$top"

QUIET=0
case "${1:-}" in
  "") : ;;
  --quiet) QUIET=1 ;;
  -h | --help)
    echo "usage: bash scripts/release-version-check.sh [--quiet]"
    exit 0
    ;;
  *)
    echo "release-version-check: unknown argument: $1 (see --help)" >&2
    exit 3
    ;;
esac

for f in docs/RELEASES.md README.md docs/ONBOARDING.md; do
  [ -f "$f" ] || {
    echo "release-version-check: $f is missing — cannot check" >&2
    exit 2
  }
done

# tr -d '\r' on every extraction: these files are checked out with CRLF on
# Windows, and a trailing carriage return would read as a different version.
latest=$(awk '/^## v[0-9]+\.[0-9]+\.[0-9]+/ { sub(/^## +/, ""); print $1; exit }' docs/RELEASES.md | tr -d '\r')
[ -n "$latest" ] || {
  echo "release-version-check: docs/RELEASES.md has no '## vX.Y.Z' release heading" >&2
  exit 2
}

readme_row=$(grep -oE '^\| \*\*\[v[0-9]+\.[0-9]+\.[0-9]+' README.md |
  head -1 | sed 's/^.*\[//' | tr -d '\r')
readme_pins=$(grep -oE 'SPORE_RELEASE=v[0-9]+\.[0-9]+\.[0-9]+[^ `"]*' README.md |
  sed 's/^SPORE_RELEASE=//' | tr -d '\r')
readme_tags=$(grep -oE -- '--source-tag v[0-9]+\.[0-9]+\.[0-9]+[^ `]*' README.md |
  sed 's/^--source-tag //' | tr -d '\r')
onboarding_pins=$(grep -oE 'SPORE_RELEASE=v[0-9]+\.[0-9]+\.[0-9]+[^ `"]*' docs/ONBOARDING.md |
  sed 's/^SPORE_RELEASE=//' | tr -d '\r')
onboarding_vtag=$(grep -oE '`vTAG` is `v[0-9]+\.[0-9]+\.[0-9]+`' docs/ONBOARDING.md |
  sed 's/.*`\(v[0-9][^`]*\)`.*/\1/' | tr -d '\r')

work=$(mktemp) || exit 2
trap 'rm -f "$work"' EXIT

# pair LABEL VALUE... — one tab-separated line per pinned value.
pair() {
  local label=$1 v
  shift
  for v in "$@"; do
    [ -n "$v" ] && printf '%s\t%s\n' "$label" "$v"
  done
}

{
  pair "docs/RELEASES.md newest heading" "$latest"
  pair "README.md bolded release row" "$readme_row"
  # shellcheck disable=SC2086
  pair "README.md SPORE_RELEASE pin" $readme_pins
  # shellcheck disable=SC2086
  pair "README.md slsa --source-tag" $readme_tags
  # shellcheck disable=SC2086
  pair "docs/ONBOARDING.md SPORE_RELEASE pin" $onboarding_pins
  # shellcheck disable=SC2086
  pair "docs/ONBOARDING.md vTAG pin" $onboarding_vtag
} >"$work"

# A pin that vanished is as broken as a pin that disagrees: the README could
# lose its install pin and every remaining check would still pass.
missing=0
while IFS= read -r label; do
  if ! cut -f1 "$work" | grep -qxF "$label"; then
    missing=1
    [ "$QUIET" -eq 1 ] || echo "release-version-check: $label — no pin found at all" >&2
  fi
done <<'LABELS'
docs/RELEASES.md newest heading
README.md bolded release row
README.md SPORE_RELEASE pin
README.md slsa --source-tag
docs/ONBOARDING.md SPORE_RELEASE pin
docs/ONBOARDING.md vTAG pin
LABELS

mismatch=0
bad=$(awk -F'\t' -v want="$latest" '$2 != want { print $1 "\t" $2 }' "$work" | sort -u)
if [ -n "$bad" ]; then
  mismatch=$(printf '%s\n' "$bad" | wc -l | tr -d ' ')
fi

if [ "$missing" -eq 0 ] && [ "$mismatch" -eq 0 ]; then
  ((QUIET)) || echo "release-version-check: clean — $latest in RELEASES.md, README.md and ONBOARDING.md"
  exit 0
fi

((QUIET)) && exit 1
echo "release-version-check: not one version. docs/RELEASES.md defines $latest."
if [ "$missing" -gt 0 ]; then
  echo "  a pin named above is absent — restore it next to the others."
fi
if [ "$mismatch" -gt 0 ]; then
  echo "  $mismatch pinned value(s) disagree:"
  printf '%s\n' "$bad" | awk -F'\t' -v want="$latest" '{ printf "    %-42s %s (expected %s)\n", $1, $2, want }'
fi
echo
echo "Bump every one in the same commit as the release notes, or the install pin"
echo "and the slsa verify command point at a tag that is not the one you shipped."
exit 1
