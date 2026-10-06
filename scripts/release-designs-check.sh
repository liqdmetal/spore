#!/usr/bin/env bash
# release-designs-check.sh — integrity + readiness check for the vendored
# v0.9.0 release-prep set in release-designs/.
#
# The default mode is CI-safe, read-only, and fast: it fails when the set is
# incomplete or when a tracked file points at a release-designs/ artifact that
# does not exist. That is what keeps release day dependent on nothing outside
# version control — a renamed or dropped draft breaks the build instead of
# breaking the release.
#
#   bash scripts/release-designs-check.sh            # integrity (exit 0 / 1)
#   bash scripts/release-designs-check.sh --status   # + readiness report
#
# Exit codes: 0 intact, 1 a missing draft or a broken pointer, 2 usage error.
set -euo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-designs-check: not inside a git repository" >&2
  exit 2
}
cd "$top"

SHOW_STATUS=0
case "${1:-}" in
  "") : ;;
  --status) SHOW_STATUS=1 ;;
  -h | --help)
    echo "usage: bash scripts/release-designs-check.sh [--status]"
    exit 0
    ;;
  *)
    echo "release-designs-check: unknown argument: $1 (see --help)" >&2
    exit 2
    ;;
esac

DIR=release-designs
STATUS=0

# The complete release-day input: the flip patch is useless without the
# checklist, the fee notes, the tag message, and the landing copy the runbook
# walks through in order. The two .patch files are the executable forms of the
# .md proposals — release day runs `git apply` on them, in order (flip first;
# the fee patch's base is the tree the flip produces), so losing either one
# means re-deriving that pass by hand.
EXPECTED=(
  README.md
  v0.9.0-pretag-checklist.md
  v0.9.0-doc-flips.md
  v0.9.0-doc-flips.patch
  v0.9.0-fee-notes.md
  v0.9.0-fee-notes.patch
  v0.9.0-tag-message.txt
  v0.9.0-landing-card.md
)
for f in "${EXPECTED[@]}"; do
  if [ ! -f "$DIR/$f" ]; then
    echo "MISSING: $DIR/$f — the release-prep set must stay self-contained" >&2
    STATUS=1
  fi
done

# Artifacts that legitimately do not exist yet: the tag message is stripped
# into -final.txt at tag time, which is deliberately the LAST step. Anything
# else a tracked file points at must be present.
NOT_YET=(v0.9.0-tag-message-final.txt)
is_not_yet() {
  local n=$1 x
  for x in "${NOT_YET[@]}"; do [ "$n" = "$x" ] && return 0; done
  return 1
}

# Only <name>.(md|txt) tokens count, so prose globs (v0.9.0-*.md) and bare
# directory mentions do not trip the pointer check.
refs=$(git grep -hoE "$DIR/[A-Za-z0-9._-]+\.(md|txt)" -- . 2>/dev/null | sort -u || true)
for ref in $refs; do
  name=${ref#"$DIR/"}
  is_not_yet "$name" && continue
  if [ ! -e "$ref" ]; then
    echo "BROKEN POINTER: $ref is referenced by a tracked file but does not exist" >&2
    STATUS=1
  fi
done

if ((SHOW_STATUS == 1)); then
  present=0
  for f in "${EXPECTED[@]}"; do [ -f "$DIR/$f" ] && present=$((present + 1)); done
  echo "release-designs readiness — v0.9.0 release-prep set"
  echo "  drafts present: $present/${#EXPECTED[@]}"
  # Raw marker occurrences, NOT a worklist: the .md drafts also MENTION markers
  # in their own prose ("replace `<release>`…", "fill every `<<FILL:…>>`"), so
  # this count overstates what is left to type in. The worklists that do not
  # overstate live in release-tag-message.sh (the tag fields) and
  # release-day-rehearsal.sh (the applied artifacts) — use those to decide.
  echo "  raw marker occurrences (prose mentions included — expected until release day):"
  for f in \
    v0.9.0-pretag-checklist.md \
    v0.9.0-doc-flips.md \
    v0.9.0-fee-notes.md \
    v0.9.0-tag-message.txt \
    v0.9.0-landing-card.md; do
    [ -f "$DIR/$f" ] || continue
    n=$(grep -oE '<<[A-Z]' "$DIR/$f" | wc -l | tr -d ' ')
    printf '    %-30s %s\n' "$f" "$n"
  done
  # The registry declaration, NOT the "8453" in its doc comment — an entry is
  # present once the map literal stops being the empty `{}` form.
  reg_line=$(grep -E '^var KnownMailboxDeployments = ' internal/evm/mailboxdefaults.go 2>/dev/null || true)
  case "$reg_line" in
    *'{}'*) echo '  registry entry ("8453"): absent — the flip has not landed' ;;
    '') echo '  registry entry ("8453"): unknown — declaration not found' ;;
    *) echo '  registry entry ("8453"): PRESENT' ;;
  esac
  if [ -f "$DIR/v0.9.0-tag-message-final.txt" ]; then
    echo "  tag-message-final.txt: present (ready to sign)"
  else
    echo "  tag-message-final.txt: absent (created at tag time, last step)"
  fi
  echo "  real fill targets: bash scripts/release-tag-message.sh --fields, and the"
  echo "    list release-day-rehearsal.sh prints; readiness: bash scripts/release-readiness.sh"
  echo "  referee: go test ./internal/evm ./cmd/spore -count=1"
fi

exit "$STATUS"
