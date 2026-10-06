#!/usr/bin/env bash
# release-readiness.sh — the machine-checkable half of "am I ready to tag?".
#
# The pre-tag checklist (release-designs/v0.9.0-pretag-checklist.md) is seven
# sections of checkboxes, and most of them need the real world: a funded key, a
# deployment, a two-party proof, a signed tag. This is the other half — every
# question a machine can answer, answered in one command, with the outstanding
# items NAMED rather than left for a reader to reconstruct from six tools.
#
# It composes the existing checks rather than re-deriving them, so it cannot
# disagree with them: release-designs-check (integrity), release-tag-message
# (the tag body), release-placeholders (markers that must not ship), the
# registry's own state, and release-day-rehearsal --check (do both frozen
# passes still land, in order).
#
#   bash scripts/release-readiness.sh          # report; exit 1 while blocked
#   bash scripts/release-readiness.sh --quiet  # exit status only
#
# Exit codes: 0 ready to tag, 1 not ready (the report names each blocker), 2
# cannot check, 3 usage.
#
# This is expected to exit 1 until release day. That is the point: a green run
# means every machine-decidable precondition of the tag holds, so what remains
# is the deployment itself and the checklist's human steps.
set -uo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-readiness: not inside a git repository" >&2
  exit 2
}
cd "$top" || exit 2

QUIET=0
case "${1:-}" in
  "") : ;;
  --quiet) QUIET=1 ;;
  -h | --help)
    echo "usage: bash scripts/release-readiness.sh [--quiet]"
    exit 0
    ;;
  *)
    echo "release-readiness: unknown argument: $1 (see --help)" >&2
    exit 3
    ;;
esac

blocked=0
report() { # report STATUS LABEL [DETAIL]
  [ "$QUIET" -eq 1 ] && return 0
  printf '  %-7s %s\n' "$1" "$2"
  [ -n "${3:-}" ] && printf '          -> %s\n' "$3"
  return 0
}
ok() { report ok "$1"; }
block() {
  blocked=$((blocked + 1))
  report BLOCKED "$1" "${2:-}"
}

for tool in scripts/release-designs-check.sh scripts/release-tag-message.sh \
  scripts/release-placeholders.sh scripts/release-day-rehearsal.sh; do
  [ -f "$tool" ] || {
    echo "release-readiness: $tool is missing — cannot check" >&2
    exit 2
  }
done

[ "$QUIET" -eq 0 ] && echo "== release readiness — Spore v0.9.0 (the machine-checkable half) ==" && echo

# 1. the release-day input is complete and every pointer resolves
if bash scripts/release-designs-check.sh >/dev/null 2>&1; then
  ok "release-designs set present; every in-repo pointer resolves"
else
  block "the release-designs set is incomplete or a pointer is broken" \
    "bash scripts/release-designs-check.sh"
fi

# 2. the tag draft still has the shape the runbook strips
if bash scripts/release-tag-message.sh >/dev/null 2>&1; then
  ok "tag draft structure (strip marker once, body present, no stray markers)"
else
  block "the tag draft's structure is broken — the strip would cut the wrong place" \
    "bash scripts/release-tag-message.sh"
fi

# 3. every tag field is filled from the receipt
tagfields=$(bash scripts/release-tag-message.sh --fields 2>/dev/null || echo '?')
if [ "$tagfields" = "0" ]; then
  ok "every tag-message field is filled"
elif [ "$tagfields" = "?" ]; then
  block "cannot read the tag draft's field count"
else
  block "$tagfields tag-message field(s) still unfilled" \
    "fill release-designs/v0.9.0-tag-message.txt from the §3 receipt, then: bash scripts/release-tag-message.sh --write"
fi

# 4. nothing on the release surfaces is a rehearsal value
if bash scripts/release-placeholders.sh --quiet >/dev/null 2>&1; then
  ok "no rehearsal marker on the release surfaces"
else
  n=$(bash scripts/release-placeholders.sh 2>/dev/null | sed -n 's/^release-placeholders: \([0-9]*\) marker.*/\1/p' || true)
  block "${n:-some} marker line(s) still on the release surfaces" \
    "bash scripts/release-placeholders.sh"
fi

# 5. the shipped default is backed by a registry entry
reg_line=$(grep -E '^var KnownMailboxDeployments = ' internal/evm/mailboxdefaults.go 2>/dev/null || true)
case "$reg_line" in
  *'{}'*) block "the mailbox registry is still empty — the flip has not landed" ;;
  '') block "the mailbox registry declaration was not found in internal/evm/mailboxdefaults.go" ;;
  *) ok "the mailbox registry carries an entry" ;;
esac

# 6. both frozen passes still land, in the order release day applies them
if bash scripts/release-day-rehearsal.sh --check >/dev/null 2>&1; then
  ok "both frozen passes still apply to HEAD, flip before fees"
else
  block "a frozen pass no longer applies (the docs moved under it)" \
    "bash scripts/release-day-rehearsal.sh --check"
fi

# 7. the tag is still free to cut
if [ -z "$(git tag -l 'v0.9.0' 2>/dev/null)" ]; then
  ok "no local v0.9.0 tag yet"
else
  block "a local v0.9.0 tag already exists"
fi

# informational: a local comparison only, so it never blocks
if [ "$QUIET" -eq 0 ]; then
  ahead=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo '?')
  case "$ahead" in
    0) report info "HEAD is level with the local origin/main (not a fetch)" ;;
    '?') report info "cannot compare with origin/main" ;;
    *) report info "$ahead local commit(s) not on the local origin/main" ;;
  esac
fi

if [ "$QUIET" -eq 1 ]; then
  [ "$blocked" -eq 0 ] || exit 1
  exit 0
fi

echo
if [ "$blocked" -eq 0 ]; then
  echo "READY TO TAG (machine-checkable half) — cut it last, after CI is green on the pushed commit:"
  echo "  git tag -s v0.9.0 -F release-designs/v0.9.0-tag-message-final.txt && git verify-tag v0.9.0"
else
  echo "NOT READY TO TAG — $blocked blocker(s) above."
fi

cat <<'HUMAN'

Not machine-checkable, and not claimed by the run above
(release-designs/v0.9.0-pretag-checklist.md):
  s0  chain decided; Sepolia rehearsal run; Base deployment + two-party proof; both estimates saved
  s1  tree clean; no unrelated work staged; full gates green; CI green on the exact SHA
  s4  `0.8.0` references swept; `git log v0.8.0..HEAD --oneline` reviewed against the tag bullets
  s5  tag body reviewed against the shipped diff, then signed (release-tag-message.sh --print)
  s6  push main first; push v0.9.0 only after CI is green on main
  s7  verify the tag signature, the release assets, one checksum, and provenance
HUMAN

[ "$blocked" -eq 0 ] || exit 1
exit 0
