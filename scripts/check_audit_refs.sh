#!/bin/bash -eu
# Verify every commit hash referenced in an audit doc resolves in git history.
#
# The audit docs (AUDIT-E2.md, ...) pin findings to the commits that fixed
# them. Rebases, typos, and wishful citations silently rot those pins; this
# check makes the rot a CI failure instead of a dead reference.
#
#   usage: check_audit_refs.sh [doc]        (default: AUDIT-E2.md)
#
# Extraction rule: backtick-quoted 7..40-char lowercase hex strings
# (`25206a2`). A line containing `no-verify-hash` is excluded, so
# illustrative/non-commit hex (a hash-shaped example, a key ID) can be
# marked deliberately.
#
# Requires full history: run with a fetch-depth: 0 checkout in CI.

doc="${1:-AUDIT-E2.md}"
if [ ! -f "$doc" ]; then
  echo "check-audit-refs: no such doc: $doc" >&2
  exit 1
fi

refs=$(grep -v 'no-verify-hash' "$doc" | grep -oE '`[0-9a-f]{7,40}`' | tr -d '`' | sort -u || true)

if [ -z "$refs" ]; then
  echo "check-audit-refs: no commit references found in $doc (nothing to verify)"
  exit 0
fi

status=0
for ref in $refs; do
  # --verify fails on typos AND on ambiguous prefixes (a too-short ref that
  # names several objects is a doc bug: lengthen the hash).
  if full=$(git rev-parse --verify --quiet "${ref}^{commit}"); then
    echo "OK: $ref -> $full"
  else
    echo "MISSING: $ref does not resolve to a commit in this repository" >&2
    status=1
  fi
done

exit "$status"
