#!/bin/bash -eu
# Verify that every commit hash cited by the docs listed in a refs manifest
# resolves to a commit in this repository's history.
#
#   usage: verify_doc_refs.sh [manifest]     (default: docs/refs.yml)
#
# Manifest format (YAML, a list of repo-root-relative doc paths):
#
#   # comment lines and blank lines are ignored
#   docs:
#     - path: AUDIT-E2.md
#
# For each listed doc, the extraction rule is: backtick-quoted 7..40-char
# lowercase hex strings (`25206a2`). A line containing `no-verify-hash` is
# excluded, so illustrative/non-commit hex (a hash-shaped example, a key ID)
# can be marked deliberately. Cross-repo pins are documented with the marker
# and enforced where they live (the owning repo's doc-refs job, a Dockerfile
# `git checkout`, ...).
#
# A cited hash must resolve exactly: typos AND ambiguous too-short prefixes
# are failures (a citation you have to disambiguate is a doc bug). A listed
# doc that contains zero citations passes with a WARN — a drift signal worth
# a look, not a failure.
#
# This file is part of the doc-refs composite action and is vendored verbatim
# into every repository that uses it — see README.md in this directory for
# the contract and the vendoring rules.

set -o pipefail

manifest_arg="${1:-docs/refs.yml}"

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "verify-doc-refs: not inside a git repository" >&2
  exit 1
}

if [ -f "$manifest_arg" ]; then
  manifest=$manifest_arg
elif [ -f "$top/$manifest_arg" ]; then
  manifest=$top/$manifest_arg
else
  echo "verify-doc-refs: no such manifest: $manifest_arg" >&2
  exit 1
fi

# Extract doc paths: lines like "  - path: AUDIT-E2.md" (values unquoted by
# convention; surrounding double/single quotes are stripped defensively).
docs=$(grep -vE '^[[:space:]]*#' "$manifest" \
  | sed -n 's/^[[:space:]]*-[[:space:]]*path:[[:space:]]*//p' \
  | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")

if [ -z "$docs" ]; then
  echo "verify-doc-refs: manifest lists no docs: $manifest" >&2
  exit 1
fi

cd "$top"
status=0
for doc in $docs; do
  if [ ! -f "$doc" ]; then
    echo "MISSING DOC: $doc is listed in $manifest but does not exist" >&2
    status=1
    continue
  fi

  refs=$(grep -v 'no-verify-hash' "$doc" | grep -oE '`[0-9a-f]{7,40}`' | tr -d '`' | sort -u || true)

  if [ -z "$refs" ]; then
    echo "WARN: no commit references found in $doc (nothing to verify)"
    continue
  fi

  for ref in $refs; do
    # --verify fails on typos AND on ambiguous prefixes (a too-short ref that
    # names several objects is a doc bug: lengthen the hash).
    if out=$(git rev-parse --verify "${ref}^{commit}" 2>&1); then
      echo "OK: $doc: $ref -> $out"
    else
      echo "MISSING: $doc: $ref does not resolve to a commit in this repository" >&2
      if grep -q 'ambiguous' <<<"$out"; then
        echo "HINT: $ref is ambiguous — lengthen the hash; a citation that needs disambiguation is a doc bug" >&2
      fi
      status=1
    fi
  done
done

exit "$status"
