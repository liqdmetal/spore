#!/usr/bin/env bash
# scripts/fuzz-corpus.sh — keep the fuzz corpus compounding across runs.
#
# Go's fuzzer keeps every input it finds interesting in
# $GOCACHE/fuzz/<import path>/<Target>/. That compounds on one machine, but it
# dies with the build cache (`go clean -cache`, a fresh clone, a new box) and is
# invisible to review — and the ClusterFuzzLite `cfl-corpus` branch that used to
# publish it went away with the workflows. This script is the durable store: it
# copies the cache's corpus into each package's testdata/fuzz/<Target>/, which
# Go loads as seed corpus on the next `go test` or `go test -fuzz`. A saved
# corpus therefore compounds, survives a cache wipe, and travels with the clone.
#
#   usage: scripts/fuzz-corpus.sh [--status] [--save] [-q]
#     --status  (default) per-target counts — saved, cached, and new; read-only
#     --save    copy every cached entry the repo does not have yet into
#               testdata/fuzz/<Target>/ (grow-only), then print what it added
#     -q        print nothing unless something is new (used by the runners)
#
# Entries are named after the sha256 of their contents, so "new" is exact: a
# file of that name in the repo is the same input. A save never rewrites or
# deletes an entry, and never touches a crash reproducer Go wrote there.
#
# `go test` replays these as subtests, so the corpus is not free forever — but
# at a few hundred inputs the cost is in the noise (measured: 521 files vs 27
# moved `go test ./internal/wirefuzz ./internal/ratchetwire` by <0.2s).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SAVE=0
QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --status) SAVE=0; shift ;;
    --save) SAVE=1; shift ;;
    -q | --quiet) QUIET=1; shift ;;
    -h | --help)
      echo "usage: scripts/fuzz-corpus.sh [--status] [--save] [-q]"
      echo "  --status  list saved/cached/new counts per target (default)"
      echo "  --save    copy new cached inputs into testdata/fuzz/<Target>/"
      echo "  -q        print nothing unless something is new"
      exit 0
      ;;
    *)
      echo "fuzz-corpus: unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
done

# The same nine targets scripts/fuzz-smoke.sh runs; TestFuzzSmokeListsEveryTarget
# (internal/wirefuzz) keeps BOTH scripts' lists in step with the code.
TARGETS=(
  "./internal/wirefuzz:FuzzFrameParse"
  "./internal/wirefuzz:FuzzHandshakeUnmarshal"
  "./internal/wirefuzz:FuzzMessageUnmarshal"
  "./internal/wirefuzz:FuzzFabricRPC2Frame"
  "./internal/ratchetwire:FuzzWireRoundtrip"
  "./internal/ratchetwire:FuzzWirePinEnforcement"
  "./internal/ratchetwire:FuzzWireMalformedFrames"
  "./internal/ratchetwire:FuzzDurableEndpointRoundtrip"
  "./internal/ratchetwire:FuzzEndpointFullRoundTrip"
)

command -v go >/dev/null 2>&1 || {
  echo "fuzz-corpus: go not found on PATH" >&2
  exit 1
}
MOD="$(awk '$1 == "module" { print $2 }' go.mod)"
CACHE="$(go env GOCACHE)/fuzz/$MOD"

rows=""
new_total=0
added_total=0
saved_total=0
for entry in "${TARGETS[@]}"; do
  pkg="${entry%%:*}"
  target="${entry##*:}"
  dest="$pkg/testdata/fuzz/$target"
  src="$CACHE/$pkg/$target"

  saved=0
  [ -d "$dest" ] && saved=$(find "$dest" -maxdepth 1 -type f | wc -l)
  cached=0
  [ -d "$src" ] && cached=$(find "$src" -maxdepth 1 -type f | wc -l)

  new=0
  added=0
  if [ -d "$src" ]; then
    while IFS= read -r f; do
      name="$(basename "$f")"
      [ -e "$dest/$name" ] && continue
      new=$((new + 1))
      if [ "$SAVE" -eq 1 ]; then
        mkdir -p "$dest"
        cp "$f" "$dest/$name"
        added=$((added + 1))
        added_total=$((added_total + 1))
        saved=$((saved + 1))
      fi
    done < <(find "$src" -maxdepth 1 -type f)
  fi

  new_total=$((new_total + new))
  saved_total=$((saved_total + saved))
  # A save reports what it copied, not what is still missing — after copying
  # the entry, "new" would be a contradiction.
  if [ "$SAVE" -eq 1 ]; then
    cols="$(printf 'saved=%-4s cached=%-4s added=%s' "$saved" "$cached" "$added")"
  else
    cols="$(printf 'saved=%-4s cached=%-4s new=%s' "$saved" "$cached" "$new")"
  fi
  rows="${rows}$(printf '  %-32s %s\n' "$target" "$cols")"$'\n'
done

if [ "$QUIET" -eq 1 ]; then
  # Called by a fuzz run: say something only when there is something to keep.
  if [ "$new_total" -gt 0 ]; then
    echo "fuzz-corpus: $new_total input(s) the fuzz cache gained are not in the repo — run scripts/fuzz-corpus.sh --save to keep them"
  fi
  exit 0
fi

printf '== fuzz corpus (repo testdata/fuzz vs the build cache)\n%s' "$rows"
if [ "$SAVE" -eq 1 ]; then
  echo "saved $added_total new input(s) across ${#TARGETS[@]} target(s); corpus now $saved_total file(s)"
else
  echo "$new_total new input(s) available; run scripts/fuzz-corpus.sh --save to preserve them"
fi
