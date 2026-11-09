#!/usr/bin/env bash
# release-provenance-verify.sh — check a published release's SLSA provenance
# with slsa-verifier, and say plainly when that cannot be done here.
#
#   bash scripts/release-provenance-verify.sh [--tag vX.Y.Z] [--all]
#                                             [--artifacts DIR] [--refresh]
#                                             [--require] [--quiet]
#
# `multiple.intoto.jsonl` is a signed statement over every asset digest — but a
# signature nothing checks is one more file in a download. This runs the command
# docs/ONBOARDING.md hands users (slsa-verifier verify-artifact, --source-uri
# github.com/liqdmetal/spore, --source-tag from the notes) against the release
# docs/RELEASES.md calls current, so the claim is exercised by a machine instead
# of believed. The tag defaults to the newest `## vX.Y.Z` heading there — the
# same reference release-version-check.sh uses.
#
# Three things make it SKIP, each with its reason printed, because none of them
# can verify anything:
#   * slsa-verifier is not installed (the one-line install is printed too;
#     --require turns this into a failure for a machine that must have it),
#   * the tag is not published yet (notes are written before the tag; a push
#     before release day has nothing to check),
#   * GitHub cannot be reached for the assets.
# A verification that RUNS and fails is never a skip: it exits 1.
#
# Downloads are cached per tag under
# ${SPORE_PROVENANCE_CACHE:-$TMPDIR/spore-provenance}/<tag>, so the push after
# the first costs nothing; --refresh re-downloads. --artifacts DIR verifies a
# directory that already holds the assets and multiple.intoto.jsonl (a staging
# dir, or an offline machine) and never touches the network.
#
# One artifact is verified by default — spore-linux-amd64, the asset the docs'
# recipe names — because one success proves both the signature over the whole
# payload and that subject's digest. --all verifies all six.
#
# Exit codes: 0 verified, or skipped with the reason printed; 1 verification
# failed (or --require and it could not run); 2 cannot check (no repo, unusable
# artifact directory); 3 usage.
set -euo pipefail

SLUG="liqdmetal/spore"
DEFAULT_ASSETS="spore-linux-amd64"
ALL_ASSETS="spore-darwin-amd64 spore-darwin-arm64 spore-linux-amd64 spore-linux-arm64 spore-windows-amd64.exe spore-windows-arm64.exe"
PROVENANCE="multiple.intoto.jsonl"

usage() {
  cat <<'EOF'
usage: bash scripts/release-provenance-verify.sh [options]

  --tag vX.Y.Z      release to verify (default: newest docs/RELEASES.md heading)
  --all             verify all six assets (default: spore-linux-amd64)
  --artifacts DIR   verify assets already in DIR; no network, no cache
  --refresh         re-download a cached tag
  --require         treat "cannot run" as a failure instead of a skip
  --quiet           print nothing unless something failed or was skipped
  -h, --help        this text
EOF
}

TAG=""
ALL=0
ARTIFACTS=""
REFRESH=0
REQUIRE=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      shift
      TAG="${1:-}"
      [ -n "$TAG" ] || { echo "release-provenance: --tag needs a value" >&2; exit 3; }
      ;;
    --all) ALL=1 ;;
    --artifacts)
      shift
      ARTIFACTS="${1:-}"
      [ -n "$ARTIFACTS" ] || { echo "release-provenance: --artifacts needs a directory" >&2; exit 3; }
      ;;
    --refresh) REFRESH=1 ;;
    --require) REQUIRE=1 ;;
    --quiet) QUIET=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "release-provenance: unknown argument: $1 (see --help)" >&2
      exit 3
      ;;
  esac
  shift
done

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-provenance: not inside a git repository" >&2
  exit 2
}
cd "$top"

# tr -d '\r' everywhere: a checkout that still hands over CRLF would otherwise
# compare a tag with a trailing carriage return against GitHub's.
if [ -z "$TAG" ]; then
  [ -f docs/RELEASES.md ] || {
    echo "release-provenance: docs/RELEASES.md is missing — pass --tag" >&2
    exit 2
  }
  TAG=$(awk '/^## v[0-9]+\.[0-9]+\.[0-9]+/ { sub(/^## +/, ""); print $1; exit }' docs/RELEASES.md | tr -d '\r')
  [ -n "$TAG" ] || {
    echo "release-provenance: docs/RELEASES.md has no '## vX.Y.Z' heading — pass --tag" >&2
    exit 2
  }
fi

note() { [ "$QUIET" -eq 1 ] || echo "$@"; }

# skip REASON — the one exit path for "nothing was verified". --require is the
# caller saying a skipped check is not acceptable here (release day), so it
# fails instead.
skip() {
  if [ "$REQUIRE" -eq 1 ]; then
    echo "release-provenance: cannot verify $TAG — $1 (--require)" >&2
    exit 1
  fi
  echo "release-provenance: $TAG NOT verified — $1"
  echo "  skipped, so this run proves nothing about that release's provenance"
  exit 0
}

VERIFIER="${SLSA_VERIFIER:-}"
if [ -z "$VERIFIER" ]; then
  VERIFIER=$(command -v slsa-verifier 2>/dev/null || true)
fi
if [ -z "$VERIFIER" ]; then
  note "  install it with: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest"
  skip "slsa-verifier is not installed (or SLSA_VERIFIER does not point at it)"
fi

ASSETS="$DEFAULT_ASSETS"
if [ "$ALL" -eq 1 ]; then
  ASSETS="$ALL_ASSETS"
fi

# dir_of_assets — the directory to verify from, downloading when needed.
fetch_state=0   # 0 ok, 4 tag absent, 5 unreachable, 1 missing asset

dl() { # dl URL DEST — 0 ok, 4 not found, 5 anything else
  local code
  code=$(curl -sS -L -o "$2" -w '%{http_code}' "$1" 2>/dev/null) || code=000
  case "$code" in
    200) return 0 ;;
    404) return 4 ;;
    *) return 5 ;;
  esac
}

if [ -n "$ARTIFACTS" ]; then
  DIR="$ARTIFACTS"
  [ -d "$DIR" ] || {
    echo "release-provenance: no such directory: $DIR" >&2
    exit 2
  }
  missing=""
  for a in $ASSETS; do
    [ -f "$DIR/$a" ] || missing="$missing $a"
  done
  [ -f "$DIR/$PROVENANCE" ] || missing="$missing $PROVENANCE"
  if [ -n "$missing" ]; then
    echo "release-provenance: $DIR is missing:$missing" >&2
    exit 2
  fi
  note "release-provenance: verifying $TAG from $DIR (no network)"
else
  CACHE="${SPORE_PROVENANCE_CACHE:-${TMPDIR:-/tmp}/spore-provenance}"
  DIR="$CACHE/$TAG"
  need=0
  if [ "$REFRESH" -eq 1 ]; then
    need=1
  else
    [ -f "$DIR/$PROVENANCE" ] || need=1
    for a in $ASSETS; do
      [ -f "$DIR/$a" ] || need=1
    done
  fi

  if [ "$need" -eq 1 ]; then
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
      "https://api.github.com/repos/$SLUG/releases/tags/$TAG" 2>/dev/null) || code=000
    case "$code" in
      200) ;;
      404) skip "no published release for $TAG (the notes are written before the tag)" ;;
      *) skip "cannot reach GitHub for the $TAG assets (HTTP ${code:-000})" ;;
    esac

    mkdir -p "$DIR" || {
      echo "release-provenance: cannot create cache directory: $DIR" >&2
      exit 2
    }
    if ! dl "https://github.com/$SLUG/releases/download/$TAG/$PROVENANCE" "$DIR/$PROVENANCE"; then
      rm -f "$DIR/$PROVENANCE"
      skip "the $TAG release carries no $PROVENANCE (manual workflow-dispatch rebuilds skip the attestation)"
    fi
    for a in $ASSETS; do
      dl "https://github.com/$SLUG/releases/download/$TAG/$a" "$DIR/$a.part" || fetch_state=$?
      case "$fetch_state" in
        0)
          mv "$DIR/$a.part" "$DIR/$a"
          fetch_state=0
          ;;
        4)
          rm -f "$DIR/$a.part"
          echo "FAIL: the $TAG release has no asset named $a" >&2
          exit 1
          ;;
        5)
          rm -f "$DIR/$a.part"
          skip "cannot download $a from the $TAG release"
          ;;
      esac
    done
  else
    note "release-provenance: verifying $TAG from cache ($DIR)"
  fi
fi

# `slsa-verifier version` opens with an ASCII banner; take the version line, not
# the logo, so the gate's own log names the tool that did the checking.
ver=""
ver=$("$VERIFIER" version 2>/dev/null | tr -d '\r' | grep -E '^(Version|GitVersion|Build):' | head -1 || true)
note "release-provenance: ${ver:-slsa-verifier} verifying $TAG ($SLUG)"

log=$(mktemp) || exit 2
trap 'rm -f "$log"' EXIT

count=0
for a in $ASSETS; do
  if "$VERIFIER" verify-artifact "$DIR/$a" \
      --provenance-path "$DIR/$PROVENANCE" \
      --source-uri "github.com/$SLUG" --source-tag "$TAG" >"$log" 2>&1; then
    count=$((count + 1))
    note "  ok  $a"
  else
    echo "FAIL: $a does not verify against the $TAG provenance:" >&2
    sed 's/^/    /' "$log" >&2
    exit 1
  fi
done

echo "release-provenance: verified $count artifact(s) against $TAG provenance ($SLUG)"
