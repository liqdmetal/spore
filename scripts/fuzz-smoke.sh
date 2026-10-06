#!/usr/bin/env bash
# scripts/fuzz-smoke.sh — the local fuzz-smoke gate.
#
# The repository's GitHub Actions workflows are gone, and the ClusterFuzzLite
# pipelines that ran the fuzz targets went with them. The targets still guard
# the byte-level wire parsers, so this script is their runner now: every
# wirefuzz and ratchetwire target gets a few seconds of real fuzzing so a
# parser regression crashes a pre-push run instead of shipping. scripts/gates.sh
# invokes it, and lefthook runs gates.sh on every push.
#
#   usage: scripts/fuzz-smoke.sh [-t SECONDS] [--check]
#     -t SECONDS  fuzz time per target (default 5; the retired CI matrix used 15)
#     --check     verify every listed target exists in the source, then stop
#
# Coverage: the four standalone SPR2 parser targets in internal/wirefuzz and
# the five SecureWire seam targets in internal/ratchetwire — the same nine the
# retired CI matrix ran for those two packages. internal/continuity and
# internal/anchor also carry fuzz targets that only the old matrix ran; add
# them to TARGETS below to fold them in.
#
# A crash writes its input to that target's testdata/fuzz/<Target>/ directory,
# so a red run leaves a committed reproducer behind, not a lost seed.
#
# Exit codes: 0 every target ran clean, 1 a target crashed, 2 usage error.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FUZZTIME=5
CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t)
      [ $# -ge 2 ] || { echo "fuzz-smoke: -t needs SECONDS" >&2; exit 2; }
      FUZZTIME="$2"
      shift 2
      ;;
    --check) CHECK=1; shift ;;
    -h | --help)
      echo "usage: scripts/fuzz-smoke.sh [-t SECONDS] [--check]"
      exit 0
      ;;
    *)
      echo "fuzz-smoke: unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
done

case "$FUZZTIME" in
  '' | *[!0-9]*)
    echo "fuzz-smoke: -t must be a whole number of seconds, got '$FUZZTIME'" >&2
    exit 2
    ;;
esac
[ "$FUZZTIME" -ge 1 ] || { echo "fuzz-smoke: -t must be at least 1" >&2; exit 2; }

# The single source of truth for what this gate runs. TestFuzzSmokeListsEveryTarget
# (internal/wirefuzz) compares it against the Fuzz functions the two packages
# actually declare, so adding, renaming, or dropping one fails `go test` until
# this list is updated to match.
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

if [ "$CHECK" -eq 1 ]; then
  missing=0
  for entry in "${TARGETS[@]}"; do
    pkg="${entry%%:*}"
    target="${entry##*:}"
    if ! grep -rqE "^func ${target}\(" "$pkg"; then
      echo "fuzz-smoke: $target is listed but not declared in $pkg" >&2
      missing=$((missing + 1))
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "fuzz-smoke: $missing listed target(s) missing from the source" >&2
    exit 1
  fi
  echo "fuzz-smoke: target list ok — ${#TARGETS[@]} target(s) resolve in the source"
  exit 0
fi

command -v go >/dev/null 2>&1 || {
  echo "fuzz-smoke: go not found on PATH" >&2
  exit 1
}

# The targets hand f.TempDir() a fresh directory per iteration; when a fuzz
# worker is killed at fuzztime expiry its cleanup is skipped, so a run leaves
# dozens of orphaned directories behind (observed: 123 across two runs). Point
# Go's temp dir at a scratch directory this script removes, so the gate leaves
# nothing outside the repo or in it.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/spore-fuzz-smoke.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
export TMPDIR="$SCRATCH" TEMP="$SCRATCH" TMP="$SCRATCH"

n=0
for entry in "${TARGETS[@]}"; do
  pkg="${entry%%:*}"
  target="${entry##*:}"
  printf -- '-- %s (%s, %ss)\n' "$target" "$pkg" "$FUZZTIME"
  if ! out="$(go test "$pkg" -run='^$' -fuzz="^${target}\$" -fuzztime="${FUZZTIME}s" 2>&1)"; then
    printf '%s\n' "$out" | tail -n 30 >&2
    echo >&2
    echo "FUZZ SMOKE FAILED: $target ($pkg) — the crashing input is committed under $pkg/testdata/fuzz/$target/" >&2
    exit 1
  fi
  # `go test -fuzz=PATTERN` exits 0 with a warning when PATTERN matches no
  # fuzz target, so a renamed or mistyped entry would otherwise pass this gate
  # having fuzzed nothing. (Found by pointing a TARGETS entry at the wrong
  # package: exit 0, no target run.)
  if printf '%s' "$out" | grep -q 'no fuzz tests to fuzz'; then
    printf '%s\n' "$out" | tail -n 10 >&2
    echo >&2
    echo "FUZZ SMOKE FAILED: $target ($pkg) never ran — go test matched no fuzz target by that name" >&2
    exit 1
  fi
  n=$((n + 1))
done

echo "FUZZ SMOKE GREEN — $n target(s), ${FUZZTIME}s each (wirefuzz + ratchetwire)"
