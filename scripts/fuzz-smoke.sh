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
#   usage: scripts/fuzz-smoke.sh [-t SECONDS] [--check] [--deep]
#     -t SECONDS  fuzz time per target (default 5; the retired CI matrix used 15)
#     --check     verify every listed target exists in the source, then stop
#     --deep      release pre-flight: 60s per target (about nine minutes) instead
#                 of the few seconds a push gets. Never run by gates.sh or
#                 lefthook — invoke it by hand before a release.
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
# Ctrl-C is the one case that writes into the repo WITHOUT a failure: Go saves
# the input it was executing when it was interrupted, and that input passes on
# replay (verified). `git status` is how you tell them apart — commit what a
# red run leaves, discard what an interrupt leaves. --deep, minutes long, is
# the run people interrupt.
#
# Exit codes: 0 every target ran clean, 1 a target crashed, 2 usage error.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEFAULT_FUZZTIME=5
FUZZTIME=""
CHECK=0
DEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t)
      [ $# -ge 2 ] || { echo "fuzz-smoke: -t needs SECONDS" >&2; exit 2; }
      FUZZTIME="$2"
      shift 2
      ;;
    --deep)
      DEEP=1
      DEFAULT_FUZZTIME=60
      shift
      ;;
    --check) CHECK=1; shift ;;
    -h | --help)
      echo "usage: scripts/fuzz-smoke.sh [-t SECONDS] [--check] [--deep]"
      echo "  -t SECONDS  fuzz time per target (default 5; --deep makes it 60)"
      echo "  --check     verify the target list resolves in the source, then stop"
      echo "  --deep      release pre-flight: 60s per target (~9 minutes), never run"
      echo "              by the pre-push gate"
      exit 0
      ;;
    *)
      echo "fuzz-smoke: unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
done

# -t wins over --deep's preset; --deep's preset wins over the smoke default.
[ -n "$FUZZTIME" ] || FUZZTIME="$DEFAULT_FUZZTIME"

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
#
# Sweep scratch dirs an interrupted run left behind. Only ones over an hour
# old: even a --deep run finishes in about nine minutes, so a newer directory
# may belong to a run still in progress and is left alone.
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'spore-fuzz-smoke.*' -mmin +60 \
  -exec rm -rf {} + 2>/dev/null || true

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/spore-fuzz-smoke.XXXXXX")"
cleanup() {
  # A fuzz worker killed mid-iteration (Ctrl-C, or this script under `timeout`)
  # keeps its temp dir busy for a moment: retry once after a short settle, so
  # an interrupted run — likelier for --deep than for the smoke — still cleans
  # up after itself instead of spraying rm errors and leaving the directory.
  rm -rf "$SCRATCH" 2>/dev/null && return 0
  sleep 1
  rm -rf "$SCRATCH" 2>/dev/null || true
}
trap cleanup EXIT
export TMPDIR="$SCRATCH" TEMP="$SCRATCH" TMP="$SCRATCH"

if [ "$DEEP" -eq 1 ]; then
  echo "fuzz-smoke: DEEP pre-flight — ${#TARGETS[@]} target(s) at ${FUZZTIME}s each, about $(( ${#TARGETS[@]} * FUZZTIME / 60 )) minute(s). The pre-push gate runs this script without --deep."
fi

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

label="FUZZ SMOKE GREEN"
[ "$DEEP" -eq 1 ] && label="FUZZ DEEP GREEN"
echo "$label — $n target(s), ${FUZZTIME}s each (wirefuzz + ratchetwire)"
