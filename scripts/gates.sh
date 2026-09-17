#!/bin/bash -eu
# Run the full pre-push gate suite locally: everything CI checks, without CI.
#
#   usage: scripts/gates.sh [--quick] [spore-checkout] [spore-peer-checkout]
#
# Both arguments are optional. The spore checkout defaults to the repo this
# script lives in. The spore-peer checkout defaults to SPORE_PEER_DIR, then a
# sibling `spore-peer` directory, then `_review_tmp/spore-peer`; if none
# exists the spore-peer gates are skipped with a loud note. (The layout
# assumption: a checkout root containing the `spore` repo and — optionally —
# a `spore-peer` checkout either as a sibling or under `_review_tmp/`.)
#
# --quick skips the spore-peer (Rust) gates and the -race + cross-binary
# interop run for fast inner-loop feedback; everything else (gofmt/
# goimports, build+vet+test, doc-refs) still runs. It complements the full
# suite — a push is still gated by the full run, never by --quick.
#
# Every gate prints its duration when it finishes, and a slowest-first
# timing table prints before the final banner — slow gates are visible at
# a glance, not buried in total runtime.
#
# The -race gate needs cgo enabled (the default on most dev boxes). Exit code
# is 0 only if every gate that ran passed; skips are printed, not hidden.
#
# NOTE: the flags are set explicitly below rather than trusted to the
# shebang — shebang flags are silently dropped when the script is invoked as
# `bash scripts/gates.sh`, and an -e-less gate script would report success
# after a failed gate.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

QUICK=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

SPORE_DIR="${ARGS[0]:-$SELF_DIR/..}"
SPORE_DIR="$(cd "$SPORE_DIR" && pwd)"

if [ "$QUICK" -eq 1 ]; then PEER_DIR=""   # quick mode never enters the Rust gates
elif [ -n "${ARGS[1]:-}" ]; then PEER_DIR="${ARGS[1]}"
elif [ -n "${SPORE_PEER_DIR:-}" ]; then PEER_DIR="$SPORE_PEER_DIR"
elif [ -d "$SPORE_DIR/../spore-peer" ]; then PEER_DIR="$SPORE_DIR/../spore-peer"
elif [ -d "$SPORE_DIR/../_review_tmp/spore-peer" ]; then PEER_DIR="$SPORE_DIR/../_review_tmp/spore-peer"
else PEER_DIR=""; fi

# ---- timing helpers --------------------------------------------------------
# Millisecond clock with a fallback for `date` implementations that lack %N
# (they emit a literal 'N', which fails the all-digits test below).
now_ms() {
  t=$(date +%s%N 2>/dev/null)
  case "$t" in
    ''|*[!0-9]*) echo $(( $(date +%s) * 1000 )) ;;
    *) echo "${t:0:13}" ;;
  esac
}

fmt_ms() {
  ms=$1
  if [ "$ms" -ge 60000 ]; then
    printf '%dm%ds' $(( ms / 60000 )) $(( (ms % 60000) / 1000 ))
  elif [ "$ms" -ge 1000 ]; then
    printf '%d.%ds' $(( ms / 1000 )) $(( (ms % 1000) / 100 ))
  else
    printf '%dms' "$ms"
  fi
}

TIMINGS=""

# run_gate LABEL CMD... — run CMD, print its duration, remember it for the
# end-of-run table, and exit with CMD's status on failure (so a failing gate
# still reports how long it ran before it died).
run_gate() {
  label=$1; shift
  printf -- '-- %s ...\n' "$label"
  t0=$(now_ms)
  rc=0
  "$@" || rc=$?
  dt=$(( $(now_ms) - t0 ))
  TIMINGS="${TIMINGS}${dt} ${label}
"
  printf -- '-- %s — %s\n' "$label" "$(fmt_ms "$dt")"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL $label (exit $rc)"
    exit "$rc"
  fi
}

check_gofmt() {
  UNFMT="$(gofmt -l .)"
  if [ -n "$UNFMT" ]; then
    echo "unformatted files:"
    echo "$UNFMT"
    return 1
  fi
}

check_goimports() {
  UNIMP="$(goimports -l .)"
  if [ -n "$UNIMP" ]; then
    echo "files needing import fixes:"
    echo "$UNIMP"
    return 1
  fi
}

RACE_PKGS="./internal/store ./internal/peerstore"
check_race() {
  if [ -n "$PEER_BIN" ]; then
    SPORE_PEER_BIN="$PEER_BIN" go test -race -count=1 $RACE_PKGS
  else
    go test -race -count=1 $RACE_PKGS
  fi
}

# ---- gates -----------------------------------------------------------------
echo "== pre-push gates =="
echo "spore: $SPORE_DIR"

cd "$SPORE_DIR"

run_gate gofmt check_gofmt

if command -v goimports >/dev/null 2>&1; then
  run_gate goimports check_goimports
else
  echo "goimports: not installed — skipped (gofmt covers formatting)"
fi

run_gate 'go build ./...' go build ./...

run_gate 'go vet ./...' go vet ./...

run_gate 'go test ./...' go test ./...

PEER_BIN=""
if [ "$QUICK" -eq 1 ]; then
  echo
  echo "== quick mode: spore-peer gates skipped (--quick) =="
elif [ -n "$PEER_DIR" ] && [ -d "$PEER_DIR" ]; then
  PEER_DIR="$(cd "$PEER_DIR" && pwd)"
  cd "$PEER_DIR"
  echo
  echo "== spore-peer gates ($PEER_DIR) =="

  run_gate 'cargo build' cargo build --locked
  run_gate 'cargo fmt --check' cargo fmt --check
  run_gate 'cargo clippy -D warnings' cargo clippy --locked --all-targets -- -D warnings
  run_gate 'cargo test' cargo test --locked

  if [ -x target/debug/spore-peer ]; then
    PEER_BIN="$PEER_DIR/target/debug/spore-peer"
  fi
else
  echo
  echo "== spore-peer: checkout not found (${PEER_DIR:-none}) — spore-peer gates skipped =="
fi

cd "$SPORE_DIR"

if [ "$QUICK" -eq 1 ]; then
  echo
  echo "== quick mode: -race + cross-binary interop skipped (--quick) =="
elif [ -n "$PEER_BIN" ]; then
  echo
  echo "== go test -race + cross-binary interop (SPORE_PEER_BIN=$PEER_BIN) =="
  run_gate '-race + cross-binary interop' check_race
else
  echo
  echo "== go test -race (no spore-peer binary — interop tests will skip) =="
  run_gate '-race' check_race
fi

echo
echo "== doc-refs checker =="
run_gate 'doc-refs checker' bash .github/actions/doc-refs/verify_doc_refs.sh

# ---- summary ---------------------------------------------------------------
if [ -n "$TIMINGS" ]; then
  echo
  echo "== gate timings (slowest first) =="
  printf '%s' "$TIMINGS" | sort -rn | while IFS=' ' read -r ms label; do
    printf '  %8s  %s\n' "$(fmt_ms "$ms")" "$label"
  done
fi

MODE=""
if [ "$QUICK" -eq 1 ]; then MODE=" (quick)"; fi

echo
echo "ALL GATES GREEN${MODE} — spore@$(git -C "$SPORE_DIR" rev-parse --short HEAD)"
if [ -n "$PEER_BIN" ]; then
  echo "              spore-peer@$(git -C "$PEER_DIR" rev-parse --short HEAD)"
fi
