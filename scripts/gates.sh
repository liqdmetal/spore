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
# Timings are also appended to a CSV so gate latency can be tracked over
# time: one row per gate per run (including failed gates), long format:
#
#   timestamp,mode,spore_sha,peer_sha,gate,duration_ms,status
#
# Default location: .gate-timings.csv in the spore repo root (gitignored).
# Override with GATE_TIMINGS_CSV=<path>, or disable with GATE_TIMINGS_CSV=off.
#
# The summary also flags any gate slower than GATE_SLOW_RATIO (default 2)
# times its historical median from prior rows of the CSV — this machine's
# own baseline, never the run being judged. Informational only: a slow-but-
# green run still exits 0. A gate needs >= 3 prior samples before its
# median is trusted; gate labels are compared across quick and full modes.
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
MODE_CSV=full
[ "$QUICK" -eq 1 ] && MODE_CSV=quick

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

# ---- CSV latency log -------------------------------------------------------
# Long format, one row per gate per run, appended as each gate finishes (so
# even a run that fails mid-way records the gates that completed). Raw
# integer duration_ms keeps the file analysis-friendly.
if [ "${GATE_TIMINGS_CSV:-}" = "off" ] || [ "${GATE_TIMINGS_CSV:-}" = "0" ]; then
  CSV_PATH=""
elif [ -n "${GATE_TIMINGS_CSV:-}" ]; then
  CSV_PATH="$GATE_TIMINGS_CSV"
else
  CSV_PATH="$SPORE_DIR/.gate-timings.csv"
fi
GATE_SLOW_RATIO="${GATE_SLOW_RATIO:-2.0}"

csv_init() {
  [ -n "$CSV_PATH" ] || return 0
  # Header when the file is missing OR empty (a zero-byte file is not a log).
  [ -s "$CSV_PATH" ] || printf 'timestamp,mode,spore_sha,peer_sha,gate,duration_ms,status\n' > "$CSV_PATH"
}

csv_row() {  # csv_row GATE DURATION_MS STATUS
  [ -n "$CSV_PATH" ] || return 0
  printf '%s,%s,%s,%s,"%s",%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MODE_CSV" "${SPORE_SHA:--}" "${PEER_SHA:--}" \
    "$1" "$2" "$3" >> "$CSV_PATH"
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
    csv_row "$label" "$dt" fail
    exit "$rc"
  fi
  csv_row "$label" "$dt" ok
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

# cmd/spore is included for the F2 cross-binary fabric test
# (TestFabricSubscribeCrossBinary): real Rust relay + real `spore fabric
# subscribe` binary; it self-skips when SPORE_PEER_BIN is absent, so the
# plain -race pass on a machine without the spore-peer checkout stays green.
RACE_PKGS="./internal/store ./internal/peerstore ./cmd/spore"
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

SPORE_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo -)"
csv_init
# Snapshot of the log BEFORE this run appends anything: the slow-gate check
# must judge this run against history, not against itself.
PRE_ROWS=0
if [ -n "$CSV_PATH" ] && [ -f "$CSV_PATH" ]; then
  PRE_ROWS=$(( $(wc -l < "$CSV_PATH") ))
fi

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
  PEER_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo -)"
  echo
  echo "== spore-peer gates ($PEER_DIR) =="

  run_gate 'cargo build' cargo build --locked
  run_gate 'cargo fmt --check' cargo fmt --check
  run_gate 'cargo clippy -D warnings' cargo clippy --locked --all-targets -- -D warnings
  run_gate 'cargo test' cargo test --locked

  # Real-binary fabric smoke: tests/fabric_smoke.rs drives the ACTUAL
  # `spore-peer serve -fabric` binary over a live socket (freg/fput/fpop +
  # hard-kill restart). The Rust unit tests call handle_client in-process,
  # so a broken main() flag path or serve loop passes them all — this smoke
  # is what fails pre-push instead of shipping.
  if [ -x target/debug/spore-peer ]; then
    PEER_BIN="$PEER_DIR/target/debug/spore-peer"
    run_gate 'fabric serve smoke' cargo test --locked --test fabric_smoke
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

# ---- slow-gate check: this run vs this machine's own history ---------------
if [ -n "$CSV_PATH" ] && [ "$PRE_ROWS" -ge 2 ]; then
  HIST=$(head -n "$PRE_ROWS" "$CSV_PATH" | awk -F',' '
    NR > 1 {
      g = $5; gsub(/^"|"$/, "", g)
      c[g]++
      v[g "," c[g]] = $6 + 0
    }
    END {
      for (g in c) {
        if (c[g] < 3) continue            # a median needs >= 3 samples
        k = 0
        for (i = 1; i <= c[g]; i++) buf[k++] = v[g "," i]
        for (i = 0; i < k - 1; i++)       # insertion sort; k is small
          for (j = i + 1; j < k; j++)
            if (buf[j] < buf[i]) { t = buf[i]; buf[i] = buf[j]; buf[j] = t }
        m = (k % 2) ? buf[int(k / 2)] : int((buf[k / 2 - 1] + buf[k / 2]) / 2)
        printf "%d\t%s\n", m, g
      }
    }')

  checked=0; flagged=0
  while read -r dt label; do
    [ -n "$label" ] || continue
    med=$(printf '%s\n' "$HIST" | awk -F'\t' -v g="$label" '$2 == g {print $1; exit}')
    [ -n "$med" ] || continue
    checked=$((checked + 1))
    if awk -v d="$dt" -v m="$med" -v r="$GATE_SLOW_RATIO" 'BEGIN { exit !(d > m * r) }'; then
      flagged=$((flagged + 1))
      printf '  SLOW: %s — %s vs median %s (%.2fx baseline)\n' \
        "$label" "$(fmt_ms "$dt")" "$(fmt_ms "$med")" \
        "$(awk -v d="$dt" -v m="$med" 'BEGIN { printf "%.2f", d / m }')"
    fi
  done <<TIMINGS
$TIMINGS
TIMINGS

  if [ "$flagged" -gt 0 ]; then
    echo "slow-gate check: $flagged gate(s) anomalously slow for this machine (see SLOW above)"
  elif [ "$checked" -gt 0 ]; then
    echo "slow-gate check: no anomalies ($checked gate(s) vs history)"
  else
    echo "slow-gate check: skipped (insufficient history — a median needs >= 3 prior runs)"
  fi
fi

MODE=""
if [ "$QUICK" -eq 1 ]; then MODE=" (quick)"; fi

echo
echo "ALL GATES GREEN${MODE} — spore@$SPORE_SHA"
if [ -n "$PEER_BIN" ]; then
  echo "              spore-peer@$PEER_SHA"
fi

if [ -n "$CSV_PATH" ]; then
  rows=$(( $(wc -l < "$CSV_PATH") - 1 ))
  echo "gate latency log: $CSV_PATH ($rows rows)"
fi
