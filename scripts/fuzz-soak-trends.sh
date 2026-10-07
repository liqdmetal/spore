#!/bin/sh
# fuzz-soak-trends.sh — read the fuzz-soak ledger (.fuzz-soak/log.tsv) and flag
# what a single pass cannot see.
#
# A soak pass reports its own delta, which answers "did anything change since
# yesterday". It cannot answer the question that actually matters after a few
# weeks: is the fuzzer still finding anything at all? A corpus that has not
# moved and coverage that has not grown looks identical to a healthy quiet week
# in any one pass, and it is also what a quietly broken harness looks like.
# This reads the whole ledger and says which one it is:
#
#   STALLED  no pass has set a new coverage best in FUZZ_STALL_PASSES passes
#   FAILING  a pass did not end GREEN (its most recent one is named)
#   FELL     measured coverage went DOWN between two passes
#   UNMEASURED  the last pass could not measure coverage — usually a reproducer
#            sitting in the corpus, which fails the very replay being measured
#
#   usage: fuzz-soak-trends.sh [--flags-only]
#     --flags-only  print just the flags (nothing at all when clean), for a
#                   caller that already has the ledger, like a soak pass
#
# Env knobs:
#   FUZZ_SOAK_LEDGER    path to the ledger (default: $FUZZ_SOAK_DIR/log.tsv, or
#                       <spore>/.fuzz-soak/log.tsv)
#   FUZZ_SOAK_DIR       the soak's state directory (scripts/fuzz-soak.sh)
#   FUZZ_STALL_PASSES   consecutive passes without a new coverage best before
#                       coverage counts as stalled (default 5)
#   FUZZ_TREND_WINDOW   how many recent passes to tabulate (default 10)
#
# Exit codes: 0 nothing flagged, 1 at least one flag, 2 no usable ledger.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
LEDGER="${FUZZ_SOAK_LEDGER:-${FUZZ_SOAK_DIR:-$SELF_DIR/../.fuzz-soak}/log.tsv}"
STALL="${FUZZ_STALL_PASSES:-5}"
WINDOW="${FUZZ_TREND_WINDOW:-10}"

FLAGS_ONLY=""
case "${1:-}" in
  '') ;;
  --flags-only) FLAGS_ONLY=1 ;;
  *) echo "usage: fuzz-soak-trends.sh [--flags-only]" >&2; exit 2 ;;
esac

case "$STALL" in
  '' | *[!0-9]*) echo "FUZZ_STALL_PASSES must be a whole number, got '$STALL'" >&2; exit 2 ;;
esac
case "$WINDOW" in
  '' | *[!0-9]* | 0) echo "FUZZ_TREND_WINDOW must be a positive whole number, got '$WINDOW'" >&2; exit 2 ;;
esac

[ -f "$LEDGER" ] || {
  echo "no soak ledger found: $LEDGER" >&2
  echo "run scripts/fuzz-soak.sh first — it creates one." >&2
  exit 2
}

# Rows are the ledger's own TSV: timestamp, mode, fuzz_seconds, status,
# corpus_before, corpus_after, found, minimized, coverage, coverage_delta,
# duration_s. Coverage is a block count or "n/a" when a reproducer in the corpus
# made the replay fail, so it is matched rather than assumed numeric.
awk -F'\t' -v stall="$STALL" -v window="$WINDOW" -v flags_only="$FLAGS_ONLY" '
NR == 1 {
  if ($1 != "timestamp") { printf "not a fuzz-soak ledger: %s\n", FILENAME > "/dev/stderr"; bad = 1; exit 2 }
  next
}
bad { next }
{
  n++
  ts[n] = $1; status[n] = $4; corpus[n] = $6; found[n] = $7; minimized[n] = $8; cov[n] = $9
  if ($4 != "GREEN") { fails++; fail_ts = $1; fail_status = $4 }
}
END {
  if (bad) exit 2                # awk runs END even after `exit` in a rule
  if (n == 0) { printf "no passes recorded in %s yet\n", FILENAME > "/dev/stderr"; exit 2 }

  # The latest pass that set a new best, and any pass that lost coverage.
  best = -1; best_i = 0; prev = -1; fell = 0
  for (i = 1; i <= n; i++) {
    if (cov[i] ~ /^[0-9]+$/) {
      v = cov[i] + 0
      if (v > best) { best = v; best_i = i }
      if (prev >= 0 && v < prev) { fell++; fell_from = prev; fell_to = v; fell_ts = ts[i] }
      prev = v
    }
  }
  since = (best_i > 0) ? n - best_i : n
  stalled = (best_i > 0 && since >= stall)
  unmeasured = (cov[n] == "n/a" || cov[n] == "")

  flags = 0
  if (!flags_only) {
    printf "== fuzz soak trends — %d pass(es) in %s\n", n, FILENAME
    printf "  %-20s %-6s %7s %6s %10s %9s\n", "timestamp", "status", "corpus", "found", "minimized", "coverage"
    first = (n - window + 1 > 1) ? n - window + 1 : 1
    for (i = first; i <= n; i++) {
      printf "  %-20s %-6s %7s %6s %10s %9s\n", ts[i], status[i], corpus[i], found[i], minimized[i], cov[i]
    }
    if (first > 1) printf "  (%d earlier pass(es) not shown)\n", first - 1
    printf "\n"
  }

  if (stalled) {
    printf "  STALLED: no new coverage best in %d pass(es) — best %d at %s, latest pass %s\n", \
           since, best, ts[best_i], cov[n]
    flags++
  }
  if (fails > 0) {
    printf "  FAILING: %d of %d pass(es) did not end GREEN — most recent %s at %s\n", \
           fails, n, fail_status, fail_ts
    flags++
  }
  if (fell > 0) {
    printf "  FELL: coverage dropped %d -> %d at %s\n", fell_from, fell_to, fell_ts
    flags++
  }
  if (unmeasured) {
    printf "  UNMEASURED: the last pass could not measure coverage — a reproducer in the corpus fails the replay\n"
  }

  if (!flags_only) {
    if (best_i > 0)
      printf "\n%d pass(es); best coverage %d at %s; stall threshold %d pass(es) without a gain; showing last %d\n", \
             n, best, ts[best_i], stall, window
    else
      printf "\n%d pass(es); coverage never measured\n", n
  }
  exit (flags > 0 ? 1 : 0)
}
' "$LEDGER"
