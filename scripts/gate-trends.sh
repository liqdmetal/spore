#!/bin/sh
# gate-trends.sh — analyze the gate-latency log written by scripts/gates.sh
# (.gate-timings.csv): per-gate median and p95, plus a trend check that flags
# any gate whose recent latency is drifting upward.
#
#   usage: gate-trends.sh [full|quick]        (optional mode filter)
#
# Env knobs:
#   GATE_TIMINGS_CSV   path to the log (default: <spore>/.gate-timings.csv)
#   GATE_TREND_RATIO   recent-half median / earlier-half median threshold
#                      above which a gate is called "trending up"
#                      (default 1.25)
#   GATE_TREND_FLOOR   minimum absolute growth in ms for a trend to be
#                      reported (default 250) — keeps sub-second noise on
#                      tiny gates from crying wolf
#
# Trend method: split each gate's rows into an earlier half and a recent
# half (by insertion order, which is chronological — the log is append-only)
# and compare medians. A gate is flagged when
#   recent_median > earlier_median * GATE_TREND_RATIO
#   AND recent_median - earlier_median >= GATE_TREND_FLOOR.
# Rows with status=fail are excluded from the timing statistics but counted
# and reported separately — a gate that starts failing IS the signal.
#
# Exit codes: 0 no trends (warnings allowed), 1 at least one gate trending.
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
CSV="${GATE_TIMINGS_CSV:-$SELF_DIR/../.gate-timings.csv}"
RATIO="${GATE_TREND_RATIO:-1.25}"
FLOOR="${GATE_TREND_FLOOR:-250}"

[ -f "$CSV" ] || { echo "no latency log found: $CSV" >&2
                   echo "run scripts/gates.sh first — it creates one." >&2; exit 2; }

MODE_FILTER="${1:-}"
case "$MODE_FILTER" in
  ''|full|quick) ;;
  *) echo "usage: gate-trends.sh [full|quick]" >&2; exit 2 ;;
esac

awk -F',' -v ratio="$RATIO" -v floor="$FLOOR" -v mode="$MODE_FILTER" '
function median(arr, n,   i, j, tmp, vals, m) {
  for (i = 0; i < n; i++) vals[i] = arr[i]
  for (i = 0; i < n - 1; i++)              # insertion sort: n is small
    for (j = i + 1; j < n; j++)
      if (vals[j] < vals[i]) { tmp = vals[i]; vals[i] = vals[j]; vals[j] = tmp }
  if (n % 2) return vals[int(n / 2)]
  return (vals[n / 2 - 1] + vals[n / 2]) / 2
}
NR == 1 {
  if ($1 != "timestamp") { print "not a gate-timings CSV: " FILENAME > "/dev/stderr"; ok = 0; exit 2 }
  ok = 1
  next
}
ok != 1 { next }
{
  if (mode != "" && $2 != mode) next
  gate = $5; ms = $6 + 0; status = $7
  gsub(/^"|"$/, "", gate)
  if (status == "fail") { fails[gate]++; next }
  n[gate]++
  all[gate "," n[gate] - 1] = ms
  if ($1 > latest[gate]) latest[gate] = $1
}
END {
  if (!ok) exit 2              # awk runs END even after `exit` in a rule
  total_trend = 0
  ng = 0
  for (g in n) gates[ng++] = g
  for (i = 0; i < ng - 1; i++)            # alphabetical: stable table across runs
    for (j = i + 1; j < ng; j++)
      if (gates[j] < gates[i]) { t = gates[i]; gates[i] = gates[j]; gates[j] = t }
  fmt = "  %-34s %8s %8s %8s %8s\n"
  printf fmt, "gate", "runs", "median", "p95", "latest"
  printf fmt, "----", "----", "------", "---", "------"
  for (gi = 0; gi < ng; gi++) {
    g = gates[gi]
    k = n[g]
    half = int(k / 2)
    # median() needs 0-based integer indices — copy each series into a flat
    # buffer first (the gate-keyed arrays are string-indexed).
    for (i = 0; i < k; i++) flat[i] = all[g "," i]
    med[g] = median(flat, k)
    p95[g] = flat[int(0.95 * k + 0.999999) - 1]    # flat is sorted in place; nearest-rank
    for (i = 0; i < half; i++) earlybuf[i] = all[g "," i]
    for (i = half; i < k; i++) recentbuf[i - half] = all[g "," i]
    em = median(earlybuf, half)
    rm = median(recentbuf, k - half)

    printf fmt, g, n[g], sprintf("%dms", med[g]), sprintf("%dms", p95[g]), latest[g]

    growth = rm - em
    if (half >= 2 && k - half >= 2 && rm > em * ratio && growth >= floor) {
      printf "  TRENDING UP: %s — recent-half median %dms vs earlier-half %dms (+%dms, %.2fx)\n", \
             g, rm, em, growth, rm / em
      total_trend++
    }
  }
  nf = 0
  for (g in fails) {
    printf "  FAILURES: %s — %d failed run(s) excluded from timing stats\n", g, fails[g]
    nf++
  }
  if (nf) total_trend++
  printf "\n%d gate(s) tracked%s\n", length(n), (mode != "" ? " (mode: " mode ")" : "")
  exit (total_trend > 0 ? 1 : 0)
}
' "$CSV"
