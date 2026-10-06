#!/usr/bin/env bash
# station-health.sh — turn a spore approval station's JSONL heartbeat log into
# a pass/fail health gate.
#
# Input: the station.jsonl produced by
#
#   spore msg approve -request-dir QUEUE ... -watch -metrics-every 1m -metrics-json | tee -a station.jsonl
#
# optionally appended to by cron one-shot scrapes:
#
#   spore msg approval-metrics -dir QUEUE -state-dir D -envelope >> station.jsonl
#
# Each line starting with {"at": is a heartbeat in the compact shape
# documented in docs/APPROVAL_RUNBOOK.md §3.1 (at, station, metrics). Lines
# that do not start with {"at": are ignored (comment noise in a hand-edited
# file); a line that starts with {"at": but carries no metrics object is a
# torn or foreign line and fails the gate. Heartbeats emitted by spore before
# v0.8.5 (no station object) still pass.
#
# The field extraction keys off the exact compact encoder output (single-line
# JSON, no spaces) that `spore` produces; it is not a general JSON parser.
#
# Checks:
#   - orphaned signing locks (lock whose guarded request file is gone)
#   - lock ages at/over the stale-break line (default 60s == approvalLockTTL:
#     the holder crashed or wedged and the next scan will break the lock)
#   - pending requests at/over the approval expiry (default 900s: past the
#     15-minute approval TTL a request can never be signed)
#   - PENDING queue depth over --max-pending (default: unchecked)
#
# Two modes:
#   batch (default)  check the whole log, print every violation, exit.
#   -w / --watch     live tripwire: follow only NEW heartbeats (pure-bash
#                    chunked follower — NOT tail -f, whose stdio buffers
#                    small appends when stdout is a pipe, stalling
#                    delivery) and stop with a non-zero exit on the FIRST
#                    violation or malformed line; a vanished file, an
#                    unopenable rotation, or a directory also stops
#                    non-zero — never a silent pass. Ctrl-C is the stop
#                    signal (exit 130). Rename/copytruncate rotation is
#                    followed.
#                    Combine with the alerting of your choice:
#                      while bash scripts/station-health.sh -w -f station.jsonl; do sleep 2; done
#
# Exit codes: 0 healthy, 1 health violation, 2 malformed input (in watch
# mode: also a vanished file, unopenable rotation, or directory — never a
# silent pass), 3 no heartbeat lines (batch mode only — a silent station is
# not a healthy one; watch mode follows instead of ending).
#
# Usage: bash scripts/station-health.sh [-w] [-f FILE] [--max-pending-age SEC]
#             [--max-lock-age SEC] [--max-pending N]
set -euo pipefail

usage() {
  sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'
}

file=""
max_pending_age=900
max_lock_age=60
max_pending="" # empty = unchecked
watch=0

while [[ $# -gt 0 ]]; do
  case "$1" in
  -w | --watch)
    watch=1
    shift
    ;;
  -f | --file)
    file="${2:?station-health: -f needs a file path}"
    shift 2
    ;;
  --max-pending-age)
    max_pending_age="${2:?station-health: --max-pending-age needs seconds}"
    shift 2
    ;;
  --max-lock-age)
    max_lock_age="${2:?station-health: --max-lock-age needs seconds}"
    shift 2
    ;;
  --max-pending)
    max_pending="${2:?station-health: --max-pending needs a count}"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "station-health: unknown argument: $1 (see --help)" >&2
    exit 2
    ;;
  esac
done

if [[ -z $file || $file == "-" ]]; then
  file=/dev/stdin
fi
if [[ ! -e $file && $file != /dev/stdin ]]; then
  echo "station-health: no such file: $file" >&2
  exit 2
fi

violations=0
parse_errors=0
heartbeats=0

fail() {
  echo "station-health: FAIL: $*"
  violations=$((violations + 1))
}

# process_line evaluates one heartbeat line (the caller has verified the
# {"at": prefix). Returns 0 healthy, 1 violation, 2 malformed. All thresholds
# and the fail() printer come from the globals above.
process_line() {
  local line=$1 at lock_age pending_age pending count bad=0
  if [[ $line != *'"metrics":{'* ]]; then
    echo "station-health: PARSE-ERROR: heartbeat line without a metrics object: ${line:0:80}"
    return 2
  fi
  at=$(sed -n 's/^{"at":"\([^"]*\)".*/\1/p' <<<"$line")

  # Orphaned signing locks: residue until the TTL stale-break fires. The
  # encoder omits "orphaned" entirely when false, so any occurrence means at
  # least one orphaned lock.
  if [[ $line == *'"orphaned":true'* ]]; then
    count=$(grep -o '"orphaned":true' <<<"$line" | wc -l)
    fail "$at: $count orphaned signing lock(s) - guarded request file gone (residue until the stale-break)"
    bad=1
  fi

  # Oldest lock at/over the stale-break line: the holder is dead or wedged.
  lock_age=$(sed -n 's/.*"locks":{"live":[0-9]*,"oldest_age_seconds":\([0-9.e+]*\).*/\1/p' <<<"$line")
  if [[ -n $lock_age ]] && awk -v a="$lock_age" -v m="$max_lock_age" 'BEGIN{exit !(a>=m)}'; then
    fail "$at: oldest lock age ${lock_age}s >= stale-break line ${max_lock_age}s (holder crashed or wedged)"
    bad=1
  fi

  # Oldest pending at/over the approval expiry: never signable again.
  pending_age=$(sed -n 's/.*"oldest_pending":{"path":"[^"]*","age_seconds":\([0-9.e+]*\).*/\1/p' <<<"$line")
  if [[ -n $pending_age ]] && awk -v a="$pending_age" -v m="$max_pending_age" 'BEGIN{exit !(a>=m)}'; then
    fail "$at: oldest pending request ${pending_age}s old >= approval TTL line ${max_pending_age}s (expired: can never be signed)"
    bad=1
  fi

  # Optional queue-depth gate.
  if [[ -n $max_pending ]]; then
    pending=$(sed -n 's/.*"status_counts":{[^}]*"PENDING":\([0-9]*\).*/\1/p' <<<"$line")
    pending=${pending:-0}
    if awk -v a="$pending" -v m="$max_pending" 'BEGIN{exit !(a>m)}'; then
      fail "$at: $pending PENDING request(s) > --max-pending $max_pending"
      bad=1
    fi
  fi
  return "$bad"
}

if [[ $watch == 1 ]]; then
  # Live tripwire: follow only NEW heartbeats and stop on the first
  # violation or malformed line. Pure-bash chunked reads instead of
  # `tail -f`: tail's stdio buffers small appends when its stdout is a
  # pipe (4KB block buffering), so a violating heartbeat could sit
  # undelivered indefinitely — found by exactly this scenario in testing.
  # Lines are reassembled across chunk boundaries; a truncated file
  # (logrotate copytruncate) or a renamed rotation reopens from the new
  # file; a vanished file exits 2. Ctrl-C exits 130 via the INT trap.
  buf=""
  # set -e: a failing stat in an assignment exits the script silently with
  # stat's status — catch it so the vanished-file check below can run.
  prev_size=$(stat -c %s "$file" 2>/dev/null) || prev_size=""
  prev_ino=$(stat -c %i "$file" 2>/dev/null) || prev_ino=""
  if [[ -z $prev_size ]]; then
    echo "station-health: watch: cannot stat $file" >&2
    exit 2
  fi
  if [[ -d $file ]]; then
    echo "station-health: watch: cannot follow a directory: $file" >&2
    exit 2
  fi
  exec 3<"$file"
  cleanup() {
    exec 3<&-
  }
  reopen() {
    exec 3<&-
    if ! exec 3<"$file"; then
      echo "station-health: watch: cannot reopen $file (rotated away?)" >&2
      exit 2
    fi
    buf=""
  }
  trap 'cleanup; exit 130' INT TERM
  trap 'cleanup' EXIT
  rc=0
  while :; do
    chunk=""
    got=0
    if IFS= read -r -u 3 -N 65536 chunk; then got=1; fi
    if [[ -n $chunk ]]; then
      buf+=$chunk
      while [[ $buf == *$'\n'* ]]; do
        line=${buf%%$'\n'*}
        buf=${buf#*$'\n'}
        line=${line%$'\r'}
        [[ $line == '{"at":'* ]] || continue
        rc=0
        process_line "$line" || rc=$?
        if ((rc != 0)); then
          exit "$rc"
        fi
      done
    fi
    cur_size=$(stat -c %s "$file" 2>/dev/null) || cur_size=""
    cur_ino=$(stat -c %i "$file" 2>/dev/null) || cur_ino=""
    if [[ -z $cur_size ]]; then
      echo "station-health: watch: $file vanished; cannot follow" >&2
      exit 2
    fi
    if [[ $cur_ino != "$prev_ino" || $cur_size -lt $prev_size ]]; then
      reopen
    fi
    prev_size=$cur_size
    prev_ino=$cur_ino
    if ((got == 0)); then
      sleep 1
    fi
  done
fi

while IFS= read -r line; do
  [[ $line == '{"at":'* ]] || continue
  heartbeats=$((heartbeats + 1))
  rc=0
  process_line "$line" || rc=$?
  if ((rc == 2)); then
    parse_errors=$((parse_errors + 1))
  fi
done <"$file"

if ((parse_errors > 0)); then
  echo "station-health: $parse_errors malformed heartbeat line(s) in $heartbeats checked" >&2
  exit 2
fi
if ((heartbeats == 0)); then
  echo "station-health: FAIL: no heartbeat lines found - a silent station is not a healthy one"
  exit 3
fi
if ((violations > 0)); then
  echo "station-health: $violations violation(s) across $heartbeats heartbeat(s)"
  exit 1
fi
echo "station-health: OK: $heartbeats heartbeat(s) checked (pending-age < ${max_pending_age}s, lock-age < ${max_lock_age}s${max_pending:+, PENDING <= $max_pending})"
