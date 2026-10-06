#!/usr/bin/env bash
# station-health-alert.sh — example alerting wrapper around
# scripts/station-health.sh -w: watch a station's heartbeat log and POST a
# JSON notification to a webhook on the first violation (or malformed line),
# then resume watching after a cooldown so a persistent condition pages once
# per cooldown, not once per heartbeat.
#
# The payload is one JSON object, so it works as-is with a Slack incoming
# webhook or any custom receiver:
#
#   {"source":"spore-station-health","at":"2026-10-05T23:59:59Z",
#    "host":"station-a","file":"/home/ops/station.jsonl","exit_code":1,
#    "text":"spore station health: /home/ops/station.jsonl tripped (exit 1): <first failure>",
#    "detail":"<the gate's full output>"}
#
# Exit codes: 0 clean stop, 2 usage error, 4 alert delivery failed (--once
# only), 130 interrupted; with --once the gate's own code (1 violation,
# 2 malformed/tail failure) is the exit. In loop mode (default) the wrapper
# keeps watching until Ctrl-C and delivery failures are logged, not fatal.
#
# Usage: bash scripts/station-health-alert.sh -f FILE --webhook URL
#             [--cooldown SEC] [--once] [--dry-run]
#             [--max-pending-age SEC] [--max-lock-age SEC] [--max-pending N]
#
#   -f FILE                the station.jsonl to watch (required)
#   --webhook URL          POST target; falls back to $STATION_HEALTH_WEBHOOK
#                          so the secret stays out of argv/ps; never logged
#   --cooldown SEC         pause after each alert before watching again
#                          (default 300)
#   --once                 alert once and exit with the gate's code (for
#                          cron/systemd supervision); exits 4 if the alert
#                          itself could not be delivered
#   --dry-run              print the payload instead of POSTing — the whole
#                          path is testable without a receiver
#   --max-pending-age/--max-lock-age/--max-pending
#                          passed through to the gate unchanged
#
#   # Slack, watched forever, alert at most every 5 minutes:
#   STATION_HEALTH_WEBHOOK=https://hooks.slack.com/services/... \
#     bash scripts/station-health-alert.sh -f ~/station.jsonl
#
#   # One-shot for cron (exits non-zero on trip for the cron mail):
#   bash scripts/station-health-alert.sh -f ~/station.jsonl \
#     --webhook "$WEBHOOK" --once --max-pending-age 600
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
gate="$script_dir/station-health.sh"

usage() {
  sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'
}

file=""
webhook="${STATION_HEALTH_WEBHOOK:-}"
cooldown=300
once=0
dry_run=0
gate_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
  -f | --file)
    file="${2:?station-health-alert: -f needs a file path}"
    shift 2
    ;;
  --webhook)
    webhook="${2:?station-health-alert: --webhook needs a URL}"
    shift 2
    ;;
  --cooldown)
    cooldown="${2:?station-health-alert: --cooldown needs seconds}"
    shift 2
    ;;
  --once)
    once=1
    shift
    ;;
  --dry-run)
    dry_run=1
    shift
    ;;
  --max-pending-age | --max-lock-age | --max-pending)
    gate_args+=("$1" "${2:?station-health-alert: $1 needs a value}")
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "station-health-alert: unknown argument: $1 (see --help)" >&2
    exit 2
    ;;
  esac
done

if [[ -z $file ]]; then
  echo "station-health-alert: -f FILE is required (the JSONL log to watch)" >&2
  exit 2
fi
if [[ ! -e $file ]]; then
  echo "station-health-alert: no such file: $file" >&2
  exit 2
fi
if [[ -z $webhook && $dry_run != 1 ]]; then
  echo "station-health-alert: --webhook URL (or STATION_HEALTH_WEBHOOK) is required unless --dry-run" >&2
  exit 2
fi

# json_escape escapes a string for embedding in a JSON string literal:
# backslash, double quote, newline, carriage return, tab. Pure bash — no jq.
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

# alert POSTs the trip notification. Prints the payload on --dry-run;
# returns non-zero when delivery fails (loop mode logs it, --once exits 4).
alert() {
  local code=$1 detail=$2 now host first_line text payload http
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  host=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
  first_line=${detail%%$'\n'*}
  text="spore station health: $file tripped (exit $code): $first_line"
  payload=$(printf '{"source":"spore-station-health","at":"%s","host":"%s","file":"%s","exit_code":%d,"text":"%s","detail":"%s"}' \
    "$(json_escape "$now")" "$(json_escape "$host")" "$(json_escape "$file")" \
    "$code" "$(json_escape "$text")" "$(json_escape "$detail")")
  if [[ $dry_run == 1 ]]; then
    printf 'station-health-alert: DRY-RUN payload: %s\n' "$payload"
    return 0
  fi
  http=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --retry 2 --retry-connrefused \
    -H 'Content-Type: application/json' -X POST --data-binary "$payload" "$webhook" 2>&1) || true
  case "$http" in
  2*)
    echo "station-health-alert: webhook delivered (HTTP $http)"
    return 0
    ;;
  *)
    echo "station-health-alert: webhook delivery FAILED (HTTP $http); payload was: $payload" >&2
    return 1
    ;;
  esac
}

while :; do
  detail=""
  rc=0
  detail=$(bash "$gate" -w -f "$file" ${gate_args+"${gate_args[@]}"} 2>&1) || rc=$?
  if ((rc == 0)); then
    echo "station-health-alert: gate exited 0 (watching stopped); exiting"
    exit 0
  fi
  if ((rc == 130)); then
    echo "station-health-alert: interrupted"
    exit 130
  fi
  # rc is 1 (violation) or 2 (malformed line / tail failure).
  delivered=0
  alert "$rc" "$detail" || delivered=1
  if ((once == 1)); then
    if ((delivered != 0)); then
      exit 4
    fi
    exit "$rc"
  fi
  echo "station-health-alert: cooldown ${cooldown}s before watching again"
  sleep "$cooldown"
done
