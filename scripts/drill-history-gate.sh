#!/usr/bin/env bash
# drill-history-gate.sh — daily cron consumer for spore's drill history.
# Gates the JSONL heartbeat file the approval-drill-watch sentinel appends
# to its repo's data-only `metrics` branch (drill.jsonl):
#   1. VERDICT: the last heartbeat must carry "verdict":"success".
#   2. FRESHNESS: the last heartbeat must be younger than --max-age-seconds
#      (default 172800 = 48h, two missed daily drills). A dead sentinel,
#      an empty file, or an unfetchable one must fail too — verdict-gating
#      alone cannot see a gate that stopped writing.
# On failure it opens/updates ONE tracking issue (marker
# <!-- drill-history-gate -->, label drill-history) via the GitHub API;
# on recovery it comments and auto-closes it. Requires GH_TOKEN for issue
# management. With --no-issue it prints and exits only.
# Exit codes: 0 healthy, 1 stale verdict, 2 stale history (too old, empty,
# unparseable, or unfetchable), 3 usage error.
# Usage: bash scripts/drill-history-gate.sh [--url URL] [--file FILE]
#             [--max-age-seconds SEC] [--repo OWNER/NAME] [--no-issue]
#   --url               fetch the JSONL from here (default:
#                       https://raw.githubusercontent.com/<repo>/metrics/drill.jsonl)
#   --file              read a local file instead of fetching (tests)
#   --max-age-seconds   freshness gate (default 172800)
#   --repo              OWNER/NAME for the tracking issue and default URL
#                       (default: liqdmetal/spore)
#   --no-issue          print the verdict only; never call the issues API
set -euo pipefail
usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }
json_escape() {
  local s=$1
  s=${s//\/\\}; s=${s//\"/\\\"}; s=${s//$'\r'/}; s=${s//$'\n'/\n}; s=${s//$'\t'/\t}
  printf '%s' "$s"
}
api() {
  local method=$1 path=$2 payload=${3:-}
  if [[ -z ${GH_TOKEN:-} ]]; then
    echo "drill-history-gate: GH_TOKEN required for issue management (or pass --no-issue)" >&2
    exit 3
  fi
  if [[ -n $payload ]]; then
    curl -fsS --max-time 30 -X "$method" -H "Authorization: Bearer ${GH_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${repo}/${path}" --data-binary "$payload"
  else
    curl -fsS --max-time 30 -X "$method" -H "Authorization: Bearer ${GH_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/${repo}/${path}"
  fi
}
find_issue() { # echoes the open tracking issue number (empty = none); returns nonzero if the QUERY itself failed — callers must not treat that as "no issue"
  local out rc=0
  out=$(api GET "issues?labels=drill-history&state=open") || rc=$?
  if ((rc != 0)); then
    echo "drill-history-gate: WARNING: could not query tracking issues (curl rc ${rc}); leaving issue state untouched" >&2
    return "$rc"
  fi
  grep -o '"number": *[0-9]*' <<<"$out" | head -1 | tr -dc '0-9' || true
}
open_issue() {
  local reason=$1 line=$2
  local title="Drill history gate: spore approval drill is red or stale"
  local marker='<!-- drill-history-gate -->'
  local body="${reason}
| | |
|---|---|
| last heartbeat | \`${line}\` |

Gate: \`bash scripts/drill-history-gate.sh --repo ${repo}\`. Re-run daily; it auto-closes on recovery.

${marker}"
  local num qrc=0
  num=$(find_issue) || qrc=$?
  if ((qrc != 0)); then
    echo "drill-history-gate: WARNING: cannot tell whether a tracking issue exists; NOT opening a duplicate — re-run the gate" >&2
    return 0
  fi
  if [[ -n $num ]]; then
    api POST "issues/$num/comments" "{\"body\":\"$(json_escape "Still failing: $reason")\"}" >/dev/null
    echo "drill-history-gate: tracking issue #$num updated: $reason"
  else
    local payload
    payload=$(printf '{"title":"%s","body":"%s","labels":["drill-history"]}' \
      "$(json_escape "$title")" "$(json_escape "$body")")
    num=$(api POST "issues" "$payload" | grep -o '"number": *[0-9]*' | head -1 | tr -dc '0-9')
    echo "drill-history-gate: tracking issue #$num opened: $reason"
  fi
}
close_issue() {
  local at=$1
  local num qrc=0
  num=$(find_issue) || qrc=$?
  if ((qrc != 0)); then
    return 0 # find_issue already warned; the next healthy run retries the close
  fi
  if [[ -n $num ]]; then
    api POST "issues/$num/comments" '{"body":"Drill history healthy again; auto-closing."}' >/dev/null
    api PATCH "issues/$num" '{"state":"closed"}' >/dev/null
    echo "drill-history-gate: tracking issue #$num closed (recovered; last drill at $at)"
  fi
}
url=""; file=""; max_age=172800; repo="liqdmetal/spore"; no_issue=0
while [[ $# -gt 0 ]]; do
  case "$1" in
  --url) url="${2:?drill-history-gate: --url needs a URL}"; shift 2 ;;
  --file) file="${2:?drill-history-gate: --file needs a path}"; shift 2 ;;
  --max-age-seconds) max_age="${2:?drill-history-gate: --max-age-seconds needs seconds}"; shift 2 ;;
  --repo) repo="${2:?drill-history-gate: --repo needs OWNER/NAME}"; shift 2 ;;
  --no-issue) no_issue=1; shift ;;
  -h | --help) usage; exit 0 ;;
  *) echo "drill-history-gate: unknown argument: $1 (see --help)" >&2; exit 3 ;;
  esac
done
tmp=""
cleanup() { if [[ -n $tmp && -z $file ]]; then rm -f "$tmp"; fi; }
trap 'cleanup' EXIT
if [[ -n $file ]]; then
  if [[ ! -r $file ]]; then
    echo "drill-history-gate: FAIL: cannot read $file" >&2
    exit 2
  fi
elif [[ -n $url ]]; then
  tmp=$(mktemp)
  if ! curl -fsSL --max-time 30 "$url" -o "$tmp"; then
    echo "drill-history-gate: FAIL: cannot fetch $url" >&2
    exit 2
  fi
else
  tmp=$(mktemp)
  if ! curl -fsSL --max-time 30 \
    "https://raw.githubusercontent.com/${repo}/metrics/drill.jsonl" -o "$tmp"; then
    echo "drill-history-gate: FAIL: cannot fetch drill.jsonl for ${repo}" >&2
    exit 2
  fi
fi
last=$(grep '^{' "${file:-$tmp}" 2>/dev/null | tail -1 || true)
if [[ -z $last ]]; then
  echo "drill-history-gate: FAIL: drill history is empty (no heartbeat lines)" >&2
  exit 2
fi
at=$(sed -n 's/^{"at":"\([^"]*\)".*/\1/p' <<<"$last")
verdict=$(sed -n 's/.*"verdict":"\([^"]*\)".*/\1/p' <<<"$last")
if [[ -z $at || -z $verdict ]]; then
  echo "drill-history-gate: FAIL: last heartbeat is not a parseable drill line: ${last:0:80}" >&2
  exit 2
fi
at_epoch=$(date -u -d "$at" +%s 2>/dev/null || echo "")
now_epoch=$(date -u +%s)
# An unparseable stamp is a corrupt history: it fails as exit 2, never as
# fresh (the first draft had the fallback sign backwards and passed corrupt
# stamps as healthy — the badstamp fixture caught it).
fail_reason=""
rc=0
if [[ -z $at_epoch ]]; then
  fail_reason="drill history is UNPARSEABLE: last heartbeat stamp \"${at}\" is not RFC3339"
  rc=2
elif ((now_epoch - at_epoch > max_age)); then
  age=$(((now_epoch - at_epoch) / 3600))
  fail_reason="drill history is STALE: last heartbeat ${at} is ${age}h old (gate: $((max_age / 3600))h)"
  rc=2
elif [[ $verdict != "success" ]]; then
  fail_reason="last drill verdict is RED: \"${verdict}\" at ${at}"
  rc=1
fi
age=$(((now_epoch - ${at_epoch:-now_epoch}) / 3600))
if [[ -z $fail_reason ]]; then
  echo "drill-history-gate: OK: last drill at ${at} verdict=success (age ${age}h)"
  if [[ $no_issue != 1 ]]; then close_issue "$at"; fi
  exit 0
fi
echo "drill-history-gate: FAIL: $fail_reason"
if [[ $no_issue != 1 ]]; then open_issue "$fail_reason" "$last"; fi
exit "$rc"
