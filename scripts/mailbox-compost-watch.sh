#!/usr/bin/env bash
# mailbox-compost-watch.sh — red signal on the compost promise, on a LIVE
# MyceliumMailbox.
#
# Spore's headline claim is that a delivered message composts: the recipient
# reads it, `chain.Watch` auto-burns the on-chain slot, and nothing but a spent
# tx remains. `msg recv-e2` once failed to burn at all and every delivered
# pointer sat in the mailbox forever while the logs looked healthy. This
# watches the one thing that cannot lie about it — the CHAIN STATE itself.
#
# How it can see a recipient-only slot: `read(to, seq)` requires
# `msg.sender == to`, but `eth_call` takes a `from`, so a monitor simulates the
# read as the recipient. The payload is already E2E-encrypted (the contract
# never holds a key), so this is not a privacy leak — and the watchdog only
# ever looks at the DATA LENGTH, never at the bytes.
#
# Per recipient it reads `length(to)` and inspects the most recent `--depth`
# sequence numbers. A slot whose data length is non-zero, whose delivery block
# is older than `--grace-seconds`, means the recipient got the message and
# never burned it: compost is broken for that slot. (A zero-length read is a
# burned slot; a slot younger than the grace window is just "not read yet".)
#
# No jq, no foundry: curl + bash only, so it runs anywhere curl does.
#
# Exit codes: 0 healthy, 1 a stuck slot beyond --max-unburned, 2 cannot check
# (RPC unreachable, no contract at --mailbox, a malformed read), 3 usage error,
# 4 alert delivery failed (--once only), 130 interrupted. Exit 2 is never a
# silent pass: a watchdog that cannot see the chain must not report green.
#
# Usage: bash scripts/mailbox-compost-watch.sh --rpc URL --mailbox 0x… \
#            (--recipient 0x… | --recipients 0x…,0x…) \
#            [--depth N] [--grace-seconds SEC] [--max-unburned N] \
#            [--interval SEC] [--cooldown SEC] [--webhook URL] \
#            [--once] [--dry-run] [--json] [-h]
#
#   --rpc URL           EVM JSON-RPC endpoint (required)
#   --mailbox 0x…       deployed MyceliumMailbox address (required)
#   --recipient 0x…     a mailbox owner to watch; repeatable
#   --recipients A,B    the same, comma-separated
#   --depth N           most recent seqs per recipient to inspect (default 64)
#   --grace-seconds SEC a slot younger than this may still be unread
#                       (default 900 — a delivery gets this long to be read
#                       and burned before it counts as stuck)
#   --max-unburned N    tolerated stuck slots before tripping (default 0)
#   --interval SEC      how often to re-check in watch mode (default 60)
#   --cooldown SEC      minimum seconds between alerts (default 300)
#   --webhook URL       POST the alert JSON here; falls back to
#                       $MAILBOX_COMPOST_WEBHOOK (so the secret stays out of
#                       argv/ps). The URL itself is never put in the payload.
#   --once              check once and exit with the code (for cron/systemd);
#                       exits 4 if the alert itself could not be delivered
#   --dry-run           print the alert payload instead of POSTing
#   --json              print one machine-readable result object and exit (no
#                       alerting; mutually exclusive with --webhook). Its
#                       `recipients` field is "addr:length:unburned,…".
#
#   # Healthy check by hand:
#   bash scripts/mailbox-compost-watch.sh --rpc https://mainnet.base.org \
#     --mailbox 0x… --recipient 0xYourMailboxAddress
#
#   # cron/systemd: page on a stuck slot, at most once every 10 minutes:
#   MAILBOX_COMPOST_WEBHOOK=https://hooks.slack.com/services/… \
#     bash scripts/mailbox-compost-watch.sh --rpc "$RPC" --mailbox 0x… \
#       --recipient 0x… --once --grace-seconds 1800
set -euo pipefail

# keccak4 selectors of the signatures in contracts/MyceliumMailbox.sol.
LENGTH_SEL=0x2c566ae5 # length(address)
READ_SEL=0x014c2add   # read(address,uint256)

RPC=""
MAILBOX=""
RECIPIENTS=()
DEPTH=64
GRACE=900
MAX_UNBURNED=0
INTERVAL=60
COOLDOWN=300
WEBHOOK="${MAILBOX_COMPOST_WEBHOOK:-}"
ONCE=0
DRY_RUN=0
JSON=0

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
  --rpc) RPC="${2:?mailbox-compost-watch: --rpc needs a URL}"; shift 2 ;;
  --mailbox) MAILBOX="${2:?mailbox-compost-watch: --mailbox needs an address}"; shift 2 ;;
  --recipient) RECIPIENTS+=("${2:?mailbox-compost-watch: --recipient needs an address}"); shift 2 ;;
  --recipients)
    IFS=',' read -r -a _split <<<"${2:?mailbox-compost-watch: --recipients needs a list}"
    for _r in "${_split[@]}"; do
      _r="${_r#"${_r%%[![:space:]]*}"}"
      _r="${_r%"${_r##*[![:space:]]}"}"
      [[ -n $_r ]] && RECIPIENTS+=("$_r")
    done
    shift 2
    ;;
  --depth) DEPTH="${2:?mailbox-compost-watch: --depth needs a number}"; shift 2 ;;
  --grace-seconds) GRACE="${2:?mailbox-compost-watch: --grace-seconds needs seconds}"; shift 2 ;;
  --max-unburned) MAX_UNBURNED="${2:?mailbox-compost-watch: --max-unburned needs a number}"; shift 2 ;;
  --interval) INTERVAL="${2:?mailbox-compost-watch: --interval needs seconds}"; shift 2 ;;
  --cooldown) COOLDOWN="${2:?mailbox-compost-watch: --cooldown needs seconds}"; shift 2 ;;
  --webhook) WEBHOOK="${2:?mailbox-compost-watch: --webhook needs a URL}"; shift 2 ;;
  --once) ONCE=1; shift ;;
  --dry-run) DRY_RUN=1; shift ;;
  --json) JSON=1; shift ;;
  -h | --help) usage; exit 0 ;;
  *) echo "mailbox-compost-watch: unknown argument: $1 (see --help)" >&2; exit 3 ;;
  esac
done

if [[ -z $RPC ]]; then echo "mailbox-compost-watch: --rpc URL is required" >&2; exit 3; fi
if [[ -z $MAILBOX ]]; then echo "mailbox-compost-watch: --mailbox ADDRESS is required" >&2; exit 3; fi
if ((${#RECIPIENTS[@]} == 0)); then
  echo "mailbox-compost-watch: at least one --recipient (or --recipients) is required" >&2
  exit 3
fi
if ((JSON == 1)) && [[ -n $WEBHOOK ]]; then
  echo "mailbox-compost-watch: --json and --webhook are mutually exclusive" >&2
  exit 3
fi
if ((JSON == 0 && DRY_RUN == 0)) && [[ -z $WEBHOOK ]]; then
  echo "mailbox-compost-watch: --webhook URL (or \$MAILBOX_COMPOST_WEBHOOK) is required unless --dry-run or --json" >&2
  exit 3
fi

hexonly() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/^0x//'; }
pad_addr() { printf '000000000000000000000000%s' "$(hexonly "$1")"; }
pad_u256() { printf '%064x' "$1"; }
rpc_result() { sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'; }

# rpc_call METHOD PARAMS_JSON — raw response body; non-zero on transport
# failure. JSON-RPC application errors still return a body, so callers look for
# "error".
rpc_call() {
  curl -sf -m 20 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# eth_call TO DATA FROM — the result hex, or non-zero when the call failed or
# the node returned a JSON-RPC error (a revert lands here).
eth_call() {
  local body
  body=$(rpc_call eth_call "[{\"to\":\"$1\",\"data\":\"$2\",\"from\":\"$3\"},\"latest\"]" 2>/dev/null) || return 1
  case "$body" in *'"error"'*) return 1 ;; esac
  rpc_result <<<"$body"
}

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

declare -A TS_CACHE=()
# block_ts BLOCK_NUMBER — unix seconds, cached.
block_ts() {
  local bn=$1 body hex
  if [[ -n ${TS_CACHE[$bn]:-} ]]; then printf '%s' "${TS_CACHE[$bn]}"; return 0; fi
  body=$(rpc_call eth_getBlockByNumber "[\"$(printf '0x%x' "$bn")\",false]" 2>/dev/null) || return 1
  case "$body" in *'"error"'*) return 1 ;; esac
  hex=$(printf '%s' "$body" | sed -n 's/.*"timestamp"[[:space:]]*:[[:space:]]*"0x\([0-9a-fA-F]*\)".*/\1/p')
  [[ -z $hex ]] && return 1
  TS_CACHE[$bn]=$(printf '%d' "0x$hex")
  printf '%s' "${TS_CACHE[$bn]}"
}

# Module-level results of the last check(). Set as globals, NOT echoed through
# a command substitution: `detail=$(check)` runs check in a subshell, which
# would throw away the very state the alert payload is built from.
UNBURNED=0
OLDEST_AGE=0
CANNOT=""
RECIP_SUMMARY=""
DETAIL=""

# check — one pass over every recipient in --depth. Prints a line per
# recipient; sets UNBURNED / OLDEST_AGE / CANNOT / RECIP_SUMMARY.
# Returns 0 healthy, 1 stuck, 2 cannot check.
check() {
  UNBURNED=0
  OLDEST_AGE=0
  CANNOT=""
  RECIP_SUMMARY=""
  DETAIL=""

  local code codehex
  if ! code=$(rpc_call eth_getCode "[\"$MAILBOX\",\"latest\"]" 2>/dev/null); then
    CANNOT="RPC unreachable at $RPC"
    return 2
  fi
  case "$code" in *'"error"'*)
    CANNOT="RPC error reading eth_getCode"
    return 2
    ;;
  esac
  codehex=$(rpc_result <<<"$code")
  if [[ -z $codehex || $codehex == 0x ]]; then
    CANNOT="no contract at $MAILBOX — wrong address, or the wrong chain?"
    return 2
  fi

  local now recipient
  now=$(date +%s)
  for recipient in "${RECIPIENTS[@]}"; do
    local lenres n pending stuck
    if ! lenres=$(eth_call "$MAILBOX" "${LENGTH_SEL}$(pad_addr "$recipient")" "$recipient"); then
      CANNOT="length($recipient) call failed"
      return 2
    fi
    if [[ -z $lenres ]]; then
      CANNOT="length($recipient) returned nothing"
      return 2
    fi
    n=$(printf '%d' "$lenres")
    pending=0
    stuck=0

    local first=$((n > DEPTH ? n - DEPTH : 0))
    local seq
    for ((seq = first; seq < n; seq++)); do
      local res hex len_word bn ts age
      if ! res=$(eth_call "$MAILBOX" "${READ_SEL}$(pad_addr "$recipient")$(pad_u256 "$seq")" "$recipient"); then
        CANNOT="read($recipient, $seq) call failed"
        return 2
      fi
      hex=$(hexonly "$res")
      # (from, blockNumber, offset, dataLength) then the bytes: four 32-byte
      # words minimum. A short return is a malformed read, never a pass.
      if ((${#hex} < 256)); then
        CANNOT="read($recipient, $seq) returned a malformed result"
        return 2
      fi
      len_word=${hex:192:64}
      if [[ $len_word == 0000000000000000000000000000000000000000000000000000000000000000 ]]; then
        continue # burned
      fi
      bn=$(printf '%d' "0x${hex:64:64}")
      ts=$(block_ts "$bn") || { CANNOT="could not read block $bn for $recipient seq $seq"; return 2; }
      age=$((now - ts))
      if ((age >= GRACE)); then
        stuck=$((stuck + 1))
        UNBURNED=$((UNBURNED + 1))
        if ((age > OLDEST_AGE)); then OLDEST_AGE=$age; fi
        DETAIL="${DETAIL}  stuck:  $recipient seq $seq — delivered $((age / 60))m ago, still on chain"$'\n'
      else
        pending=$((pending + 1))
      fi
    done

    DETAIL="${DETAIL}  ok:     $recipient — $n delivered (inspected last $((n - first))), $stuck stuck, $pending still in the grace window"$'\n'
    RECIP_SUMMARY="${RECIP_SUMMARY}${RECIP_SUMMARY:+,}${recipient}:${n}:${stuck}"
  done

  if ((UNBURNED > MAX_UNBURNED)); then return 1; fi
  return 0
}

# alert CODE DETAIL — POST the notification (or print it on --dry-run). Returns
# non-zero when delivery failed.
alert() {
  local code=$1 detail=$2 now host text payload http
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  host=$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)
  if ((code == 1)); then
    text="spore mailbox compost: $UNBURNED slot(s) delivered but never burned on $MAILBOX (oldest $((OLDEST_AGE / 60))m)"
  else
    text="spore mailbox compost: cannot check $MAILBOX ($CANNOT)"
  fi
  payload=$(printf '{"source":"spore-mailbox-compost","at":"%s","host":"%s","mailbox":"%s","exit_code":%d,"unburned":%d,"oldest_age_s":%d,"recipients":"%s","text":"%s","detail":"%s"}' \
    "$(json_escape "$now")" "$(json_escape "$host")" "$(json_escape "$MAILBOX")" \
    "$code" "$UNBURNED" "$OLDEST_AGE" "$(json_escape "$RECIP_SUMMARY")" \
    "$(json_escape "$text")" "$(json_escape "$detail")")
  if ((DRY_RUN == 1)); then
    printf 'mailbox-compost-watch: DRY-RUN payload: %s\n' "$payload"
    return 0
  fi
  http=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --retry 2 --retry-connrefused \
    -H 'Content-Type: application/json' -X POST --data-binary "$payload" "$WEBHOOK" 2>&1) || true
  case "$http" in
  2*)
    echo "mailbox-compost-watch: alerted (HTTP $http)"
    return 0
    ;;
  *)
    echo "mailbox-compost-watch: alert delivery FAILED (HTTP $http); payload was: $payload" >&2
    return 1
    ;;
  esac
}

# json_result CODE DETAIL — one machine-readable object on stdout.
json_result() {
  local code=$1 detail=$2 verdict
  case "$code" in
  0) verdict=ok ;;
  1) verdict=stuck ;;
  *) verdict=unverifiable ;;
  esac
  printf '{"source":"spore-mailbox-compost","at":"%s","mailbox":"%s","verdict":"%s","exit_code":%d,"unburned":%d,"oldest_age_s":%d,"recipients":"%s","reason":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(json_escape "$MAILBOX")" "$verdict" "$code" \
    "$UNBURNED" "$OLDEST_AGE" "$(json_escape "$RECIP_SUMMARY")" "$(json_escape "$detail")"
}

# ---- one-shot modes --------------------------------------------------------
if ((JSON == 1)); then
  rc=0
  check || rc=$?
  json_result "$rc" "$CANNOT"
  exit "$rc"
fi

if ((ONCE == 1)); then
  printf 'mailbox-compost-watch: %s, mailbox %s, grace %ss\n' "$RPC" "$MAILBOX" "$GRACE"
  rc=0
  check || rc=$?
  printf '%s' "$DETAIL"
  if ((rc == 0)); then
    echo "mailbox-compost-watch: every watched slot composts (or is still within the grace window)"
    exit 0
  fi
  delivered=0
  alert "$rc" "$DETAIL" || delivered=1
  if ((delivered != 0)); then exit 4; fi
  exit "$rc"
fi

# ---- watch mode ------------------------------------------------------------
printf 'mailbox-compost-watch: watching %s at %s every %ss (grace %ss, cooldown %ss) — Ctrl-C to stop\n' \
  "$MAILBOX" "$RPC" "$INTERVAL" "$GRACE" "$COOLDOWN"
trap 'echo "mailbox-compost-watch: interrupted"; exit 130' INT
last_alert=0
while :; do
  rc=0
  check || rc=$?
  printf '%s' "$DETAIL"
  if ((rc != 0)); then
    now=$(date +%s)
    if ((now - last_alert >= COOLDOWN)); then
      alert "$rc" "$DETAIL" || true
      last_alert=$(date +%s)
    else
      echo "mailbox-compost-watch: tripped again (exit $rc); inside the ${COOLDOWN}s cooldown, not re-alerting"
    fi
  fi
  sleep "$INTERVAL"
done
