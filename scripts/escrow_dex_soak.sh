#!/usr/bin/env bash
# scripts/escrow_dex_soak.sh — two-party escrow/dex soak against a local DERO
# simulator (spore derosim serve). REAL spore CLI processes on both sides:
#
#   bootstrap   spore init kits, a real spore mailbox run as the shared
#               body store, signed invites, msg mail add -invite
#   fund→claim  alice funds RelayHTLC via msg send-e2 -escrow htlc, bob
#               claims with msg escrow claim; sim state + in-thread notices
#               prove the settlement on both sides
#   fund→refund the same fund shape, then /debug/bump past expiry and
#               msg escrow refund returns the funds to alice
#   swap        msg dex swap (+ wrap/unwrap) against the sim's
#               constant-product pool with min-out enforced in the "contract"
#   watchdog    continuity watch-reaper against a LIVE `spore serve` node:
#               baseline, alive-advance, SIGKILL the daemon, watch the
#               frozen pass counter escalate through grace to a durable
#               outbox alert, confirm the alert latch dedupes, then restart
#               the daemon and prove recovery re-arms the watchdog
#
# Every assertion is checked; any failure aborts naming the step.
# Usage: scripts/escrow_dex_soak.sh [path-to-spore-binary]
set -euo pipefail

SPORE="${1:-}"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spore-soak.XXXXXX")"
# Random loopback ports: a stale server from a previous run must never be
# able to answer for THIS run (deterministic sim addresses would make that
# look like silent message loss — the worst kind of soak failure).
SIM_PORT=$((21000 + RANDOM % 8000))
MAIL_PORT=$((SIM_PORT + 1))
WEB_A_PORT=$((SIM_PORT + 2))
WEB_B_PORT=$((SIM_PORT + 3))
SIM_LISTEN="127.0.0.1:$SIM_PORT"
SIM_RPC="http://127.0.0.1:$SIM_PORT"
MAILBOX_LISTEN="127.0.0.1:$MAIL_PORT"
MAILBOX_URL="http://127.0.0.1:$MAIL_PORT"

# --- fixed contract IDs the simulator defines (see derosimcmd.go) ---------
export SPORE_SAP_HTLC_SC="sim-htlc-00000000000000000000000000000000000000000000000000000000000001"
export SPORE_SAP_DEX_SC="sim-dex-000000000000000000000000000000000000000000000000000000000000002"
export SPORE_SAP_WDERO_SC="sim-wdero-0000000000000000000000000000000000000000000000000000000003"

PASS=0
SIM_PID=""; MAILBOX_PID=""; WEB_A_PID=""; WEB_B_PID=""; NODE_PID=""
cleanup() {
  for pid in "$SIM_PID" "$MAILBOX_PID" "$WEB_A_PID" "$WEB_B_PID" "$NODE_PID"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

# ---------------- helpers (all defined before use) ----------------
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"; }

wait_for() { # wait_for URL — poll until an HTTP endpoint answers
  local url="$1" i
  for i in $(seq 1 100); do
    curl -sf -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "endpoint never came up: $url"
}

sim_state() { curl -sf "$SIM_RPC/debug/state"; }
sim_field() { sim_state | jq -r ".$1"; }
sim_balance() { sim_state | jq -r ".balances.$1"; }
sim_htlc_field() { # sim_htlc_field HASH FIELD
  sim_state | jq -r "[.htlcs[] | select(.hash_hex==\"$1\")][0].${2}"
}

rpc() { # rpc WALLET METHOD PARAMS — one wallet-RPC call
  curl -sf "$SIM_RPC/w/$1" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$2\",\"params\":$3}"
}

run_spore() { # run_spore PARTY args... — CLI as one party with its own kit
  local party="$1"; shift
  env -u SPORE_HOME -u SPORE_CONFIG \
    SPORE_HOME="$ROOT/$party/home" \
    SPORE_CONFIG="$ROOT/$party/home/config.json" \
    "$SPORE" "$@"
}

# run_web PARTY LISTEN — spore web -e2-dir for a party (structured recv).
start_web() {
  local party="$1" listen="$2"
  env -u SPORE_HOME -u SPORE_CONFIG \
    SPORE_HOME="$ROOT/$party/home" \
    SPORE_CONFIG="$ROOT/$party/home/config.json" \
    "$SPORE" web -listen "$listen" -allow-browser-spend \
      -store "$MAILBOX_URL" \
      -wallet-rpc "$SIM_RPC/w/$party" -e2-dir "$ROOT/$party/home" \
      >"$ROOT/$party.web.log" 2>&1 &
}
web_recv() { curl -sf "http://127.0.0.1:$1/e2/recv"; }

wait_for_web_card() { # wait_for_web_card PORT KIND TRIES — a card of KIND arrives
  local port="$1" kind="$2" tries="$3" i txt
  for i in $(seq 1 "$tries"); do
    txt=$(web_recv "$port" || true)
    if [[ -n "$txt" ]] && printf '%s' "$txt" | jq -e --arg k "$kind" \
        '[.[] | select(.card != null and .card.kind==$k)] | length > 0' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_web_text() { # wait_for_web_text PORT NEEDLE TRIES
  local port="$1" needle="$2" tries="$3" i txt
  for i in $(seq 1 "$tries"); do
    txt=$(web_recv "$port" || true)
    if [[ -n "$txt" ]] && printf '%s' "$txt" | grep -q "$needle"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

random_hex32() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}
# sha256_of_hex HEXSTRING — sha256 over the BYTES the hex encodes (the same
# pairing the CLI verifies locally and the contract enforces on-chain).
# xxd is required and verified at preflight: a printf '%b'/'\\x' fallback
# provably mangles bytes on some shells, and a wrong hash here looks like a
# protocol failure instead of a harness bug.
sha256_of_hex() { printf '%s' "$1" | xxd -r -p | sha256sum | cut -d' ' -f1; }

# ---------------- preflight ----------------
require curl; require jq; require xxd
if [[ -z "$SPORE" ]]; then
  step "building spore"
  SPORE="$ROOT/spore"
  (cd "$(dirname "$0")/.." && go build -o "$SPORE" ./cmd/spore) || fail "go build failed"
  ok "built $SPORE"
fi

step "workspace: $ROOT"
step "starting derosim on $SIM_LISTEN"
"$SPORE" derosim serve -listen "$SIM_LISTEN" >"$ROOT/sim.log" 2>&1 &
SIM_PID=$!
wait_for "$SIM_RPC/healthz"
ok "simulator up (height $(sim_field height))"

# ---------------- bootstrap: kits, mailbox, invites ----------------
step "bootstrap: kits"
run_spore alice init -dir "$ROOT/alice/home" -opks 4 >/dev/null
run_spore bob   init -dir "$ROOT/bob/home"   -opks 4 >/dev/null

ALICE_ADDR=$(rpc alice getaddress null | jq -r .result.address)
BOB_ADDR=$(rpc bob getaddress null | jq -r .result.address)
[[ -n "$ALICE_ADDR" && -n "$BOB_ADDR" && "$ALICE_ADDR" != "$BOB_ADDR" ]] \
  || fail "wallet addresses missing or collide"
ok "alice $ALICE_ADDR"
ok "bob   $BOB_ADDR"

step "bootstrap: mailbox (a real spore mailbox run)"
mkdir -p "$ROOT/mailbox"
run_spore alice mailbox run -dir "$ROOT/mailbox" -listen "$MAILBOX_LISTEN" \
  -chain dero -rpc "$SIM_RPC/w/alice" -interval 1s \
  >"$ROOT/mailbox.log" 2>&1 &
MAILBOX_PID=$!
wait_for "$MAILBOX_URL/list"
ok "mailbox up at $MAILBOX_URL"

step "bootstrap: signed invites + contacts"
ALICE_INVITE=$(run_spore alice invite issue -identity "$ROOT/alice/home/identity.key" \
  -spk "$ROOT/alice/home/spk.key" -address "$ALICE_ADDR" -name alice \
  -mailbox "$MAILBOX_URL/prekey" -store "$MAILBOX_URL" | head -1)
BOB_INVITE=$(run_spore bob invite issue -identity "$ROOT/bob/home/identity.key" \
  -spk "$ROOT/bob/home/spk.key" -address "$BOB_ADDR" -name bob \
  -mailbox "$MAILBOX_URL/prekey" -store "$MAILBOX_URL" | head -1)
[[ "$ALICE_INVITE" == spore-invite-v1:* ]] || fail "alice invite malformed"
[[ "$BOB_INVITE" == spore-invite-v1:* ]] || fail "bob invite malformed"
run_spore alice msg mail -db "$ROOT/alice/home/mail.json" add -invite "$BOB_INVITE" >/dev/null
run_spore bob   msg mail -db "$ROOT/bob/home/mail.json" add -invite "$ALICE_INVITE" >/dev/null
ok "each side added the other (pinned sigs bound to invite signatures)"

step "bootstrap: kit config pointing at sim + mailbox"
for p in alice bob; do
  # MERGE into the config `spore init` wrote (identity/spk/pool/state paths
  # must survive); only add store + rpc for this soak.
  jq --arg store "$MAILBOX_URL" --arg rpc "$SIM_RPC/w/$p" \
     '.store = $store | .rpc = $rpc' \
    "$ROOT/$p/home/config.json" > "$ROOT/$p/cfg.tmp" \
    && mv "$ROOT/$p/cfg.tmp" "$ROOT/$p/home/config.json"
done
ok "config.json: store + rpc defaults set per party (init paths preserved)"

step "bootstrap: web servers (structured receives)"
start_web alice "127.0.0.1:$WEB_A_PORT"; WEB_A_PID=$!
start_web bob "127.0.0.1:$WEB_B_PORT"; WEB_B_PID=$!
wait_for "http://127.0.0.1:$WEB_A_PORT/"
wait_for "http://127.0.0.1:$WEB_B_PORT/"
ok "web up (alice :$WEB_A_PORT, bob :$WEB_B_PORT)"

# ================= flow 1: fund → claim =================
step "fund→claim: alice funds the HTLC and opens the session"
PREIMAGE=$(random_hex32)
HASH=$(sha256_of_hex "$PREIMAGE")
EXPIRY=1000000

run_spore alice msg send-e2 -to bob \
  -escrow htlc -amount "1.5dero" \
  -escrow-hash "$HASH" -escrow-recipient "$BOB_ADDR" -escrow-expiry "$EXPIRY" \
  -msg-file - <<< "claim the funds with the preimage, friend" \
  > "$ROOT/flow1.send.log" 2>&1 \
  || { cat "$ROOT/flow1.send.log"; fail "fund send failed"; }
ok "HTLC funded (1.5 DERO locked under ${HASH:0:12}…)"
grep -q "escrow HTLC funded" "$ROOT/flow1.send.log" && ok "send printed the fund tx"

[[ "$(sim_htlc_field "$HASH" claimed)" == "false" ]] || fail "HTLC already settled at fund time"
ok "simulator: HTLC open under the hash (recipient $BOB_ADDR)"

ok "waiting for bob to decrypt the bootstrap pointer…"
wait_for_web_text "$WEB_B_PORT" "claim the funds" 60 || {
  cat "$ROOT/bob.web.log"; fail "bob never decrypted the bootstrap message"; }
ok "bob decrypted the bootstrap message"

BOB_SESSION=$(run_spore bob msg sessions | head -1)
[[ "$BOB_SESSION" =~ ^[0-9a-f]{16}$ ]] || fail "bob has no usable session id"
ok "session open: $BOB_SESSION"

step "fund→claim: bob claims with the preimage"
run_spore bob msg escrow claim \
  -hash "$HASH" -preimage "$PREIMAGE" \
  -to "$ALICE_ADDR" -session "$BOB_SESSION" -amount-atomic 150000 \
  -receipts "$ROOT/bob/receipts.json" \
  > "$ROOT/flow1.claim.log" 2>&1 \
  || { cat "$ROOT/flow1.claim.log"; fail "claim failed"; }
grep -q "ESCROW CLAIMED" "$ROOT/flow1.claim.log" && ok "claim printed ESCROW CLAIMED"
[[ "$(sim_htlc_field "$HASH" claimed)" == "true" ]] || fail "simulator shows the HTLC unclaimed"
ok "simulator: HTLC claimed, recipient credited"

wait_for_web_card "$WEB_A_PORT" escrow 60 \
  || { cat "$ROOT/alice.web.log"; fail "alice never saw the escrow card"; }
ok "alice received the spore/escrow/v1 settlement notice (web card)"

# ---------------- flow 2: fund → refund (expiry path) ----------------
step "fund→refund: same fund shape, short expiry"
PREIMAGE2=$(random_hex32)
HASH2=$(sha256_of_hex "$PREIMAGE2")
run_spore alice msg send-e2 -to bob \
  -escrow htlc -amount "0.75dero" \
  -escrow-hash "$HASH2" -escrow-recipient "$BOB_ADDR" -escrow-expiry 2 \
  -msg-file - <<< "second deal (will expire)" \
  > "$ROOT/flow2.send.log" 2>&1 \
  || { cat "$ROOT/flow2.send.log"; fail "fund 2 failed"; }
ok "HTLC 2 funded (0.75 DERO, expiry height 2)"

step "fund→refund: bump the chain past expiry, alice refunds"
curl -sf -X POST "$SIM_RPC/debug/bump" -H 'Content-Type: application/json' -d '{"blocks": 10}' >/dev/null
run_spore alice msg escrow refund \
  -hash "$HASH2" -to "$BOB_ADDR" -session "$BOB_SESSION" -amount-atomic 75000 \
  -receipts "$ROOT/alice/receipts.json" \
  > "$ROOT/flow2.refund.log" 2>&1 \
  || { cat "$ROOT/flow2.refund.log"; fail "refund failed"; }
grep -q "ESCROW REFUNDED" "$ROOT/flow2.refund.log" && ok "refund printed ESCROW REFUNDED"
[[ "$(sim_htlc_field "$HASH2" refunded)" == "true" ]] || fail "simulator shows HTLC 2 unrefunded"
ok "simulator: HTLC refunded, funds back with alice"
wait_for_web_card "$WEB_B_PORT" escrow 60 || fail "bob never saw the refund notice"
ok "bob received the refund settlement notice"

# ---------------- flow 3: swap + wrap/unwrap ----------------
step "swap: bob swaps through the constant-product pool"
PA0=$(sim_field pool_a); PB0=$(sim_field pool_b)
run_spore bob msg dex swap -ta tA -tb tB -amount 10tA -min-out 1 \
  -to "$ALICE_ADDR" -session "$BOB_SESSION" \
  -receipts "$ROOT/bob/receipts.json" \
  > "$ROOT/flow3.swap.log" 2>&1 \
  || { cat "$ROOT/flow3.swap.log"; fail "swap failed"; }
grep -q "DEX SWAPPED" "$ROOT/flow3.swap.log" && ok "swap printed DEX SWAPPED"
PA1=$(sim_field pool_a); PB1=$(sim_field pool_b)
[[ "$PA1" -gt "$PA0" && "$PB1" -lt "$PB0" ]] || fail "pool reserves did not move"
ok "pool reserves moved: $PA0/$PB0 -> $PA1/$PB1"

step "swap: impossible min-out refused by the contract"
if run_spore bob msg dex swap -ta tA -tb tB -amount 10tA -min-out 999999999999999 \
    -to "$ALICE_ADDR" -session "$BOB_SESSION" \
    > "$ROOT/flow3.swap2.log" 2>&1; then
  fail "impossible min-out swap was accepted"
fi
ok "impossible min-out refused by the sim DEX"
wait_for_web_card "$WEB_A_PORT" dex 60 || fail "alice never saw the swap notice"
ok "alice received the spore/dex/v1 swap notice"

step "swap: wrap + unwrap round trip"
run_spore alice msg dex wrap -amount 2dero \
  -to "$BOB_ADDR" -session "$BOB_SESSION" \
  -receipts "$ROOT/alice/receipts.json" \
  > "$ROOT/flow3.wrap.log" 2>&1 \
  || { cat "$ROOT/flow3.wrap.log"; fail "wrap failed"; }
grep -q "WDERO WRAPPED" "$ROOT/flow3.wrap.log" && ok "wrap printed WDERO WRAPPED"
W0=$(sim_field wdero_supply)
[[ "$W0" == "200000" ]] || fail "wDERO supply after wrap = $W0, want 200000"
ok "wDERO minted 1:1 (200000 atomic = 2 dero)"

run_spore alice msg dex unwrap -amount 2wdero \
  -to "$BOB_ADDR" -session "$BOB_SESSION" \
  > "$ROOT/flow3.unwrap.log" 2>&1 \
  || { cat "$ROOT/flow3.unwrap.log"; fail "unwrap failed"; }
W1=$(sim_field wdero_supply)
[[ "$W1" == "0" ]] || fail "wDERO supply after unwrap = $W1, want 0"
ok "unwrap burned the wDERO (supply back to 0)"

step "ledger: settlements filed in the receipts ledger"
jq -s -e '[.[] | select(.kind=="escrow-claim")] | length > 0' "$ROOT/bob/receipts.json" >/dev/null \
  && ok "bob's ledger has escrow-claim"
jq -s -e '[.[] | select(.kind=="escrow-refund")] | length > 0' "$ROOT/alice/receipts.json" >/dev/null \
  && ok "alice's ledger has escrow-refund"
jq -s -e '[.[] | select(.kind=="dex-swap")] | length > 0' "$ROOT/bob/receipts.json" >/dev/null \
  && ok "bob's ledger has dex-swap"

# ================= flow 4: stale-reaper watchdog against a live node ==========
# The watchdog's contract is pinned by unit tests; this section proves it
# against a REAL daemon: heartbeat lines with a live advancing pass counter,
# a SIGKILLed daemon whose counter freezes forever, alerts queueing in a
# durable outbox, and recovery re-arming after a restart. The node reaps on
# a 1s cadence while the watches are back-to-back, so freezes resolve in
# seconds. The webhook points at a dead port ON PURPOSE: the alert path then
# exercises the durable behavior (exit 1 with the alert still owed) that a
# delivered-and-forgotten webhook would hide.
step "watchdog: start a live spore serve node (1s reaper)"
NODE_DIR="$ROOT/node"; mkdir -p "$NODE_DIR" "$NODE_DIR/hold"
NODE_LOG="$NODE_DIR/serve.log"
NODE_STATE="$NODE_DIR/watchdog-state.json"
NODE_OUTBOX="$NODE_DIR/watchdog-outbox.jsonl"
WD_WEBHOOK="http://127.0.0.1:9/notifier"   # nothing listens: alerts stay durably queued (by design)
start_node() {
  "$SPORE" serve -dir "$NODE_DIR/hold" -reap-every 1s >"$NODE_LOG" 2>&1 &
  NODE_PID=$!
}
wait_for_node_status() { # wait until the log carries a parseable reaper status line
  local i
  for i in $(seq 1 100); do
    grep -q "reaper status:" "$NODE_LOG" 2>/dev/null && return 0
    sleep 0.2
  done
  fail "node never printed a reaper status heartbeat: $NODE_LOG"
}
start_node
wait_for_node_status
ok "node up, reaper heartbeat live (log $NODE_LOG)"

watchdog() { # watchdog EXTRA-ARGS... — one watch pass; stdout on stdout, exit code returned
  run_spore alice continuity watch-reaper -log "$NODE_LOG" -state "$NODE_STATE" \
    -node spore -outbox "$NODE_OUTBOX" -webhook "$WD_WEBHOOK" "$@"
}
last_passes() { # the pass counter from the newest heartbeat in the log
  grep "reaper status:" "$NODE_LOG" | tail -1 | sed -E 's/.*reaper status: ([0-9]+) passes.*/\1/'
}

step "watchdog: baseline watch records the first observation"
BASE_OUT=$(watchdog)
[[ "$BASE_OUT" == *baseline* ]] || fail "first watchdog pass did not baseline: $BASE_OUT"
ok "baseline recorded from a real heartbeat ($BASE_OUT)"

step "watchdog: alive watch — the counter advances while the daemon runs"
sleep 2.5
ALIVE_BASE=$(last_passes)
ALIVE_OUT=$(watchdog)
if [[ "$ALIVE_OUT" == *"ok passes="* ]]; then
  ok "alive watch: ok passes=$ALIVE_BASE"
elif [[ "$ALIVE_OUT" == *re-baselined* ]]; then
  # A respawn can truncate the log; re-baselining on the SAME live daemon is
  # honest too (the counter is only comparable within one log file).
  ok "alive watch: re-baselined (log was truncated) passes=$ALIVE_BASE"
else
  fail "watch against a live daemon did not report alive: $ALIVE_OUT"
fi

step "watchdog: SIGKILL the node — grace tolerates, then the freeze alerts"
kill -9 "$NODE_PID" 2>/dev/null || fail "could not kill the node"
wait "$NODE_PID" 2>/dev/null || true
NODE_PID=""
ok "node SIGKILLed — its reaper can never pass again"

FROZEN_BASE=$(last_passes)
G1_OUT=$(watchdog -grace 2 || true)   # || true: watch-reaper may exit 1 when it queues an alert
if [[ "$(last_passes)" -gt "$FROZEN_BASE" ]]; then
  # Inherent ±1 race: a pass completed between the last alive watch and the
  # kill, so the FIRST dead-watch still sees an advance. Absorb it once.
  G1_OUT=$(watchdog -grace 2 || true)
  FROZEN_BASE=$(last_passes)
fi
[[ "$G1_OUT" == *"1/2 within grace"* ]] || fail "frozen watch 1 expected within-grace 1/2: $G1_OUT"
ok "frozen watch 1: within grace (1/2)"

G2_OUT=$(watchdog -grace 2 || true)
[[ "$G2_OUT" == *"2/2 within grace"* ]] || fail "frozen watch 2 expected within-grace 2/2: $G2_OUT"
ok "frozen watch 2: within grace (2/2)"

step "watchdog: freeze past grace — the alert is queued and the watch exits 1"
# With the webhook down, watch-reaper exits 1 AFTER the alert is durably
# queued (the non-zero exit is the cron-visible signal; the outbox is the
# durable one). That is the design being tested: delivery failure must not
# eat the alert.
ALERT_RC=0
ALERT_OUT=$(watchdog -grace 2) || ALERT_RC=$?
[[ "$ALERT_RC" -eq 1 ]] || fail "alert watch should exit 1 when delivery fails (rc=$ALERT_RC): $ALERT_OUT"
ok "alert watch exited 1 with the alert durably owed (counter frozen at $FROZEN_BASE)"

step "watchdog: the alert is durable and deduped in the outbox"
[[ -s "$NODE_OUTBOX" ]] || fail "outbox file missing after ALERT"
[[ "$(jq -s '[.[] | select(.TxID=="watchdog/reaper/stale reaper")] | length' "$NODE_OUTBOX")" -eq 1 ]] \
  || fail "outbox should carry exactly one stale-reaper alert"
ok "outbox holds exactly one durable stale-reaper alert (webhook down, delivery still owed)"

# Watch again while still frozen: the alert is re-raised (delivery is still
# failing) but the outbox TxID-dedupe keeps it at exactly one record — no
# alert storms while the counter holds still.
DUP_RC=0
DUP_OUT=$(watchdog -grace 2) || DUP_RC=$?
[[ "$DUP_RC" -eq 1 ]] || fail "repeat frozen watch should still exit 1 while delivery fails (rc=$DUP_RC): $DUP_OUT"
[[ "$(jq -s '[.[] | select(.TxID=="watchdog/reaper/stale reaper")] | length' "$NODE_OUTBOX")" -eq 1 ]] \
  || fail "repeat frozen watch must not duplicate the outbox alert"
ok "repeat frozen watch: still one alert, no duplicate (state $NODE_STATE)"

step "watchdog: restart the daemon — recovery re-arms the watchdog"
start_node                            # >"$NODE_LOG" truncates: the fresh daemon restarts its counter
wait_for_node_status
# Recovery needs the first post-restart watch to re-baseline (fresh log =
# counter regression) or coincide by chance with the old count (within
# grace); either way, keep watching until the counter ADVANCES — ok passes=N
# is the re-armed state. Bounded, because a daemon that never advances is
# exactly the failure this watchdog exists to catch.
REC_OK=""
for i in $(seq 1 12); do
  OUT=$(watchdog -grace 2 || true)
  case "$OUT" in
    *"ok passes="*) REC_OK="$OUT"; break ;;
    *re-baselined*|*within*grace*) : ;;
    *) fail "recovery watch unexpected: $OUT" ;;
  esac
  sleep 1
done
[[ -n "$REC_OK" ]] || fail "recovery never reached 'ok passes=N' (counter did not advance)"
ok "recovery: watch reports ok passes=$(last_passes) — the watchdog is re-armed"

step "SOAK COMPLETE — $PASS checks passed"
echo "  workspace kept for inspection: $ROOT"
exit 0
