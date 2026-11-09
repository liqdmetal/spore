#!/usr/bin/env bash
# scripts/rehearsal-continuity-checkin.sh — live rehearsal of continuity
# check-in messages over an E2 thread, with REAL spore CLI processes:
#
#   vault      owner seals a continuity vault; the holder receives a copy
#              (seq 0), exactly as a recipient would receive the file
#   thread     owner opens a real E2 session (bundle pulled from the relay's
#              /prekey), holder runs `msg recv-e2 -continuity-vault`
#   check-in   owner runs `continuity check-in -emit` + `msg checkin`; the
#              holder's copy advances FROM THE INBOX (seq 1), still verifies,
#              and ends byte-identical to the owner's file
#   refusal    a different vault's check-in over the same session is refused
#              and leaves the holder's file byte-identical; the next genuine
#              check-in still lands
#   chat       an ordinary message after the refusals still arrives, and it
#              does not move the vault
#
# Everything is loopback and offline. The carrier is the in-repo wallet-RPC
# simulator (`spore derosim serve`), not the DERO network; the relay hop is a
# real `spore mailbox run`. Adopting a check-in needs no private key, so the
# sealed vault uses a throwaway recipient key: this rehearsal proves
# transport, inbox adoption and refusal safety, NOT release decryption (the
# continuity test suite covers that).
#
# Every assertion is checked; any failure aborts naming the step and keeps
# the workspace for inspection (SPORE_REHEARSAL_KEEP=1 always keeps it).
# Usage: scripts/rehearsal-continuity-checkin.sh [path-to-spore-binary]
set -euo pipefail

SPORE="${1:-}"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spore-checkin.XXXXXX")"
KEEP="${SPORE_REHEARSAL_KEEP:-0}"
PASS=0
STATUS=0

SIM_PID=""
MAILBOX_PID=""
RECV_PID=""

cleanup() {
  STATUS=$?
  for pid in "$RECV_PID" "$MAILBOX_PID" "$SIM_PID"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ $STATUS -eq 0 && "$KEEP" != "1" ]]; then
    rm -rf "$ROOT"
  else
    printf '\nworkspace kept: %s\n' "$ROOT"
  fi
}
trap cleanup EXIT

# ---------------- helpers (all defined before use) ----------------
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
fail() {
  printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2
  for f in sim.log mailbox.log a-send.log b-recv.log; do
    [[ -f "$ROOT/$f" ]] && { printf '\n--- %s (tail) ---\n' "$f"; tail -15 "$ROOT/$f"; }
  done
  exit 1
}

require() { command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"; }

# pick_port — a loopback port nothing is listening on (a stale server from a
# previous run must never answer for this one: it would look like silent
# message loss instead of a harness collision).
pick_port() {
  local p i
  for i in $(seq 1 40); do
    p=$((21000 + RANDOM % 8000))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      printf '%s' "$p"
      return 0
    fi
  done
  return 1
}

wait_http() { # wait_http URL — poll until it answers (5s budget)
  local url=$1 i
  for i in $(seq 1 100); do
    curl -sf -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.05
  done
  return 1
}

wait_log() { # wait_log FILE PATTERN [TRIES] — poll (1s each) for a log line
  local f=$1 pat=$2 n="${3:-60}" i
  for i in $(seq 1 "$n"); do
    grep -q -- "$pat" "$f" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

random_hex32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    openssl dgst -sha256 "$1" | sed 's/.*= //'
  fi
}

checkins_count() { # checkins_count VAULT — the status line's checkins=N
  "$SPORE" continuity status -vault "$1" | grep -o 'checkins=[0-9]*' | cut -d= -f2
}

# ---------------- preflight ----------------
require curl
if [[ -z "$SPORE" ]]; then
  require go
  step "building spore"
  SPORE="$ROOT/spore"
  (cd "$(dirname "$0")/.." && go build -o "$SPORE" ./cmd/spore) || fail "go build failed"
  ok "built $SPORE"
fi
[[ -x "$SPORE" ]] || fail "not executable: $SPORE"

SIM_PORT="$(pick_port)" || fail "no free port for derosim"
MAIL_PORT="$(pick_port)" || fail "no free port for the mailbox"
while [[ "$MAIL_PORT" == "$SIM_PORT" ]]; do MAIL_PORT="$(pick_port)" || fail "no free port for the mailbox"; done
SIM_URL="http://127.0.0.1:$SIM_PORT"
MAIL_URL="http://127.0.0.1:$MAIL_PORT"
step "workspace: $ROOT"
ok "spore: $("$SPORE" -version 2>&1 | head -1)"

# ---------------- carrier + relay ----------------
step "carrier: derosim on 127.0.0.1:$SIM_PORT"
"$SPORE" derosim serve -listen "127.0.0.1:$SIM_PORT" >"$ROOT/sim.log" 2>&1 &
SIM_PID=$!
wait_http "$SIM_URL/healthz" || fail "derosim did not come up"
ok "carrier up (wallet RPC /w/alice and /w/bob)"

step "relay: real spore mailbox on 127.0.0.1:$MAIL_PORT"
"$SPORE" mailbox run -dir "$ROOT/mailbox" -listen "127.0.0.1:$MAIL_PORT" \
  -chain dero -rpc "$SIM_URL/w/alice" -interval 1s >"$ROOT/mailbox.log" 2>&1 &
MAILBOX_PID=$!
wait_http "$MAIL_URL/list" || fail "mailbox did not come up"
ok "relay up (body store + /prekey + chain scan)"

# ---------------- two identities ----------------
step "identities: owner (alice) and holder (bob)"
"$SPORE" init -dir "$ROOT/a" -opks 4 -store "$MAIL_URL" >"$ROOT/a-init.log" 2>&1 || fail "init owner"
"$SPORE" init -dir "$ROOT/b" -opks 4 -store "$MAIL_URL" >"$ROOT/b-init.log" 2>&1 || fail "init holder"
A_ADDR="$(curl -sf "$SIM_URL/w/alice" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":null}' |
  sed -n 's/.*"address":"\([^"]*\)".*/\1/p')"
B_ADDR="$(curl -sf "$SIM_URL/w/bob" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"getaddress","params":null}' |
  sed -n 's/.*"address":"\([^"]*\)".*/\1/p')"
[[ -n "$A_ADDR" && -n "$B_ADDR" && "$A_ADDR" != "$B_ADDR" ]] ||
  fail "wallet addresses missing or colliding (a='$A_ADDR' b='$B_ADDR')"
BOB_SIG="$(sed -n 's/.*"pinned_sig": *"\([0-9a-f]*\)".*/\1/p' "$ROOT/b/identity-card.json")"
[[ -n "$BOB_SIG" ]] || fail "holder pinned sig not found in identity-card.json"
ok "owner $A_ADDR"
ok "holder $B_ADDR (pinned sig ${BOB_SIG:0:16}…)"

step "holder publishes single-use prekey bundles to the relay"
"$SPORE" prekeybatch push -in "$ROOT/b/batch.json" -mailbox "$MAIL_URL" >"$ROOT/b-push.log" 2>&1 ||
  fail "prekeybatch push"
ok "relay /prekey now serves the holder's bundles"

# ---------------- vault ----------------
step "vault: owner seals one, holder gets a copy (seq 0)"
printf 'sealed continuity payload\n' >"$ROOT/payload.txt"
RECIPIENT="$(random_hex32)"
"$SPORE" continuity create -owner-key "$ROOT/a/identity.key" -recipient-pub "$RECIPIENT" \
  -file "$ROOT/payload.txt" -out "$ROOT/a/vault.json" -interval 24h -grace 24h \
  >"$ROOT/a-vault.log" 2>&1 || fail "continuity create"
cp "$ROOT/a/vault.json" "$ROOT/b/vault.json"
BEFORE="$("$SPORE" continuity status -vault "$ROOT/b/vault.json")"
echo "   $BEFORE"

# ---------------- thread ----------------
step "holder starts the live inbox with -continuity-vault"
"$SPORE" msg recv-e2 -identity "$ROOT/b/identity.key" -spk "$ROOT/b/spk.key" \
  -opk-pool "$ROOT/b/opk-pool.json" -store "$MAIL_URL" -rpc "$SIM_URL/w/bob" \
  -state-dir "$ROOT/b/state" -state-key "$ROOT/b/state.key" \
  -maildb "$ROOT/b/mail.json" -interval 1s \
  -continuity-vault "$ROOT/b/vault.json" >"$ROOT/b-recv.log" 2>&1 &
RECV_PID=$!
sleep 1

step "owner opens the E2 session (bundle fetched through the relay)"
printf 'hello holder\n' | "$SPORE" msg send-e2 -to "$B_ADDR" -identity "$ROOT/a/identity.key" \
  -bundle-url "$MAIL_URL/prekey" -pinned-sig "$BOB_SIG" -store "$MAIL_URL" \
  -rpc "$SIM_URL/w/alice" -state-dir "$ROOT/a/state" -state-key "$ROOT/a/state.key" \
  -maildb "$ROOT/a/mail.json" >"$ROOT/a-send.log" 2>&1 || fail "opening send-e2"
wait_log "$ROOT/b-recv.log" "hello holder" 60 || fail "holder never decrypted the opening message"
ok "holder decrypted the opening message from the chain"

SID="$("$SPORE" msg sessions -state-dir "$ROOT/a/state" -state-key "$ROOT/a/state.key" | head -1)"
SID_B="$("$SPORE" msg sessions -state-dir "$ROOT/b/state" -state-key "$ROOT/b/state.key" | head -1)"
[[ -n "$SID" && "$SID" == "$SID_B" ]] || fail "session ids differ (a='$SID' b='$SID_B')"
ok "one session on both sides: $SID"

# ---------------- check-in, refusal, check-in ----------------
step "check-in: owner signs and sends; holder adopts from the inbox"
sleep 2 # the signed chain advances in whole seconds
"$SPORE" continuity check-in -vault "$ROOT/a/vault.json" -owner-key "$ROOT/a/identity.key" \
  -emit "$ROOT/checkins1.json" >"$ROOT/a-checkin1.log" 2>&1 || fail "continuity check-in"
"$SPORE" msg checkin -to "$B_ADDR" -session "$SID" -checkins "$ROOT/checkins1.json" \
  -store "$MAIL_URL" -rpc "$SIM_URL/w/alice" -state-dir "$ROOT/a/state" \
  -state-key "$ROOT/a/state.key" -maildb "$ROOT/a/mail.json" >"$ROOT/a-msgcheckin1.log" 2>&1 ||
  fail "msg checkin"
wait_log "$ROOT/b-recv.log" "adopted: +1 (seq 1" 60 || fail "holder did not adopt check-in 1"
AFTER="$(checkins_count "$ROOT/b/vault.json")"
[[ "$AFTER" == "2" ]] || fail "holder vault after adoption: checkins=$AFTER (want 2)"
"$SPORE" continuity verify -vault "$ROOT/b/vault.json" >/dev/null 2>&1 ||
  fail "adopted holder vault does not verify"
ok "holder copy advanced seq 0 -> seq 1 from the inbox and verifies"

step "refusal: another vault's check-in must not touch the holder copy"
printf '%s\n' "$(random_hex32)" >"$ROOT/foreign-owner.key"
"$SPORE" continuity create -owner-key "$ROOT/foreign-owner.key" -recipient-pub "$RECIPIENT" \
  -file "$ROOT/payload.txt" -out "$ROOT/foreign-vault.json" >/dev/null 2>&1 ||
  fail "foreign vault create"
sleep 2
"$SPORE" continuity check-in -vault "$ROOT/foreign-vault.json" -owner-key "$ROOT/foreign-owner.key" \
  -emit "$ROOT/foreign-checkins.json" >/dev/null 2>&1 || fail "foreign check-in"
SHA_BEFORE="$(sha256_file "$ROOT/b/vault.json")"
"$SPORE" msg checkin -to "$B_ADDR" -session "$SID" -checkins "$ROOT/foreign-checkins.json" \
  -store "$MAIL_URL" -rpc "$SIM_URL/w/alice" -state-dir "$ROOT/a/state" \
  -state-key "$ROOT/a/state.key" -maildb "$ROOT/a/mail.json" >/dev/null 2>&1 ||
  fail "foreign msg checkin send"
wait_log "$ROOT/b-recv.log" "refused check-in message" 60 || fail "foreign envelope was not refused"
[[ "$(sha256_file "$ROOT/b/vault.json")" == "$SHA_BEFORE" ]] ||
  fail "refusal modified the holder vault"
ok "refused loudly; holder vault is byte-identical"

step "recovery: the next genuine check-in still lands"
sleep 2
"$SPORE" continuity check-in -vault "$ROOT/a/vault.json" -owner-key "$ROOT/a/identity.key" \
  -emit "$ROOT/checkins2.json" >/dev/null 2>&1 || fail "check-in 2"
"$SPORE" msg checkin -to "$B_ADDR" -session "$SID" -checkins "$ROOT/checkins2.json" \
  -store "$MAIL_URL" -rpc "$SIM_URL/w/alice" -state-dir "$ROOT/a/state" \
  -state-key "$ROOT/a/state.key" -maildb "$ROOT/a/mail.json" >/dev/null 2>&1 ||
  fail "msg checkin 2"
wait_log "$ROOT/b-recv.log" "adopted: +1 (seq 2" 60 || fail "holder did not adopt check-in 2"
FINAL="$(checkins_count "$ROOT/b/vault.json")"
[[ "$FINAL" == "3" ]] || fail "holder vault after check-in 2: checkins=$FINAL (want 3)"
cmp -s "$ROOT/a/vault.json" "$ROOT/b/vault.json" ||
  fail "owner and holder vaults differ after live adoption"
DUE_A="$("$SPORE" continuity status -vault "$ROOT/a/vault.json" | grep -o 'due=[^ ]*')"
DUE_B="$("$SPORE" continuity status -vault "$ROOT/b/vault.json" | grep -o 'due=[^ ]*')"
[[ -n "$DUE_A" && "$DUE_A" == "$DUE_B" ]] || fail "deadlines differ (owner '$DUE_A' holder '$DUE_B')"
ok "adopted seq 2; holder file is byte-identical and reports the owner's $DUE_A"

step "chat: an ordinary message still arrives and does not move the vault"
printf 'still talking\n' | "$SPORE" msg reply-e2 -to "$B_ADDR" -session "$SID" \
  -store "$MAIL_URL" -rpc "$SIM_URL/w/alice" -state-dir "$ROOT/a/state" \
  -state-key "$ROOT/a/state.key" >"$ROOT/a-reply.log" 2>&1 || fail "reply-e2"
wait_log "$ROOT/b-recv.log" "still talking" 60 || fail "ordinary message after refusals was lost"
[[ "$(checkins_count "$ROOT/b/vault.json")" == "3" ]] || fail "a chat message moved the vault"
ok "chat delivered after the refusals; vault unchanged"

step "hygiene"
if grep -q 'continuity-checkins/v1' "$ROOT/b/mail.json" 2>/dev/null; then
  fail "a check-in envelope was indexed as a chat body"
fi
ok "no check-in envelope in the mail index"
ADOPTED="$(grep -c 'adopted:' "$ROOT/b-recv.log")"
[[ "$ADOPTED" == "2" ]] || fail "expected 2 adoptions in the inbox log, saw $ADOPTED"
ok "inbox log shows exactly 2 adoptions"

printf '\n\033[32mLIVE REHEARSAL PASSED\033[0m (%d checks)\n' "$PASS"
printf '  carrier: derosim %s   relay: spore mailbox %s\n' "$SIM_URL" "$MAIL_URL"
printf '  owner %s -> holder %s, session %s\n' "$A_ADDR" "$B_ADDR" "$SID"
printf '  holder vault: checkins=1 -> checkins=2 -> checkins=3, verified, byte-identical\n'
