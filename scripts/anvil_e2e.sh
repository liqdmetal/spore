#!/usr/bin/env bash
# scripts/anvil_e2e.sh — the v0.9.0 EVM path, end to end, on a LOCAL Anvil.
#
# Proves the two-party MyceliumMailbox arc with the REAL CLI and NOTHING
# external: no funded key, no faucet, no testnet RPC, no jq, no network. It
# is the local mirror of scripts/sepolia_rehearsal.sh — that script needs two
# funded testnet keys and the public relays; this one needs only `anvil` on
# PATH and spins the whole thing up itself:
#
#   1. start a private anvil with its well-known unlocked dev accounts
#   2. deploy the PINNED tools/mycelium.bin through the real
#      `spore contract deploy-mycelium` path (the exact v0.9.0 deploy path)
#   3. run one local mailbox that is both the E2 body store (/body, /put) and
#      the prekey authority (/prekey, /prekey-batch)
#   4. A → B `spore msg send-e2 -mailbox <deployed>` (bundle discovered by the
#      real /prekey pop, pinned-sig still verified)
#   5. B `spore msg recv-e2` decrypts, acks, and chain.Watch auto-burns
#   6. assert compost: a FRESH-STATE rescan returns the message as absent, and
#      (with foundry's `cast`) the on-chain read(to, seq) is empty
#
# Why this exists: TestMailboxLiveAnvil proves the same on-chain round trip but
# SKIPS unless an anvil + a deployed mailbox already exist, and its fallback
# deploy shelled out to `forge create` (needs solc). This harness makes the
# proof reproducible on any dev box — and wires the deploy to the pinned
# bytecode the release actually ships, so it cannot drift from what Base gets.
#
# With -r FILE it also writes the RECEIPT the fill consumes: the key=value file
# scripts/release-fill.sh takes as -in, built from what this run observed (a
# real mailbox address, a real creation txid, the deployer, a real deliver txid,
# and the BURN txid — recovered from chain state, because the receive path
# issues the burn and deliberately does not log it) and measured (the runbook's
# own `spore contract estimate`, run the way §3 says to run it). Release day's
# last hand-work step is transcription — hex strings from a terminal into a
# receipt — and a mistyped mailbox address ships as every user's default mailbox
# while satisfying the receipt gate. So the proof writes the file, and
# release-fill.sh checks it (and refuses a receipt naming anvil's dev accounts
# unless it is told the point is a local proof).
#
# What it does NOT prove: gas/funding reality (anvil is free) and public-RPC
# behaviour. Those are what Phase A/B on Base Sepolia/mainnet are for.
#
# Usage:
#   scripts/anvil_e2e.sh [-a ANVIL_PORT] [-m MAIL_PORT] [-b SPORE_BINARY]
#                        [-r RECEIPT_FILE] [-s] [-k]
#     -a   anvil JSON-RPC port (default 18545)
#     -m   local mailbox port — body store + prekey authority (default 19393)
#     -b   spore binary to drive (default: built fresh from this repo)
#     -r   also write the fill-shaped receipt to this path (including the burn
#          txid recovered from chain state), and check it against
#          scripts/release-fill.sh's own rules (see below)
#     -s   skip (exit 0) when anvil is not installed, instead of failing
#          (exit 3). For CI/gates where foundry may be absent.
#     -k   keep the workspace + anvil running on exit (for inspection)
#
# Exit codes: 0 proof green, 1 a proof step failed, 2 usage error,
#             3 anvil missing and -s not given (never a silent pass).
set -euo pipefail

ANVIL_PORT=18545
MAIL_PORT=19393
SPORE=""
RECEIPT=""
SKIP_IF_MISSING=0
KEEP=0

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }

while getopts "a:m:b:r:skh" opt; do
  case "$opt" in
    a) ANVIL_PORT=$OPTARG ;;
    m) MAIL_PORT=$OPTARG ;;
    b) SPORE=$OPTARG ;;
    r) RECEIPT=$OPTARG ;;
    s) SKIP_IF_MISSING=1 ;;
    k) KEEP=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spore-anvil-e2e.XXXXXX")"
RPC="http://127.0.0.1:$ANVIL_PORT"
MAIL="http://127.0.0.1:$MAIL_PORT"

# anvil's well-known dev accounts (public, documented, never funded). A is the
# deployer + sender; B is the recipient whose account signs the burn.
KEY_A="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ADDR_A="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ADDR_B="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
# The fill's values are lowercase-only (its shape rules say so); every address
# this script writes into a receipt goes through this.
lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
DEPLOYER="$(lower "$ADDR_A")"

PASS=0
ANVIL_PID=""; MAIL_PID=""; RECV_PID=""
cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    printf 'workspace kept: %s (anvil %s, pid %s)\n' "$ROOT" "$RPC" "$ANVIL_PID"
    return
  fi
  for pid in "$RECV_PID" "$MAIL_PID" "$ANVIL_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

rpc_call() { # rpc_call METHOD [PARAMS-JSON]
  curl -sf -m 15 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}
# rpc_result extracts "result" without jq: result is a scalar (string/number).
rpc_result() {
  sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}
hex_to_dec() { # bash arithmetic reads 0x… as hex
  local h="$1"
  [[ "$h" =~ ^0x[0-9a-fA-F]+$ ]] || { echo 0; return; }
  echo $(( h ))
}
wait_http() { # wait_http URL LABEL [TRIES]
  local url="$1" label="$2" tries="${3:-40}" i
  for i in $(seq 1 "$tries"); do
    if curl -s --connect-timeout 2 -o /dev/null "$url"; then return 0; fi
    sleep 0.5
  done
  fail "$label never answered at $url"
}
first_hash_in() { grep -oE '0x[0-9a-f]{64}' "$1" | head -1; }
contract_addr_in() { grep 'contract addr:' "$1" | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }

find_anvil() {
  if command -v anvil >/dev/null 2>&1; then command -v anvil; return 0; fi
  local c
  for c in "${HOME:-}/.cargo/bin/anvil" "${HOME:-}/.cargo/bin/anvil.exe" \
           "${USERPROFILE:-}/.cargo/bin/anvil.exe" "${USERPROFILE:-}/.cargo/bin/anvil"; do
    [ -n "$c" ] && [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

ANVIL_BIN="$(find_anvil || true)"
if [ -z "$ANVIL_BIN" ]; then
  if [ "$SKIP_IF_MISSING" -eq 1 ]; then
    echo "SKIP: anvil not found — install foundry to run the local EVM proof"
    exit 0
  fi
  echo "FAIL: anvil not found on PATH or in ~/.cargo/bin (install foundry, or pass -s to skip)" >&2
  exit 3
fi
command -v curl >/dev/null 2>&1 || { echo "FAIL: curl is required" >&2; exit 3; }

# A busy port is an explicit error, never a silent reuse: a stale anvil or
# mailbox from an earlier run would serve the wrong chain/workspace and make
# this proof lie in either direction.
port_busy() { curl -s --connect-timeout 2 -o /dev/null "http://127.0.0.1:$1"; }
if port_busy "$ANVIL_PORT"; then
  fail "port $ANVIL_PORT already serves HTTP — pass -a with a free port (a stale anvil would poison the proof)"
fi
if port_busy "$MAIL_PORT"; then
  fail "port $MAIL_PORT already serves HTTP — pass -m with a free port (a stale mailbox would serve the wrong dir)"
fi

step "build"
if [ -z "$SPORE" ]; then
  SPORE="$ROOT/spore"
  (cd "$REPO_ROOT" && go build -o "$SPORE" ./cmd/spore) || fail "go build failed"
fi
[ -x "$SPORE" ] || fail "spore binary not executable: $SPORE"
ok "spore: $SPORE"

step "anvil: $RPC"
"$ANVIL_BIN" --port "$ANVIL_PORT" --silent >"$ROOT/anvil.log" 2>&1 &
ANVIL_PID=$!
CHAIN_ID=""
for _ in $(seq 1 40); do
  CHAIN_ID="$(rpc_call eth_chainId 2>/dev/null | rpc_result || true)"
  [ -n "$CHAIN_ID" ] && break
  sleep 0.5
done
[ -n "$CHAIN_ID" ] || { cat "$ROOT/anvil.log" 2>/dev/null; fail "anvil never answered eth_chainId"; }
ok "chain id $(hex_to_dec "$CHAIN_ID") up in $RPC"

step "deploy: the pinned MyceliumMailbox through the real deploy path"
SPORE_EVM_PRIVATE_KEY="$KEY_A" "$SPORE" contract deploy-mycelium \
  -rpc "$RPC" -wait 2m -bin "$REPO_ROOT/tools/mycelium.bin" >"$ROOT/deploy.log" 2>&1 \
  || { cat "$ROOT/deploy.log"; fail "deploy-mycelium failed"; }
CONTRACT="$(contract_addr_in "$ROOT/deploy.log")"
DEPLOY_TX="$(first_hash_in "$ROOT/deploy.log")"
[ -n "$CONTRACT" ] || { cat "$ROOT/deploy.log"; fail "deploy printed no contract address"; }
ok "mailbox $CONTRACT (creation tx ${DEPLOY_TX:-?}) — eth_getCode verified by the command"

step "local mailbox: body store (/body) + prekey authority (/prekey)"
HEAD_HEX="$(rpc_call eth_blockNumber | rpc_result || true)"
HEAD="$(hex_to_dec "${HEAD_HEX:-}")"
"$SPORE" mailbox run -dir "$ROOT/mb" -listen "127.0.0.1:$MAIL_PORT" \
  -chain evm -rpc "$RPC" -from "$ADDR_B" -mailbox "$CONTRACT" -min-height "$HEAD" \
  >"$ROOT/mailbox.log" 2>&1 &
MAIL_PID=$!
wait_http "$MAIL/list" "local mailbox"
ok "mailbox up at $MAIL (store + prekey discovery)"

step "identity kits: spore init for both parties"
"$SPORE" init -dir "$ROOT/alice" -chain evm -opks 4 >/dev/null
"$SPORE" init -dir "$ROOT/bob"   -chain evm -opks 4 >/dev/null
PIN_B="$(grep -o '"pinned_sig":[[:space:]]*"[0-9a-fA-F]\{64\}"' "$ROOT/bob/identity-card.json" | grep -o '[0-9a-fA-F]\{64\}' | head -1)"
[ -n "$PIN_B" ] || fail "could not read bob's pinned_sig from identity-card.json"
ok "kits ready; bob's pinned sig $PIN_B"

step "prekey publish: bob's batch -> the mailbox (GET /prekey pop for alice)"
"$SPORE" prekeybatch push -in "$ROOT/bob/batch.json" -mailbox "$MAIL" >"$ROOT/prekeypush.log" 2>&1 \
  || { cat "$ROOT/prekeypush.log"; fail "prekeybatch push failed"; }
ok "bob's single-use bundles published"

step "receiver: B runs recv-e2 against the deployed mailbox"
mkdir -p "$ROOT/bob/state"
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/bob" \
  "$SPORE" msg recv-e2 \
    -chain evm -from "$ADDR_B" -rpc "$RPC" -mailbox "$CONTRACT" \
    -identity "$ROOT/bob/identity.key" \
    -store "$MAIL" -min-height "$HEAD" \
    -state-dir "$ROOT/bob/state" -state-key "$ROOT/bob/state.key" \
    >"$ROOT/recv.log" 2>&1 &
RECV_PID=$!
sleep 2
kill -0 "$RECV_PID" 2>/dev/null || { cat "$ROOT/recv.log"; fail "recv-e2 died at startup"; }
ok "receiver up (scanning from block $HEAD)"

step "sender: A discovers B's prekey and send-e2 -mailbox"
MSG="anvil e2e $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s' "$MSG" >"$ROOT/msg.txt"
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/alice" \
  "$SPORE" msg send-e2 \
    -to "$ADDR_B" -identity "$ROOT/alice/identity.key" \
    -bundle-url "$MAIL/prekey" -pinned-sig "$PIN_B" \
    -chain evm -from "$ADDR_A" -rpc "$RPC" -mailbox "$CONTRACT" \
    -store "$MAIL" -msg-file "$ROOT/msg.txt" >"$ROOT/send.log" 2>&1 \
  || { cat "$ROOT/send.log"; fail "send-e2 failed"; }
DELIVER_TX="$(first_hash_in "$ROOT/send.log")"
[ -n "$DELIVER_TX" ] || { cat "$ROOT/send.log"; fail "send printed no pointer tx hash"; }
ok "pointer delivered on chain: $DELIVER_TX (body on $MAIL, chain carried the pointer only)"

step "B decrypts (Inbox(to=B) log discovery + read)"
GOT=0
for _ in $(seq 1 120); do
  if grep -qF "$MSG" "$ROOT/recv.log" 2>/dev/null; then GOT=1; break; fi
  kill -0 "$RECV_PID" 2>/dev/null || break
  sleep 0.5
done
[ "$GOT" -eq 1 ] || { tail -30 "$ROOT/recv.log"; fail "B never decrypted the message"; }
ok "round trip complete: B decrypted the message"

step "compost: the slot must be provably empty after the burn"
# The burn is best-effort by design and deliberately unlogged, so prove the
# OUTCOME: let the burn window land, stop the watcher, then read the slot back
# with a FRESH state dir (existing ratchet state must not mask a re-delivery).
sleep 5
kill "$RECV_PID" 2>/dev/null || true; wait "$RECV_PID" 2>/dev/null || true; RECV_PID=""
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/bob" \
  timeout 30 "$SPORE" msg recv-e2 \
    -chain evm -from "$ADDR_B" -rpc "$RPC" -mailbox "$CONTRACT" \
    -identity "$ROOT/bob/identity.key" \
    -store "$MAIL" -min-height "$HEAD" \
    -state-dir "$ROOT/bob/rescan-state" -state-key "$ROOT/bob/state.key" \
    >"$ROOT/rescan.log" 2>&1 || true
if grep -qF "$MSG" "$ROOT/rescan.log"; then
  fail "message still readable on-chain after AutoBurn — compost did not happen"
fi
ok "COMPOST VERIFIED: a fresh-state production read returns an empty slot"

if command -v cast >/dev/null 2>&1; then
  LEN_RAW="$(cast call "$CONTRACT" "length(address)(uint256)" "$ADDR_B" --rpc-url "$RPC" 2>/dev/null || echo 0x0)"
  LEN="$(printf '%d' "$LEN_RAW" 2>/dev/null || echo 0)"
  SEQ=$(( LEN - 1 ))
  if [ "$SEQ" -ge 0 ]; then
    READ_OUT="$(cast call "$CONTRACT" "read(address,uint256)(address,uint256,bytes)" "$ADDR_B" "$SEQ" \
      --from "$ADDR_B" --rpc-url "$RPC" 2>/dev/null || echo cast-error)"
    LAST_LINE="$(printf '%s\n' "$READ_OUT" | tail -1 | tr -d ' ')"
    if [ "$LAST_LINE" = "0x" ] || [ -z "$LAST_LINE" ]; then
      ok "ON-CHAIN PROOF: read(to, seq=$SEQ) is empty (length(to)=$LEN, unchanged by the burn)"
    else
      fail "on-chain slot seq=$SEQ still holds data after the burn: $LAST_LINE"
    fi
  else
    ok "length(to)=0 — no slot to read back; the fresh-state rescan carries the proof"
  fi
else
  ok "cast not installed — the fresh-state rescan carries the empty-slot proof"
fi

step "burn: recover the transaction from the chain (the receive path does not log it)"
# The compost assertion above proves the OUTCOME — a fresh-state production read
# returns an empty slot, so the burn landed. It does not name the transaction,
# and it cannot: chain.Watch issues burn(to,seq) best-effort and logs nothing,
# by design (a burn failure must never look like a delivery failure). The §3
# receipt used to describe that absence — "unlogged by design, see the
# explorer". A chain keeps its own history, so read the tx back out instead:
# scripts/evm-burn-txid.sh enumerates the blocks since the delivery for a
# burn(address,uint256) from B to this mailbox. No match is a FAILURE here, so
# the old wording can never quietly come back as the fallback.
BURN_FINDER="$REPO_ROOT/scripts/evm-burn-txid.sh"
[ -f "$BURN_FINDER" ] || fail "scripts/evm-burn-txid.sh is missing — the proof cannot name the burn it just asserted"
DELIVER_BLOCK_HEX="$(rpc_call eth_getTransactionByHash "[\"$DELIVER_TX\"]" \
  | sed -n 's/.*"blockNumber":"\(0x[0-9a-fA-F]*\)".*/\1/p' | head -1)"
if [ -n "$DELIVER_BLOCK_HEX" ]; then
  DELIVER_BLOCK="$(hex_to_dec "$DELIVER_BLOCK_HEX")"
else
  DELIVER_BLOCK="$HEAD"
fi
BURN_HIT="$(bash "$BURN_FINDER" -rpc "$RPC" -mailbox "$CONTRACT" -recipient "$ADDR_B" \
  -from-block "$DELIVER_BLOCK" 2>"$ROOT/burn-scan.log" | tail -1 || true)"
BURN_TX="$(printf '%s' "$BURN_HIT" | awk '{print $1}')"
BURN_SEQ="$(printf '%s' "$BURN_HIT" | awk '{print $2}')"
BURN_BLOCK="$(printf '%s' "$BURN_HIT" | awk '{print $3}')"
case "$BURN_TX" in
  0x*) ;;
  *)
    cat "$ROOT/burn-scan.log" >&2
    fail "no burn transaction found from $ADDR_B to $CONTRACT in blocks $DELIVER_BLOCK.. — the slot IS empty, but a receipt without the txid would fall back to describing the burn's absence"
    ;;
esac
for other in "$DEPLOY_TX" "$DELIVER_TX"; do
  if [ "$BURN_TX" = "$other" ]; then
    fail "the recovered burn tx ($BURN_TX) is also $other — that is not a burn"
  fi
done
if [ -n "${SEQ:-}" ] && [ -n "$BURN_SEQ" ] && [ "$BURN_SEQ" != "$SEQ" ]; then
  fail "the recovered burn erases slot $BURN_SEQ, but the delivered slot is $SEQ — that burn belongs to a different message"
fi
[ -n "$BURN_SEQ" ] || fail "the recovered burn printed no sequence number: $BURN_HIT"
ok "burn recovered: $BURN_TX (burn(address,uint256), slot $BURN_SEQ, block $BURN_BLOCK — nothing in this run logged it)"

# ---- the receipt the fill consumes -----------------------------------------
# Everything above proved the arc; this writes the artifact release day needs,
# from the same run. Nothing here is typed by a human: the deploy and deliver
# txids come out of the command logs, the burn txid comes off the chain itself
# (the step above — the receive path deliberately does not log it), the dates
# come off the clock, and the fee numbers come from the runbook's own estimator,
# invoked the way §3 invokes it.
if [ -n "$RECEIPT" ]; then
  mkdir -p "$(dirname "$RECEIPT")" 2>/dev/null || true
  [ -n "$DEPLOY_TX" ] || fail "the deploy printed no creation txid — there is nothing honest to write in a receipt"

  step "receipt: the row the rehearsal stands in for"
  # The two receipt rows are two different chains' deployments, so they cannot
  # share a creation txid and the fill refuses it if they do. Locally the second
  # row is one more REAL transaction, so the substitution is rehearsed with real
  # hashes rather than with plausible-looking constants.
  SEPOLIA_TX="$(rpc_call eth_sendTransaction \
    "[{\"from\":\"$ADDR_A\",\"to\":\"$ADDR_B\",\"value\":\"0x1\"}]" | rpc_result || true)"
  case "$SEPOLIA_TX" in 0x*) ;; *) fail "anvil returned no tx hash for the rehearsal row's transaction" ;; esac
  for other in "$DEPLOY_TX" "$DELIVER_TX" "$BURN_TX"; do
    if [ "$SEPOLIA_TX" = "$other" ]; then
      fail "the rehearsal-row transaction is also $other — release-fill.sh refuses a receipt whose txids are not distinct"
    fi
  done
  ok "rehearsal-row tx $SEPOLIA_TX (real, and distinct from the deploy, the deliver and the burn)"

  step "receipt: measure with the runbook's own command"
  # Run it from a tree that carries the pinned creation bytecode: the estimator
  # reads tools/mycelium.bin, so the runbook's own working directory is the repo.
  # SPORE_HOME/SPORE_CONFIG are unset so this box's real config cannot leak a
  # mailbox default or a chain into the numbers the receipt will carry.
  # LIVE_NODES §3 step 1: once with -from for the deploy row, then again with
  # -mailbox for deliver/burn and the funding total. The order is the point: the
  # fee block is filled from the command it quotes.
  (cd "$REPO_ROOT" && env -u SPORE_HOME -u SPORE_CONFIG "$SPORE" contract estimate \
    -rpc "$RPC" -from "$DEPLOYER" -rounds 5) >"$ROOT/estimate-pre.log" 2>&1 ||
    { cat "$ROOT/estimate-pre.log"; fail "the pre-deploy estimate failed"; }
  grep -q '^deploy ' "$ROOT/estimate-pre.log" ||
    { cat "$ROOT/estimate-pre.log"; fail "the pre-deploy estimate printed no deploy row"; }
  (cd "$REPO_ROOT" && env -u SPORE_HOME -u SPORE_CONFIG "$SPORE" contract estimate \
    -rpc "$RPC" -from "$DEPLOYER" -mailbox "$CONTRACT" -rounds 5) >"$ROOT/estimate.log" 2>&1 ||
    { cat "$ROOT/estimate.log"; fail "the post-deploy estimate failed"; }

  est() { sed -n "$1" "$ROOT/estimate.log" | head -1; }
  EST_GAS_PRICE="$(est 's/^gas price: *\([0-9][0-9]*\) wei.*/\1/p')"
  EST_DEPLOY_GAS="$(est 's/^deploy  *\([0-9][0-9,]*\) gas.*/\1/p')"
  EST_DEPLOY_ETH="$(est 's/^deploy  *[0-9][0-9,]* gas  *\(.*\)$/\1/p')"
  EST_DELIVER_GAS="$(est 's/^deliver  *\([0-9][0-9,]*\) gas.*/\1/p')"
  EST_DELIVER_ETH="$(est 's/^deliver  *[0-9][0-9,]* gas  *\(.*\)$/\1/p')"
  EST_BURN_GAS="$(est 's/^burn  *\([0-9][0-9,]*\) gas.*/\1/p')"
  EST_BURN_ETH="$(est 's/^burn  *[0-9][0-9,]* gas  *\(.*\)$/\1/p')"
  EST_ROUND_ETH="$(est 's/^deliver+burn  *[0-9][0-9,]* gas  *\(.*\)$/\1/p')"
  EST_N_ROUNDS="$(est 's/^funding total:.*deploy + \([0-9][0-9]*\) .*/\1/p')"
  EST_FUNDING_TOTAL="$(est 's/^funding total:.* = //p')"
  TTODAY="$(date -u +%Y-%m-%d)"
  for v in EST_GAS_PRICE EST_DEPLOY_GAS EST_DEPLOY_ETH EST_DELIVER_GAS EST_DELIVER_ETH \
           EST_BURN_GAS EST_BURN_ETH EST_ROUND_ETH EST_N_ROUNDS EST_FUNDING_TOTAL; do
    [ -n "${!v:-}" ] || { cat "$ROOT/estimate.log"; fail "could not parse $v out of the estimator output"; }
  done
  [ "$EST_N_ROUNDS" = "5" ] || fail "the funding total reports $EST_N_ROUNDS rounds, asked for 5 — the parse is wrong"
  ok "gas price $EST_GAS_PRICE wei; deploy $EST_DEPLOY_GAS gas; round $EST_ROUND_ETH; total $EST_FUNDING_TOTAL ($EST_N_ROUNDS rounds)"

  step "receipt: write it, then require the fill to accept it"
  MAINNET_ADDR="$(lower "$CONTRACT")"
  SEPOLIA_ADDR="$(lower "$ADDR_B")"
  cat >"$RECEIPT" <<RECEIPT_FILE
# LOCAL ANVIL PROOF — NOT A DEPLOYMENT RECEIPT (chain $(hex_to_dec "$CHAIN_ID"), $RPC).
#
# Written by scripts/anvil_e2e.sh from the run it just proved, so that release
# day copies a file instead of transcribing hex strings, and so this shape of
# file is exercised on every push. Every value was observed in that run or
# measured by the runbook's own estimator; none was typed.
#
# The fill's two receipt rows are two chains' deployments. Locally they are:
#   MAINNET_*  this proof's deployment
#   SEPOLIA_*  the rehearsal row's shape — a real extra transaction, because the
#              two rows must differ and the fill checks that they do
# DEPLOYER, DELIVER_TX and BURN_TX are this proof's; the EST_* numbers are this
# chain's. BURN_TX is the one value the CLI never printed — it was recovered
# from chain state above, which is why the shipped burn note can cite a txid.
# scripts/release-fill.sh REFUSES anvil's dev accounts unless it is passed
# --local-proof: they can only come from a run like this one.
SEPOLIA_ADDR=$SEPOLIA_ADDR
SEPOLIA_TX=$SEPOLIA_TX
SEPOLIA_DATE=$TTODAY
MAINNET_ADDR=$MAINNET_ADDR
MAINNET_TX=$DEPLOY_TX
MAINNET_DATE=$TTODAY
DEPLOYER=$DEPLOYER
DELIVER_TX=$DELIVER_TX
BURN_TX=$BURN_TX
EST_DATE=$TTODAY
EST_GAS_PRICE=$EST_GAS_PRICE
EST_DEPLOY_GAS=$EST_DEPLOY_GAS
EST_DEPLOY_ETH=$EST_DEPLOY_ETH
EST_DELIVER_GAS=$EST_DELIVER_GAS
EST_DELIVER_ETH=$EST_DELIVER_ETH
EST_BURN_GAS=$EST_BURN_GAS
EST_BURN_ETH=$EST_BURN_ETH
EST_ROUND_ETH=$EST_ROUND_ETH
EST_N_ROUNDS=$EST_N_ROUNDS
EST_FUNDING_TOTAL=$EST_FUNDING_TOTAL
RECEIPT_FILE
  ok "receipt written: $RECEIPT ($(grep -c '^[A-Z]' "$RECEIPT" || true) values, $(grep -c '^#' "$RECEIPT" || true) provenance lines)"

  # The receipt's shape is defined by its consumer, so the consumer gets to say
  # whether this one is usable. On a tree where the frozen passes are not applied
  # that is a pure validation (nothing is filled); on a flipped tree it is a dry
  # run. Either way exit 0 means the fill would take this file.
  if [ ! -f "$REPO_ROOT/scripts/release-fill.sh" ]; then
    fail "scripts/release-fill.sh is missing — the receipt's consumer defines its shape, so it cannot be checked"
  fi
  if ! bash "$REPO_ROOT/scripts/release-fill.sh" -C "$REPO_ROOT" --check \
    -in "$RECEIPT" --local-proof >"$ROOT/receipt-check.log" 2>&1; then
    cat "$ROOT/receipt-check.log"
    fail "the receipt this run wrote is not accepted by the fill: $RECEIPT"
  fi
  ok "the fill accepts it: $(sed -n 's/^release-fill: //p' "$ROOT/receipt-check.log" | head -1)"
fi

printf '\n\033[1;32mANVIL E2E GREEN\033[0m — %d checks. mailbox %s on chain %s.\n' \
  "$PASS" "$CONTRACT" "$(hex_to_dec "$CHAIN_ID")"
if [ -n "$RECEIPT" ]; then
  printf 'Receipt: %s\n' "$RECEIPT"
  printf '  check/consume it: bash scripts/release-fill.sh -in %s --local-proof   (drop --local-proof on a real chain)\n' "$RECEIPT"
fi
printf 'Burn: %s (slot %s, block %s) — recovered from chain state; the receive path logs nothing.\n' \
  "$BURN_TX" "$BURN_SEQ" "$BURN_BLOCK"
printf 'Next: the same flow on Base Sepolia with funded keys — scripts/sepolia_rehearsal.sh\n'
