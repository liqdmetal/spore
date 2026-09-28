#!/usr/bin/env bash
# scripts/sepolia_rehearsal.sh — Phase A of the v0.9.0 landing card as one
# command: a Base Sepolia rehearsal of the full MyceliumMailbox arc.
#
#   estimate   spore contract estimate against the live RPC (deploy row,
#              then the full funding number once the mailbox exists)
#   deploy     spore contract deploy-mycelium (signs locally; public RPC)
#   proof      A → B spore msg send-e2 through loopback evm-proxy A, B
#              receiving via recv-e2 through loopback evm-proxy B
#              (bodies on the serverless nostr commons, prekey bundle
#              exchanged out-of-band inside this workspace)
#   compost    assert the burn: a FRESH-state production read returns
#              nothing for the burned slot, and (if foundry's `cast` is
#              installed) the on-chain length(to) is unchanged by the burn
#   receipt    print the exact docs/LIVE_NODES.md §3 STATUS lines to paste
#
# Keys and secrets: the two funded test keys are read from the environment
# (never argv — shell history and `ps` read argv):
#   SPORE_EVM_PRIVATE_KEY     key A — deployer + sender (gets the faucet ETH)
#   SPORE_EVM_PRIVATE_KEY_B   key B — recipient; its proxy signs the burn
#                             (burn(to,seq) requires msg.sender == to, so the
#                             recipient needs its own funded key)
# They never leave this box's env; the script prints addresses only.
#
# Resume: if you already deployed, pass the address + creation tx to skip the
# funded steps and rerun only the proof:
#   MYCELIUM_TEST_MAILBOX=0x… MYCELIUM_TEST_CREATION_TX=0x… \
#     scripts/sepolia_rehearsal.sh
#
# Auto-burn caveat: burn is BEST-EFFORT by design (a burn failure never
# blocks delivery). This script FAILS when the burn did not land — for the
# rehearsal that is exactly the bar.
#
# Usage:
#   scripts/sepolia_rehearsal.sh [-r RPC] [-b SPORE_BINARY]
#     -r   RPC (default https://sepolia.base.org; ANY EVM chain works —
#          the script warns if the chain id is not Base Sepolia 84532)
#     -b   spore binary to drive (default: built fresh from this repo)
#
# Cost: a deploy plus a dozen deliver/burn rounds is well under 0.01 testnet
# ETH. Fund both keys from a Base Sepolia faucet (Alchemy/Chainlink run ones).
set -euo pipefail

RPC="https://sepolia.base.org"
SPORE=""
while getopts "r:b:h" opt; do
  case "$opt" in
    r) RPC="$OPTARG" ;;
    b) SPORE="$OPTARG" ;;
    h) sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: scripts/sepolia_rehearsal.sh [-r RPC] [-b SPORE_BINARY]" >&2; exit 2 ;;
  esac
done

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spore-sepolia.XXXXXX")"
# The pinned creation bytecode ships with the repo; resolve it relative to
# this script so the rehearsal runs from any cwd.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_ARG=()
if [[ -f "$REPO_ROOT/tools/mycelium.bin" ]]; then
  BIN_ARG=(-bin "$REPO_ROOT/tools/mycelium.bin")
fi
PROXY_A_PORT=$((21600 + RANDOM % 2000))
PROXY_B_PORT=$((PROXY_A_PORT + 1))
PROXY_A_RPC="http://127.0.0.1:$PROXY_A_PORT"
PROXY_B_RPC="http://127.0.0.1:$PROXY_B_PORT"
# Serverless body store: no mailbox to run, both sides reach the same public
# relays. A dedicated store key ships with each `spore init` kit.
# SPORE_REHEARSAL_STORE overrides it (e.g. a local `spore mailbox host` URL
# for a fully offline rehearsal against a local stub chain).
NOSTR_STORE="${SPORE_REHEARSAL_STORE:-nostr://relay.damus.io,nos.lol}"
RECV_BUDGET=300          # seconds B gets to decrypt (Base blocks ~2s)
RESCAN_TIMEOUT=60        # seconds for the fresh-state empty-slot read

PASS=0
PROXY_A_PID=""; PROXY_B_PID=""; RECV_PID=""
cleanup() {
  for pid in "$PROXY_A_PID" "$PROXY_B_PID" "$RECV_PID"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"; }

rpc_call() { # rpc_call METHOD PARAMS — minimal JSON-RPC over curl
  curl -sf -m 15 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}
hex_to_dec() { # hex_to_dec 0x… — bash arithmetic reads 0x… as hex
  local h="$1"
  [[ "$h" =~ ^0x[0-9a-fA-F]+$ ]] || { echo 0; return; }
  echo $(( h ))
}
eth_balance_wei() { printf '%s' "$(hex_to_dec "$(rpc_call eth_getBalance "[\"$1\",\"latest\"]" | jq -r '.result' || echo '')")"; }
# wait_port HOST PORT LABEL TRIES — any HTTP answer (even the proxy's 405 on
# GET) proves the listener is up; curl --connect-timeout keeps it bounded.
wait_port() {
  local host="$1" port="$2" label="$3" tries="${4:-30}" i
  for i in $(seq 1 "$tries"); do
    if curl -s --connect-timeout 2 -o /dev/null "http://$host:$port/"; then return 0; fi
    sleep 1
  done
  fail "$label never opened a listener on $host:$port"
}
first_addr_in()  { grep -oE '0x[0-9a-fA-F]{40}' "$1" | head -1; }
# contract_addr_in FILE — the deploy log also carries the 64-hex creation tx
# hash, whose first 40 chars would fool a bare 40-hex grep; anchor to the
# labeled line instead.
contract_addr_in() { grep 'contract addr:' "$1" | grep -oE '0x[0-9a-fA-F]{40}' | head -1; }
first_hash_in()  { grep -oE '0x[0-9a-f]{64}'  "$1" | head -1; }

# ---------------- preflight ----------------
require curl; require jq
[[ -n "${SPORE_EVM_PRIVATE_KEY:-}"   ]] || fail "set SPORE_EVM_PRIVATE_KEY (key A: deployer + sender, funded)"
[[ -n "${SPORE_EVM_PRIVATE_KEY_B:-}" ]] || fail "set SPORE_EVM_PRIVATE_KEY_B (key B: recipient — its proxy signs the burn)"
KEY_A="$SPORE_EVM_PRIVATE_KEY"; KEY_B="$SPORE_EVM_PRIVATE_KEY_B"

step "workspace + binary"
if [[ -z "$SPORE" ]]; then
  SPORE="$ROOT/spore"
  (cd "$(dirname "$0")/.." && go build -o "$SPORE" ./cmd/spore) || fail "go build failed"
fi
[[ -x "$SPORE" ]] || fail "spore binary not executable: $SPORE"
ok "spore: $SPORE"

step "chain: $RPC"
CHAIN_ID_HEX=$(rpc_call eth_chainId | jq -r '.result' || true)
CHAIN_ID=$(hex_to_dec "${CHAIN_ID_HEX:-}")
[[ "$CHAIN_ID" -gt 0 ]] || fail "RPC never answered eth_chainId"
if [[ "$CHAIN_ID" -eq 84532 ]]; then
  ok "Base Sepolia confirmed (chain id 84532)"
else
  ok "note: chain id $CHAIN_ID is not Base Sepolia (84532) — proceeding (the path is chain-agnostic)"
fi

# ---------------- proxies (they also announce the addresses) ----------------
step "loopback signing proxies (the public RPC never sees a key)"
SPORE_EVM_PRIVATE_KEY="$KEY_A" "$SPORE" evm-proxy -rpc "$RPC" -listen "127.0.0.1:$PROXY_A_PORT" \
  >"$ROOT/proxyA.log" 2>&1 & PROXY_A_PID=$!
SPORE_EVM_PRIVATE_KEY="$KEY_B" "$SPORE" evm-proxy -rpc "$RPC" -listen "127.0.0.1:$PROXY_B_PORT" \
  >"$ROOT/proxyB.log" 2>&1 & PROXY_B_PID=$!
wait_port 127.0.0.1 "$PROXY_A_PORT" "proxy A" || true
wait_port 127.0.0.1 "$PROXY_B_PORT" "proxy B" || true
ADDR_A=$(first_addr_in "$ROOT/proxyA.log"); [[ -n "$ADDR_A" ]] || { cat "$ROOT/proxyA.log"; fail "could not read proxy A signer address"; }
ADDR_B=$(first_addr_in "$ROOT/proxyB.log"); [[ -n "$ADDR_B" ]] || { cat "$ROOT/proxyB.log"; fail "could not read proxy B signer address"; }
[[ "$ADDR_A" != "$ADDR_B" ]] || fail "keys A and B derive the same address — use two different keys"
ok "A (deploy+send): $ADDR_A via $PROXY_A_RPC"
ok "B (recv+burn):  $ADDR_B via $PROXY_B_RPC"

step "faucet check (keys must be funded BEFORE running this script)"
BAL_A=$(eth_balance_wei "$ADDR_A" || echo 0); BAL_B=$(eth_balance_wei "$ADDR_B" || echo 0)
ok "balances (wei): A=$BAL_A B=$BAL_B"
[[ "$BAL_A" -gt 1000000000000000 ]] || fail "key A ($ADDR_A) looks unfunded — hit a Base Sepolia faucet (Alchemy/Chainlink) and retry"
[[ "$BAL_B" -gt 1000000000000000 ]] || fail "key B ($ADDR_B) looks unfunded — burn gas is paid by the RECIPIENT; fund it too"

# ---------------- estimate (before any funded tx) ----------------
step "estimate: the funding math, one command"
"$SPORE" contract estimate -rpc "$RPC" -from "$ADDR_A" "${BIN_ARG[@]}" | tee "$ROOT/estimate-deploy.txt" \
  || fail "contract estimate (deploy row) failed"
ok "deploy row priced (deliver/burn rows are added after the deploy)"

# ---------------- deploy (or resume) ----------------
SKIP_DEPLOY=0
if [[ -n "${MYCELIUM_TEST_MAILBOX:-}" ]]; then
  SKIP_DEPLOY=1
  CONTRACT="$MYCELIUM_TEST_MAILBOX"
  DEPLOY_TX="${MYCELIUM_TEST_CREATION_TX:-}"
  ok "resume mode: using MYCELIUM_TEST_MAILBOX=$CONTRACT"
fi
if [[ "$SKIP_DEPLOY" -eq 0 ]]; then
  step "deploy: spore contract deploy-mycelium (waits for code on chain)"
  SPORE_EVM_PRIVATE_KEY="$KEY_A" "$SPORE" contract deploy-mycelium \
    -rpc "$RPC" -wait 5m "${BIN_ARG[@]}" >"$ROOT/deploy.log" 2>&1 || { cat "$ROOT/deploy.log"; fail "deploy failed"; }
  cat "$ROOT/deploy.log"
  CONTRACT=$(contract_addr_in "$ROOT/deploy.log")
  DEPLOY_TX=$(first_hash_in "$ROOT/deploy.log")
  [[ -n "$CONTRACT" ]] || fail "deploy printed no contract address"
  [[ -n "$DEPLOY_TX"  ]] || fail "deploy printed no creation tx hash"
  ok "mailbox deployed at $CONTRACT (creation tx $DEPLOY_TX)"
fi

step "estimate: full funding number with the deployed mailbox"
if "$SPORE" contract estimate -rpc "$RPC" -from "$ADDR_A" -mailbox "$CONTRACT" "${BIN_ARG[@]}" \
    | tee "$ROOT/estimate-full.txt"; then
  ok "full estimate captured (see receipt block below)"
else
  ok "post-deploy estimate failed (non-fatal; the rehearsal continues)"
fi

# ---------------- identity kits (serverless posture) ----------------
step "identity kits: spore init for both parties"
"$SPORE" init -dir "$ROOT/alice/home" -chain evm -opks 4 >/dev/null
"$SPORE" init -dir "$ROOT/bob/home"   -chain evm -opks 4 >/dev/null
for p in alice bob; do
  jq --arg store "$NOSTR_STORE" --arg tok "${SPORE_REHEARSAL_STORE_TOKEN:-}" \
    '.store = $store | .store_token = $tok' \
    "$ROOT/$p/home/config.json" > "$ROOT/$p/cfg.tmp" \
    && mv "$ROOT/$p/cfg.tmp" "$ROOT/$p/home/config.json"
done
ok "kits initialized; store default = serverless nostr commons"

step "out-of-band bundle exchange (inside this workspace, standing in for a QR)"
jq '.bundles[0]' "$ROOT/bob/home/batch.json"   > "$ROOT/bob-bundle.json"
jq '.bundles[0]' "$ROOT/alice/home/batch.json" > "$ROOT/alice-bundle.json"
PIN_B=$(jq -r '.pinned_sig' "$ROOT/bob/home/identity-card.json")
[[ -n "$PIN_B" && "$PIN_B" != "null" ]] || fail "bob's identity card missing pinned_sig"
ok "bob's single-use bundle + pinned sig handed to alice"

# ---------------- the two-party proof ----------------
step "proof: B receives in the background (auto-burn is the default)"
# -min-height pins the scan to the current head: the deliver tx lands in a
# LATER block, so discovery is a bounded lookup, never genesis-to-head.
HEAD_HEX=$(rpc_call eth_blockNumber | jq -r '.result' || true)
HEAD=$(hex_to_dec "${HEAD_HEX:-}")
[[ "$HEAD" -gt 0 ]] || fail "RPC never answered eth_blockNumber"
mkdir -p "$ROOT/bob/home/state"
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/bob/home" \
  "$SPORE" msg recv-e2 \
    -chain evm -from "$ADDR_B" -rpc "$PROXY_B_RPC" -mailbox "$CONTRACT" \
    -min-height "$HEAD" \
    -state-dir "$ROOT/bob/home/state" -state-key "$ROOT/bob/home/state.key" \
    >"$ROOT/recv.log" 2>&1 &
RECV_PID=$!
sleep 2
kill -0 "$RECV_PID" 2>/dev/null || { cat "$ROOT/recv.log"; fail "recv-e2 died at startup"; }
ok "receiver up (scanning from block $HEAD; proxy B signs every eth_sendTransaction, including the burn)"

step "proof: A sends through the loopback proxy"
MSG="sepolia rehearsal $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s' "$MSG" > "$ROOT/msg.txt"
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/alice/home" \
  "$SPORE" msg send-e2 \
    -to "$ADDR_B" -identity "$ROOT/alice/home/identity.key" \
    -bundle "$ROOT/bob-bundle.json" -pinned-sig "$PIN_B" \
    -chain evm -from "$ADDR_A" -rpc "$PROXY_A_RPC" -mailbox "$CONTRACT" \
    -store "$NOSTR_STORE" \
    -msg-file "$ROOT/msg.txt" >"$ROOT/send.log" 2>&1 \
  || { cat "$ROOT/send.log"; fail "send-e2 failed"; }
cat "$ROOT/send.log"
DELIVER_TX=$(grep -oE 'sent-e2 txid (0x[0-9a-f]{64})' "$ROOT/send.log" | awk '{print $3}' | head -1)
[[ -n "$DELIVER_TX" ]] || DELIVER_TX=$(first_hash_in "$ROOT/send.log")
[[ -n "$DELIVER_TX" ]] || fail "send printed no pointer tx hash"
ok "pointer delivered on chain: $DELIVER_TX"
ok "body published to $NOSTR_STORE (the chain carried the 116-byte pointer only)"

step "proof: B decrypts (Inbox(to=B) log discovery + read)"
GOT=0
for i in $(seq 1 $((RECV_BUDGET / 5))); do
  if grep -qF "$MSG" "$ROOT/recv.log" 2>/dev/null; then GOT=1; break; fi
  kill -0 "$RECV_PID" 2>/dev/null || break
  sleep 5
done
[[ "$GOT" -eq 1 ]] || { tail -30 "$ROOT/recv.log"; fail "B never decrypted the message within ${RECV_BUDGET}s"; }
ok "round trip complete: B decrypted the message"

step "compost: the slot must be provably empty after the burn"
# The burn is best-effort by design (a failure never blocks delivery) and is
# deliberately UNLOGGED — neither chain.Watch nor the proxy prints the burn
# txid. So the rehearsal proves the OUTCOME, not the txid: give the burn a
# window to land (a couple of 3s poll cadences), then assert emptiness.
ok "waiting out the burn window (the burn itself is unlogged by design)"
sleep 20
kill "$RECV_PID" 2>/dev/null || true; wait "$RECV_PID" 2>/dev/null || true
# Mandatory assertion: a FRESH-state production read (new state dir, same
# proxy + read path a real recipient uses) returns nothing for the burned
# slot — existing ratchet state could theoretically mask a re-delivery.
env -u SPORE_HOME -u SPORE_CONFIG SPORE_HOME="$ROOT/bob/home" \
  timeout "$RESCAN_TIMEOUT" "$SPORE" msg recv-e2 \
    -chain evm -from "$ADDR_B" -rpc "$PROXY_B_RPC" -mailbox "$CONTRACT" \
    -min-height "$HEAD" \
    -state-dir "$ROOT/bob/rescan-state" -state-key "$ROOT/bob/home/state.key" \
    >"$ROOT/recv-again.log" 2>&1 || true
if grep -qF "$MSG" "$ROOT/recv-again.log"; then
  fail "message still readable on-chain after AutoBurn — compost did not happen"
fi
ok "COMPOST VERIFIED: a fresh-state production read returns an empty slot"

# Stronger assertion with foundry's cast — the LIVE_NODES §3 form, made
# concrete: length(to) counts every deliver ever (it never decreases), and
# the LAST slot — our message's seq — must read back EMPTY after the burn.
if command -v cast >/dev/null 2>&1; then
  LEN_RAW=$(cast call "$CONTRACT" "length(address)(uint256)" "$ADDR_B" --rpc-url "$RPC" 2>/dev/null || echo "0x0")
  LEN=$(printf '%d' "$LEN_RAW" 2>/dev/null || echo 0)
  SEQ=$(( LEN - 1 ))
  if [[ "$SEQ" -ge 0 ]]; then
    # read() requires msg.sender == to, so the simulation must be --from B.
    READ_OUT=$(cast call "$CONTRACT" "read(address,uint256)(address,uint256,bytes)" "$ADDR_B" "$SEQ" \
      --from "$ADDR_B" --rpc-url "$RPC" 2>/dev/null || echo "cast-error")
    if [[ "$READ_OUT" == "cast-error" ]]; then
      ok "cast read() failed (non-fatal) — the fresh-state rescan above carries the proof"
    else
      LAST_LINE=$(printf '%s\n' "$READ_OUT" | tail -1 | tr -d ' ')
      if [[ "$LAST_LINE" == "0x" || -z "$LAST_LINE" ]]; then
        ok "ON-CHAIN COMPOST PROOF: read(to, seq=$SEQ) returned EMPTY bytes (length(to)=$LEN, unchanged by the burn)"
      else
        fail "on-chain slot seq=$SEQ still holds data after the burn window: $LAST_LINE"
      fi
    fi
  else
    ok "length(to)=0 — nothing to read back; the fresh-state rescan above carries the proof"
  fi
else
  ok "cast not installed — the fresh-state rescan above carries the empty-slot proof (install foundry for the on-chain read() cross-check)"
fi

# ---------------- receipt ----------------
DATE_UTC=$(date -u +%Y-%m-%d)
FULL_TOTAL=$(grep -h 'funding total' "$ROOT/estimate-full.txt" 2>/dev/null | head -1 || true)
CREATION_CELL="$DEPLOY_TX"
if [[ -z "$CREATION_CELL" ]]; then
  CREATION_CELL="(fill the creation tx from the original run's explorer history)"
fi
step "receipt — paste into docs/LIVE_NODES.md §3 STATUS (rehearsal line)"
cat <<EOF

- Base Sepolia rehearsal: address \`$CONTRACT\`, creation tx \`$CREATION_CELL\`, date $DATE_UTC
- Two-party E2E → receive → auto-burn → empty-slot proof: deliver \`$DELIVER_TX\`; burn verified by the on-chain empty-slot read (the burn tx is unlogged by design — see \`$CONTRACT\`'s explorer tx history for the burn txid)
EOF
cat <<EOF

Rehearsal details (not for the STATUS block):
- Bodies on the serverless commons ($NOSTR_STORE); the chain carried 116-byte pointers only.
- Sender signed through loopback proxy A ($ADDR_A); the recipient's proxy B ($ADDR_B) signed the burn.
- Funding estimate at rehearsal time: ${FULL_TOTAL:-see $ROOT/estimate-full.txt} (re-run at deploy time — never fund from a stale number).
- Workspace kept for inspection: $ROOT

ok: rehearsal complete — $PASS checks green. Next: Phase B on mainnet (landing card), then fill the STATUS mainnet line.
EOF
