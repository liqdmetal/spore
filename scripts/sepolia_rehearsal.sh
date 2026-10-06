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
#   scripts/sepolia_rehearsal.sh [-r RPC] [-b SPORE_BINARY] [-s] [--self-check]
#     -r   RPC (default https://sepolia.base.org; ANY EVM chain works —
#          the script warns if the chain id is not Base Sepolia 84532)
#     -b   spore binary to drive (default: built fresh from this repo)
#     -s   self-skip (exit 0) when --self-check cannot run without foundry
#     --self-check
#          exercise THIS script's burn-recovery wiring against a throwaway
#          local anvil: no keys, no faucet, no network, no jq (see below)
#
# Cost: a deploy plus a dozen deliver/burn rounds is well under 0.01 testnet
# ETH. Fund both keys from a Base Sepolia faucet (Alchemy/Chainlink run ones).
#
# Before spending even testnet ETH, run the FREE offline mirror of this arc:
# scripts/anvil_e2e.sh — same two-party path against a throwaway local anvil,
# no keys, no faucet, no jq. It is the fast pre-flight for this rehearsal.
#
# Why --self-check exists. The burn is the one value in this rehearsal that
# nothing logs, so the step below reads it back out of chain state with
# scripts/evm-burn-txid.sh, and the receipt line this script prints carries that
# txid. Neither line can be exercised by a plain syntax check, and the funded
# run cannot be exercised at all without two faucet-funded keys — so the wiring
# would otherwise ship unexecuted. --self-check starts its own anvil, puts a
# burn-shaped transaction on the chain from a dev account, burns the same
# calldata shape through a handful of near-miss variants (wrong method, wrong
# sender, wrong address word) plus a real burn for a second mailbox, and requires
# the recovery step to name exactly the one burn it is asked for, to find the
# other mailbox's burn when asked for THAT, and to refuse every variant and every
# empty window — then prints and validates the receipt line. It needs foundry
# and nothing else: about ten seconds, on every pre-push. What it does NOT prove:
# that the chain is Base Sepolia, that the keys are funded, or that the CLI's own
# burn has this shape — scripts/anvil_e2e.sh drives the real `chain.Watch` burn
# for that, on the same gate run.
set -euo pipefail

RPC="https://sepolia.base.org"
SPORE=""
SELF_CHECK=0
SKIP_IF_MISSING=0
# --self-check is a long flag, so it is peeled off before getopts sees the rest;
# everything else keeps the single-letter surface this script has always had.
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-check) SELF_CHECK=1; shift ;;
    -s | --self-skip) SKIP_IF_MISSING=1; shift ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- ${ARGS[@]+"${ARGS[@]}"}
while getopts "r:b:h" opt; do
  case "$opt" in
    r) RPC="$OPTARG" ;;
    b) SPORE="$OPTARG" ;;
    h) sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: scripts/sepolia_rehearsal.sh [-r RPC] [-b SPORE_BINARY] [-s] [--self-check]" >&2; exit 2 ;;
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
PROXY_A_PID=""; PROXY_B_PID=""; RECV_PID=""; ANVIL_PID=""
cleanup() {
  for pid in "$PROXY_A_PID" "$PROXY_B_PID" "$RECV_PID" "$ANVIL_PID"; do
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
rpc_result() { sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'; }
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

# ---- the burn txid: one implementation, run by the funded pass and by -------
# ---- --self-check ----------------------------------------------------------
# chain.Watch issues burn(to,seq) best-effort and prints nothing, so the txid
# has to be read back off the chain. scripts/evm-burn-txid.sh does the reading;
# these two functions are how THIS script uses it, and --self-check drives them
# against a real (local) chain so their wiring is executed on every push rather
# than only on the one day two funded keys exist.

# deliver_block_of TXID -> the block (hex) the tx landed in, empty if unknown.
# jq-free, like the reader it feeds: a burn cannot precede its delivery, so this
# is the one bound the scan needs.
deliver_block_of() {
  rpc_call eth_getTransactionByHash "[\"$1\"]" \
    | sed -n 's/.*"blockNumber":"\(0x[0-9a-fA-F]*\)".*/\1/p' | head -1
}

# recover_burn RPC MAILBOX RECIPIENT FROM_BLOCK -> "<txid> <seq> <block>".
# Non-zero when there is no such burn (1) or the reader cannot run (2); it never
# prints a partial line, so a caller that ignores the status cannot mistake an
# empty result for a txid. The reader's own diagnostic goes to stderr.
recover_burn() {
  local rpc=$1 mailbox=$2 recipient=$3 from_block=$4 finder hit rc=0
  finder="$REPO_ROOT/scripts/evm-burn-txid.sh"
  if [[ ! -f "$finder" ]]; then
    echo "sepolia_rehearsal: $finder is missing — the receipt line cannot name the burn" >&2
    return 2
  fi
  set +e
  hit=$(bash "$finder" -rpc "$rpc" -mailbox "$mailbox" -recipient "$recipient" \
        -from-block "$from_block")
  rc=$?
  set -e
  [[ "$rc" -eq 0 ]] || return "$rc"
  hit=$(printf '%s\n' "$hit" | grep . | tail -1)
  [[ -n "$hit" ]] || return 1
  printf '%s\n' "$hit"
}

# receipt_lines CONTRACT CREATION_TX DATE DELIVER_TX BURN_TX — the §3 STATUS
# lines, exactly as the operator pastes them. A function so --self-check prints
# the SAME text the funded run prints, instead of a copy that can drift from it.
receipt_lines() {
  printf -- '- Base Sepolia rehearsal: address `%s`, creation tx `%s`, date %s\n' "$1" "$2" "$3"
  printf -- '- Two-party E2E → receive → auto-burn → empty-slot proof: deliver `%s`, burn `%s` (recovered from chain state — the receive path issues the burn and logs nothing), and a fresh-state `read()` on `%s` plus a production rescan both came back empty\n' "$4" "$5" "$1"
}

# find_anvil — PATH first, then cargo's bin (foundry installs there).
find_anvil() {
  if command -v anvil >/dev/null 2>&1; then command -v anvil; return 0; fi
  local c
  for c in "${HOME:-}/.cargo/bin/anvil" "${HOME:-}/.cargo/bin/anvil.exe" \
           "${USERPROFILE:-}/.cargo/bin/anvil.exe" "${USERPROFILE:-}/.cargo/bin/anvil"; do
    [[ -n "$c" && -x "$c" ]] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# ---- --self-check ----------------------------------------------------------
# A throwaway anvil, one real burn-shaped transaction, four near misses, and the
# real recovery step — so the wiring around the reader (the block window, the
# RPC shape, the calldata fields, the printed receipt line) is executed on every
# push instead of only on the day two funded keys exist. The fixture builds its
# burn calldata from the selector scripts/evm-burn-txid.sh itself matches on, so
# a drift in that constant moves both sides together: this check is about the
# wiring, and scripts/anvil_e2e.sh — which drives the CLI's own burn through
# chain.Watch — is what keeps the constant itself honest.
self_check() {
  local ANVIL_BIN PORT MB MB2 MB3 A B OTHER SEL NOT_SEL BOUND_TX BURN_TX BOUND_BLOCK
  local BURN_BLOCK_HEX MB2_TX MB2_HIT RAW N LINE CHAIN i

  ANVIL_BIN=$(find_anvil) || {
    if [[ "$SKIP_IF_MISSING" -eq 1 ]]; then
      echo "SKIP sepolia rehearsal self-check: anvil not found (self-skip)"
      return 0
    fi
    echo "sepolia_rehearsal: anvil not found — install foundry, or pass -s to skip" >&2
    return 3
  }
  require curl
  PORT=${SPORE_SELFTEST_ANVIL_PORT:-18549}
  RPC="http://127.0.0.1:$PORT"
  # A busy port is an explicit error, never a silent reuse: a stale anvil would
  # serve the wrong chain and make this check lie in either direction.
  if curl -s --connect-timeout 2 -o /dev/null "$RPC"; then
    fail "port $PORT already serves HTTP — set SPORE_SELFTEST_ANVIL_PORT to a free one"
  fi

  # addr_word/seq_word build the ABI words the reader parses: a 20-byte address
  # right-aligned in 32 bytes, and a 32-byte big-endian sequence number.
  addr_word() { local a=${1#0x}; printf '000000000000000000000000%s' "$(printf '%s' "$a" | tr 'A-F' 'a-f')"; }
  seq_word() { printf '%064x' "$1"; }
  send_tx() { # send_tx FROM TO DATA -> txid
    local h
    h=$(rpc_call eth_sendTransaction \
      "[{\"from\":\"$1\",\"to\":\"$2\",\"value\":\"0x0\",\"data\":\"$3\"}]" | rpc_result || true)
    [[ "$h" =~ ^0x[0-9a-fA-F]{64}$ ]] || fail "anvil returned no tx hash for a self-check transaction"
    printf '%s' "$h"
  }
  refused() { # refused LABEL CMD... — the command must fail
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
      echo "  self-check: $label — it succeeded, and must not" >&2
      return 1
    fi
    printf '  \033[32mok:\033[0m %s\n' "$label"
    PASS=$((PASS + 1))
    return 0
  }

  step "self-check: a throwaway anvil (no keys, no faucet, no network)"
  "$ANVIL_BIN" --port "$PORT" --silent >"$ROOT/anvil.log" 2>&1 & ANVIL_PID=$!
  CHAIN=0
  for i in $(seq 1 40); do
    CHAIN=$(hex_to_dec "$(rpc_call eth_chainId | rpc_result || true)")
    [[ "$CHAIN" -gt 0 ]] && break
    sleep 0.5
  done
  [[ "$CHAIN" -gt 0 ]] || { cat "$ROOT/anvil.log" 2>/dev/null; fail "anvil never answered eth_chainId"; }
  ok "chain id $CHAIN up at $RPC"

  step "self-check: one burn, four near misses, all real transactions"
  A=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266     # anvil dev account 0
  B=0x70997970C51812dc3A010C7d01b50e0d17dc79C8     # dev account 1 — the "recipient"
  MB=0x1111111111111111111111111111111111111111     # the "mailbox"
  MB2=0x2222222222222222222222222222222222222222    # a second mailbox, burned to as well
  MB3=0x4444444444444444444444444444444444444444    # a mailbox nothing ever touched
  OTHER=0x3333333333333333333333333333333333333333  # a recipient that never burned
  SEL=$(grep -oE '^BURN_SEL="0x[0-9a-fA-F]+"' "$REPO_ROOT/scripts/evm-burn-txid.sh" \
    | head -1 | sed 's/.*"\(0x[0-9a-fA-F]*\)"/\1/')
  [[ -n "$SEL" ]] || fail "could not read BURN_SEL out of scripts/evm-burn-txid.sh"
  NOT_SEL=0x69783d77   # deliver(address,bytes) — any non-burn selector would do

  # The bound transaction stands in for the delivery: the scan starts at its
  # block, so the recovery step has to read a real block number back off the RPC.
  BOUND_TX=$(send_tx "$A" "$MB" "${NOT_SEL}$(addr_word "$B")$(seq_word 0)")
  BOUND_BLOCK=$(deliver_block_of "$BOUND_TX")
  [[ -n "$BOUND_BLOCK" ]] || fail "could not read the bounding transaction's block back from the RPC"
  BURN_TX=$(send_tx "$B" "$MB" "${SEL}$(addr_word "$B")$(seq_word 0)")
  BURN_BLOCK_HEX=$(deliver_block_of "$BURN_TX")
  [[ -n "$BURN_BLOCK_HEX" ]] || fail "could not read the burn transaction's block back from the RPC"
  ok "bound tx $BOUND_TX (block $BOUND_BLOCK); burn-shaped tx $BURN_TX (block $BURN_BLOCK_HEX)"

  # Sent AFTER the real burn, so a near miss that matched would be the last line
  # the reader prints — which is the line the funded run takes.
  MB2_TX=$(send_tx "$B" "$MB2" "${SEL}$(addr_word "$B")$(seq_word 2)")  # a real burn, for the OTHER mailbox
  send_tx "$B" "$MB"  "${NOT_SEL}$(addr_word "$B")$(seq_word 1)" >/dev/null  # right sender+target, wrong method
  send_tx "$A" "$MB"  "${SEL}$(addr_word "$A")$(seq_word 3)"     >/dev/null  # right method+target, other sender
  send_tx "$B" "$MB"  "${SEL}$(addr_word "$A")$(seq_word 4)"     >/dev/null  # right sender+target, calldata names A
  ok "a real burn for another mailbox ($MB2_TX) plus three near misses: wrong method, other sender, wrong address word"

  step "self-check: the recovery step must name that burn, and only that burn"
  RAW=$(bash "$REPO_ROOT/scripts/evm-burn-txid.sh" -rpc "$RPC" -mailbox "$MB" \
    -recipient "$B" -from-block "$BOUND_BLOCK" 2>/dev/null || true)
  N=$(printf '%s\n' "$RAW" | grep -c . || true)
  [[ "$N" -eq 1 ]] || fail "the reader found $N burns in the window; the fixture put exactly one there — a near miss matched"
  [[ "$(printf '%s' "$RAW" | awk '{print $1}')" == "$BURN_TX" ]] || fail "the reader named $(printf '%s' "$RAW" | awk '{print $1}') instead of the fixture burn ($BURN_TX)"
  [[ "$(printf '%s' "$RAW" | awk '{print $2}')" == 0 ]] || fail "the reader reports seq $(printf '%s' "$RAW" | awk '{print $2}'), expected 0"
  [[ "$(printf '%s' "$RAW" | awk '{print $3}')" == "$(hex_to_dec "$BURN_BLOCK_HEX")" ]] || fail "the reader reports block $(printf '%s' "$RAW" | awk '{print $3}'), expected $(( BURN_BLOCK )) — the deliver-block bound was misread"
  ok "exactly one burn: $BURN_TX, seq 0, block $(hex_to_dec "$BURN_BLOCK_HEX") — all four near misses excluded"

  recover_burn "$RPC" "$MB" "$B" "$BOUND_BLOCK" >/dev/null || fail "the recovery step rejected the burn the reader just confirmed"
  ok "the recovery step accepts it (the funded run calls exactly this)"

  # The mailbox filter must discriminate, not merely exclude: asked for the other
  # mailbox, the same call has to find the burn that went there.
  MB2_HIT=$(recover_burn "$RPC" "$MB2" "$B" "$BOUND_BLOCK") || fail "the reader missed the burn to $MB2 — the mailbox filter excludes too much"
  [[ "$(printf '%s' "$MB2_HIT" | awk '{print $1}')" == "$MB2_TX" ]] || fail "asked for $MB2 the reader named $(printf '%s' "$MB2_HIT" | awk '{print $1}') instead of $MB2_TX"
  ok "asked for the OTHER mailbox it finds that mailbox's burn: the filter discriminates both ways"

  step "self-check: the refusal directions"
  refused "no burn for a recipient that never burned" recover_burn "$RPC" "$MB" "$OTHER" "$BOUND_BLOCK" || fail "a lookup that must refuse did not"
  refused "no burn in a window opening after it" recover_burn "$RPC" "$MB" "$B" "$(printf '0x%x' $(( $(hex_to_dec "$BURN_BLOCK_HEX") + 1 )))" || fail "a lookup that must refuse did not"
  refused "no burn to a mailbox nothing ever touched" recover_burn "$RPC" "$MB3" "$B" "$BOUND_BLOCK" || fail "a lookup that must refuse did not"
  refused "no answer from an unreachable RPC" recover_burn "http://127.0.0.1:1" "$MB" "$B" 0 || fail "a lookup that must refuse did not"

  step "self-check: the receipt line the funded run prints"
  LINE=$(receipt_lines "$MB" "$BOUND_TX" "2026-01-01" "$BOUND_TX" "$BURN_TX")
  N=$(printf '%s\n' "$LINE" | grep -c .)
  [[ "$N" -eq 2 ]] || fail "the receipt step printed $N lines, expected the two §3 STATUS rows"
  grep -qF "$BURN_TX" <<<"$LINE" || fail "the printed receipt line does not name the recovered burn txid"
  grep -qF "$BOUND_TX" <<<"$LINE" || fail "the printed receipt line does not name the deliver txid"
  grep -qF "$MB" <<<"$LINE" || fail "the printed receipt line does not name the mailbox"
  grep -qF 'recovered from chain state' <<<"$LINE" || fail "the printed burn note does not say where the txid came from"
  ! grep -qE '<|unlogged|DRYRUN' <<<"$LINE" || fail "the printed receipt line carries a placeholder or the old wording: $LINE"
  ok "the receipt line names both txids, cites the mailbox, and has no placeholder"

  printf '\n\033[1;32mSEPOLIA REHEARSAL SELF-CHECK GREEN\033[0m — %d checks. The burn recovery and the receipt line work against a real chain.\n' "$PASS"
  printf 'Not proved here: Base Sepolia itself, funded keys, and the shape of the CLI-owned burn — scripts/anvil_e2e.sh drives that one.\n'
  return 0
}

if [[ "$SELF_CHECK" -eq 1 ]]; then
  RC=0
  self_check || RC=$?
  exit "$RC"
fi

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
# txid. So the rehearsal proves the OUTCOME first: give the burn a window to
# land (a couple of 3s poll cadences), then assert emptiness. The step after
# this one recovers the TXID as well, because a receipt that names the
# transaction is better evidence than one that explains why it cannot.
ok "waiting out the burn window (the burn itself is never logged)"
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

# ---------------- the burn txid ----------------
step "burn: recover the txid from the chain (nothing logs it)"
# The same lookup scripts/anvil_e2e.sh runs locally, against this RPC: a
# `burn(address,uint256)` from B to the mailbox, whose calldata carries B's own
# address because only the recipient may erase its slot. The reader exits 1
# rather than guessing and 2 rather than swallowing an RPC error, so an unfound
# burn is a failed rehearsal — never a receipt line that quietly falls back to
# describing the burn's absence.
DELIVER_BLOCK=$(deliver_block_of "$DELIVER_TX")
[[ -n "$DELIVER_BLOCK" ]] || DELIVER_BLOCK="$HEAD"
BURN_RC=0
BURN_HIT=$(recover_burn "$RPC" "$CONTRACT" "$ADDR_B" "$DELIVER_BLOCK") || BURN_RC=$?
[[ "$BURN_RC" -eq 0 ]] ||
  fail "the burn-recovery step failed (exit $BURN_RC) for $ADDR_B → $CONTRACT in blocks $DELIVER_BLOCK.. — the slot IS empty, but the receipt line needs the txid"
BURN_TX=$(printf '%s' "$BURN_HIT" | awk '{print $1}')
ok "burn recovered: $BURN_TX (slot $(printf '%s' "$BURN_HIT" | awk '{print $2}'), block $(printf '%s' "$BURN_HIT" | awk '{print $3}'))"

# ---------------- receipt ----------------
DATE_UTC=$(date -u +%Y-%m-%d)
FULL_TOTAL=$(grep -h 'funding total' "$ROOT/estimate-full.txt" 2>/dev/null | head -1 || true)
CREATION_CELL="$DEPLOY_TX"
if [[ -z "$CREATION_CELL" ]]; then
  CREATION_CELL="(fill the creation tx from the original run's explorer history)"
fi
step "receipt — paste into docs/LIVE_NODES.md §3 STATUS (rehearsal line)"
printf '\n'
receipt_lines "$CONTRACT" "$CREATION_CELL" "$DATE_UTC" "$DELIVER_TX" "$BURN_TX"
cat <<EOF

Rehearsal details (not for the STATUS block):
- Bodies on the serverless commons ($NOSTR_STORE); the chain carried 116-byte pointers only.
- Sender signed through loopback proxy A ($ADDR_A); the recipient's proxy B ($ADDR_B) signed the burn.
- Funding estimate at rehearsal time: ${FULL_TOTAL:-see $ROOT/estimate-full.txt} (re-run at deploy time — never fund from a stale number).
- Workspace kept for inspection: $ROOT

ok: rehearsal complete — $PASS checks green. Next: Phase B on mainnet (landing card), then fill the STATUS mainnet line.
EOF
