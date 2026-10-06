#!/usr/bin/env bash
# scripts/preflight-base.sh — the free, read-only half of the Base deployment
# checklist (docs/LIVE_NODES.md §3) as ONE command, ending in a GO/NO-GO.
#
# It runs gates 0–2 of that checklist and nothing that spends or mutates:
#
#   gate 0  local: the pinned-bytecode tests, the receipt-gate/doc-claim tests,
#           and the offline two-party Anvil proof (scripts/anvil_e2e.sh)
#   gate 1  chain/key/address: chain id, the deployer address (derived from the
#           key), its nonce, the PREDICTED creation address, and the pinned
#           bytecode's sha256
#   gate 2  funding: live `spore contract estimate` (deploy row, plus the
#           deliver/burn round budget once a mailbox exists) checked against the
#           deployer's live balance
#
# It does NOT run gate 3 (the Base Sepolia rehearsal) — that spends testnet ETH
# and is therefore not read-only — nor gates 4–6. On GO it points you at them.
# Nothing here signs, deploys, or sends a transaction.
#
# The predicted creation address is the point: gate 4's `deploy-mycelium` must
# print exactly it. If a transaction lands first the nonce shifts and the
# prediction changes — which is why the abort rules say re-run this after any
# earlier failure.
#
# Requires: cast (foundry) for address derivation + the prediction, go + anvil
# for gate 0, and a spore build (it builds one unless -b is given). A missing
# tool is a NO-GO with a clear reason, never a silent pass.
#
# Usage:
#   scripts/preflight-base.sh [-r URL] [-c CHAIN_ID] [-a 0x…] [-k ENV_VAR]
#                             [-m 0x…] [-i FILE] [-n ROUNDS] [-b SPORE_BIN]
#                             [-s] [-h]
#     -r URL        JSON-RPC endpoint (default https://mainnet.base.org)
#     -c CHAIN_ID   required chain id (default 8453 = Base mainnet)
#     -a 0x…        deployer address; default: derived from the key
#     -k ENV_VAR    env var holding the funded key, used for derivation and
#                   NEVER printed (default SPORE_EVM_PRIVATE_KEY)
#     -m 0x…        already-deployed MyceliumMailbox (post-deploy run: adds
#                   the deliver/burn round budget to the funding check)
#     -i FILE       solc creation bytecode (default tools/mycelium.bin)
#     -n ROUNDS     deliver+burn rounds to fund for (default 12)
#     -b SPORE_BIN  spore binary to use (default: built fresh)
#     -s            skip gate 0 (the local tests + Anvil proof)
#
# Exit codes: 0 GO, 1 NO-GO, 2 usage error.
set -euo pipefail

RPC="https://mainnet.base.org"
EXPECT_CHAIN_ID=8453
ADDRESS_FLAG=""
KEY_ENV="SPORE_EVM_PRIVATE_KEY"
MAILBOX_FLAG=""
BIN="tools/mycelium.bin"
ROUNDS=12
SPORE=""
SKIP_LOCAL=0

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }

while getopts "r:c:a:k:m:i:n:b:sh" opt; do
  case "$opt" in
    r) RPC=$OPTARG ;;
    c) EXPECT_CHAIN_ID=$OPTARG ;;
    a) ADDRESS_FLAG=$OPTARG ;;
    k) KEY_ENV=$OPTARG ;;
    m) MAILBOX_FLAG=$OPTARG ;;
    i) BIN=$OPTARG ;;
    n) ROUNDS=$OPTARG ;;
    b) SPORE=$OPTARG ;;
    s) SKIP_LOCAL=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BLOCKERS=0
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m       %s\n' "$*"; }
info() { printf '  \033[36minfo:\033[0m     %s\n' "$*"; }
fail() { printf '  \033[31mNO-GO:\033[0m    %s\n' "$*"; BLOCKERS=$((BLOCKERS+1)); }
unverified() { printf '  \033[33munverified:\033[0m %s\n' "$*"; BLOCKERS=$((BLOCKERS+1)); }

# dec_ge A B — true when decimal string A >= B, without floats or 64-bit
# overflow (balances and gas totals can exceed int64). Compares digit counts
# first, then lexically, which is exact for equal-length digit strings.
norm_dec() { printf '%s' "$1" | tr -dc '0-9' | sed 's/^0*//'; }
dec_ge() {
  local a b
  a=$(norm_dec "$1"); b=$(norm_dec "$2")
  a=${a:-0}; b=${b:-0}
  if [ "${#a}" -ne "${#b}" ]; then [ "${#a}" -gt "${#b}" ]; return; fi
  [ "$a" \> "$b" ] || [ "$a" = "$b" ]
}

need_cast() { command -v cast >/dev/null 2>&1; }

RPC_CHAIN=""
ADDR=""
NONCE=""
PRED=""
MAILBOX="$MAILBOX_FLAG"

# ---------------------------------------------------------------- gate 0
if [ "$SKIP_LOCAL" -eq 0 ]; then
  step "gate 0 — local proof + bytecode pins (free)"
  LOG="$(mktemp)"
  if command -v go >/dev/null 2>&1; then
    if go test ./internal/evm -run 'TestPinnedMyceliumBytecode|TestDeployTxCarriesPinnedMyceliumCode' -count=1 -v >"$LOG" 2>&1; then
      if grep -q -- '--- PASS: TestPinnedMyceliumBytecode' "$LOG" && \
         grep -q -- '--- PASS: TestDeployTxCarriesPinnedMyceliumCode' "$LOG"; then
        ok "bytecode pins PASS (shipped bytes == the reviewed source)"
      else
        fail "pin tests did not both PASS — a skip is not a pass (is solc/the test being filtered out?)"
      fi
    else
      fail "bytecode pin tests failed"
    fi
    if go test ./internal/evm ./cmd/spore -count=1 >"$LOG" 2>&1; then
      ok "receipt gate + doc-claim tests green"
    else
      fail "receipt gate / doc-claim tests failed"
    fi
  else
    fail "go not found — cannot run the local test gates"
  fi

  if bash scripts/anvil_e2e.sh -s >"$LOG" 2>&1; then
    if grep -q 'SKIP:' "$LOG"; then
      unverified "local Anvil proof skipped (foundry not installed) — install foundry for release day"
    elif grep -q 'ANVIL E2E GREEN' "$LOG" && grep -q 'ON-CHAIN PROOF' "$LOG"; then
      ok "local Anvil two-party proof GREEN (burned slot reads back empty)"
    else
      fail "local Anvil proof ran but did not print the empty-slot proof"
    fi
  else
    fail "local Anvil proof failed (see scripts/anvil_e2e.sh output)"
  fi
  rm -f "$LOG"
else
  step "gate 0 — skipped (-skip-local)"
fi

# ---------------------------------------------------------------- gate 1
step "gate 1 — chain, key, and predicted address (read-only)"
if ! need_cast; then
  fail "cast not found — install foundry; the address derivation and creation-address prediction need it"
fi

RPC_CHAIN=$(cast chain-id --rpc-url "$RPC" 2>/dev/null || true)
if [ -z "$RPC_CHAIN" ]; then
  fail "no chain id from $RPC — is the RPC reachable?"
elif [ "$RPC_CHAIN" = "$EXPECT_CHAIN_ID" ]; then
  ok "chain id $RPC_CHAIN"
else
  fail "chain id is $RPC_CHAIN, expected $EXPECT_CHAIN_ID (a pointer sent here targets a different contract)"
fi

if [ -n "$ADDRESS_FLAG" ]; then
  ADDR="$ADDRESS_FLAG"
  ok "deployer $ADDR (from -address)"
else
  KEY="${!KEY_ENV:-}"
  if [ -z "$KEY" ]; then
    fail "no deployer: pass -address or set \$$KEY_ENV"
  else
    ADDR=$(cast wallet address --private-key "$KEY" 2>/dev/null || true)
    if [ -n "$ADDR" ]; then ok "deployer $ADDR (derived from \$$KEY_ENV)"; else fail "could not derive an address from \$$KEY_ENV (32-byte hex?)"; fi
  fi
fi

if [ -n "$ADDR" ]; then
  NONCE=$(cast nonce "$ADDR" --rpc-url "$RPC" 2>/dev/null || true)
  if [ -n "$NONCE" ]; then ok "deployer nonce $NONCE"; else fail "could not read the deployer nonce"; fi
  if [ -n "$NONCE" ]; then
    PRED=$(cast compute-address "$ADDR" --nonce "$NONCE" 2>/dev/null || true)
    if [ -n "$PRED" ]; then ok "predicted creation address $PRED (gate 4 must print exactly this)"; else fail "could not compute the creation address"; fi
  fi
fi

if [ -f "$BIN" ]; then
  ok "bytecode sha256 $(sha256sum "$BIN" | cut -d' ' -f1) ($BIN)"
else
  fail "$BIN not found — the deploy needs the pinned creation bytecode"
fi

# Post-deploy detection: adopt the predicted address as the mailbox only if a
# contract already lives there (an explicit -mailbox always wins).
if [ -z "$MAILBOX" ] && [ -n "$PRED" ]; then
  CODE_AT_PRED=$(cast code "$PRED" --rpc-url "$RPC" 2>/dev/null || echo "")
  if [ "$CODE_AT_PRED" = "0x" ] || [ -z "$CODE_AT_PRED" ]; then
    ok "no contract at the predicted address yet (pre-deploy run)"
  else
    info "a contract already exists at the predicted address — treating it as the deployed mailbox"
    MAILBOX="$PRED"
  fi
fi

# ---------------------------------------------------------------- gate 2
step "gate 2 — funding (read-only, live gas)"
if [ -z "$ADDR" ]; then
  fail "no deployer address — cannot price the deployment"
else
  if [ -z "$SPORE" ]; then
    SPORE="$(mktemp -d)/spore"
    if ! go build -o "$SPORE" ./cmd/spore; then
      fail "go build ./cmd/spore failed"
      SPORE=""
    fi
  fi
  if [ -n "$SPORE" ] && [ -x "$SPORE" ]; then
    est_args=(-rpc "$RPC" -from "$ADDR" -bin "$BIN" -rounds "$ROUNDS")
    if [ -n "$MAILBOX" ]; then est_args+=(-mailbox "$MAILBOX"); fi
    if EST=$("$SPORE" contract estimate "${est_args[@]}" 2>&1); then
      printf '%s\n' "$EST" | sed 's/^/    /'
      if printf '%s' "$EST" | grep -q "^estimates sent from $ADDR "; then
        ok "estimate is for the deployer address"
      else
        fail "estimate did not confirm the deployer address (estimates sent from …)"
      fi

      PRICE=$(printf '%s\n' "$EST" | sed -n 's/^gas price:[[:space:]]*\([0-9][0-9]*\) wei.*/\1/p' | head -1)
      DEPLOY_GAS=$(printf '%s\n' "$EST" | sed -n 's/^deploy[[:space:]]*\([0-9,]*\)[[:space:]]*gas.*/\1/p' | head -1 | tr -d ',')
      ROUND_GAS=$(printf '%s\n' "$EST" | sed -n 's/^deliver+burn[[:space:]]*\([0-9,]*\)[[:space:]]*gas.*/\1/p' | head -1 | tr -d ',')

      if [ -z "$PRICE" ] || [ -z "$DEPLOY_GAS" ]; then
        fail "could not read the gas price / deploy row out of the estimate"
      elif [ "${#PRICE}" -gt 12 ]; then
        unverified "gas price ${PRICE} wei is implausibly large — review the estimate by hand"
      else
        want=$(( DEPLOY_GAS * PRICE ))
        what="deploy"
        if [ -n "$ROUND_GAS" ]; then
          want=$(( want + ROUNDS * ROUND_GAS * PRICE ))
          what="deploy + $ROUNDS x (deliver+burn)"
        fi
        BAL=$(cast balance "$ADDR" --rpc-url "$RPC" 2>/dev/null || true)
        if [ -z "$BAL" ]; then
          fail "could not read the deployer balance"
        elif dec_ge "$BAL" "$want"; then
          ok "funded: $BAL wei >= $want wei required for $what"
        else
          fail "underfunded: $BAL wei < $want wei required for $what"
        fi
      fi
      if printf '%s' "$EST" | grep -q 'funding total:.*not computable'; then
        if [ -z "$MAILBOX" ]; then
          info "round budget not priced yet — re-run with -mailbox <addr> after gate 4"
        else
          fail "funding total is not computable even with a mailbox — deliver/burn pricing failed"
        fi
      fi
    else
      printf '%s\n' "$EST" | sed 's/^/    /'
      fail "spore contract estimate failed"
    fi
  fi
fi

# ---------------------------------------------------------------- verdict
step "verdict"
if [ "$BLOCKERS" -eq 0 ]; then
  printf '\n\033[1;32mGO\033[0m — every free read-only gate is green'
  if [ -n "$ADDR" ]; then printf ' for %s' "$ADDR"; fi
  if [ -n "$RPC_CHAIN" ]; then printf ' on chain %s' "$RPC_CHAIN"; fi
  printf '.\n'
  if [ -n "$PRED" ]; then printf 'Deploy must print: %s\n' "$PRED"; fi
  printf 'Next: gate 3 (Base Sepolia rehearsal, free but not read-only), then gate 4 — the one spending step. See docs/LIVE_NODES.md §3.\n'
  exit 0
fi
printf '\n\033[1;31mNO-GO\033[0m — %d blocker(s) above. Fix them (or fund the deployer) before spending anything.\n' "$BLOCKERS"
exit 1
