#!/usr/bin/env bash
# release-fill-rehearsal.sh — prove the fill step is EXECUTABLE and SATISFIABLE.
#
# Release day is: apply the flip, apply the fee notes, then fill every marker
# from the receipt. release-day-rehearsal.sh proves the first two. It cannot
# prove the third, because the third needs values — and until this script
# existed, only ONE direction of the fill had ever been shown:
#
#   the sweep flags a rehearsed tree   (scripts/release-day-rehearsal.sh)
#
# The other direction was assumption: that some complete set of values exists
# which makes the sweep go clean AND still satisfies the receipt gate. If it
# did not — a marker no rule reaches, a filled value the gate rejects, a
# registry entry the receipt does not cite — nobody would find out until the
# tag, when the placeholders are already in the release.
#
# So this runs the real thing, from a real deployment:
#
#   1. a scratch tree at HEAD with BOTH frozen passes applied (the real state
#      on release day, marker for marker)
#   2. a real anvil + a real `spore contract deploy-mycelium` — the receipt
#      values are actual addresses and txids from actual transactions
#   3. the runbook's OWN command, `spore contract estimate`, run twice exactly
#      as LIVE_NODES §3 step 1 tells the operator to (pre-deploy with -from,
#      post-deploy with -mailbox) — so the fee block is filled from the command
#      it quotes, parsed out of that command's real output
#   4. scripts/release-fill.sh fills the tree from those values
#
# and then requires all of the following, none of which anything else checks:
#
#   the sweep goes CLEAN      filling every marker is possible at all
#   the referee stays GREEN   the filled values satisfy the receipt gate
#   readiness loses a blocker the registry is populated by the fill, and the
#                             tree is still NOT ready (the tag body is unfilled)
#   refusals                  a duplicated receipt row is refused by the filler,
#                             and a registry address the §3 receipt does not
#                             cite is refused by the gate — the two mistakes a
#                             shape check cannot see
#
# It is the local, pre-tag companion to `scripts/anvil_e2e.sh`: same self-skip
# discipline, no funded key, no network, no jq. It does NOT prove gas reality
# (anvil is free) or that the receipt values are the real chain's — only that
# release day's substitution is mechanically possible and gated.
#
# Usage:
#   scripts/release-fill-rehearsal.sh [-a ANVIL_PORT] [-b SPORE_BINARY] [-s] [-k]
#     -a   anvil JSON-RPC port (default 18547)
#     -b   spore binary to drive (default: built fresh from the scratch tree)
#     -s   skip (exit 0) when anvil or the Go toolchain is missing, instead of
#          failing (exit 3). For gates/CI where foundry may be absent.
#     -k   keep the scratch tree + the anvil process (for inspection)
#
# Exit codes: 0 green (or self-skipped), 1 a proof step failed, 2 cannot check
# (missing patch, busy port), 3 a required tool is missing and -s was not
# given (never a silent pass), 130 interrupted.
set -euo pipefail

ANVIL_PORT=18547
SPORE=""
SKIP_IF_MISSING=0
KEEP=0

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }

while getopts "a:b:skh" opt; do
  case "$opt" in
    a) ANVIL_PORT=$OPTARG ;;
    b) SPORE=$OPTARG ;;
    s) SKIP_IF_MISSING=1 ;;
    k) KEEP=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spore-fill-rehearsal.XXXXXX")"
RPC="http://127.0.0.1:$ANVIL_PORT"

PATCH_FLIP="release-designs/v0.9.0-doc-flips.patch"
PATCH_FEE="release-designs/v0.9.0-fee-notes.patch"

# anvil's well-known dev accounts (public, documented, never funded). A is the
# deployer; B stands in for the Sepolia-side receipt address — the rehearsal is
# about the SUBSTITUTION machinery, not about which chain produced a value, and
# the two rows must hold DIFFERENT values or the filler refuses them.
KEY_A="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ADDR_A="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ADDR_B="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

PASS=0
ANVIL_PID=""
cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    printf 'workspace kept: %s (anvil %s, pid %s)\n' "$ROOT" "$RPC" "$ANVIL_PID"
    return
  fi
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true
  rm -rf "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

rpc_call() { # rpc_call METHOD [PARAMS-JSON]
  curl -sf -m 15 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}
rpc_result() { sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'; }
port_busy() { curl -s --connect-timeout 2 -o /dev/null "http://127.0.0.1:$1"; }

find_tool() { # find_tool NAME — PATH first, then cargo's bin (foundry installs there)
  if command -v "$1" >/dev/null 2>&1; then command -v "$1"; return 0; fi
  local c
  for c in "${HOME:-}/.cargo/bin/$1" "${HOME:-}/.cargo/bin/$1.exe" \
           "${USERPROFILE:-}/.cargo/bin/$1.exe" "${USERPROFILE:-}/.cargo/bin/$1"; do
    [ -n "$c" ] && [ -x "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

# gitx pins line endings: this repository is stored LF and core.autocrlf=true is
# set on this box, so a plain `git apply` would rewrite the docs to CRLF and
# fail the gate's fee-notes claim on an otherwise perfect fill.
gitx() { git -c core.autocrlf=false -c core.eol=lf "$@"; }

# ---- preconditions ---------------------------------------------------------
for tool in git tar mktemp curl; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "release-fill-rehearsal: $tool not found — cannot check" >&2
    exit 2
  }
done

missing=""
command -v go >/dev/null 2>&1 || missing="$missing go"
ANVIL_BIN="$(find_tool anvil || true)"
[ -n "$ANVIL_BIN" ] || missing="$missing anvil"
if [ -n "$missing" ]; then
  if [ "$SKIP_IF_MISSING" -eq 1 ]; then
    echo "SKIP release-fill rehearsal: not installed:$missing (self-skip)"
    exit 0
  fi
  echo "release-fill-rehearsal: not installed:$missing — install it, or pass -s to skip" >&2
  exit 3
fi

for p in "$REPO_ROOT/$PATCH_FLIP" "$REPO_ROOT/$PATCH_FEE" "$REPO_ROOT/scripts/release-fill.sh"; do
  [ -f "$p" ] || {
    echo "release-fill-rehearsal: $p is missing — cannot rehearse the fill" >&2
    exit 2
  }
done

if port_busy "$ANVIL_PORT"; then
  echo "release-fill-rehearsal: port $ANVIL_PORT already serves HTTP — pass -a with a free port" >&2
  echo "  (a stale anvil would serve the wrong chain and make this proof lie)" >&2
  exit 2
fi

sha=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')
echo "== release-fill rehearsal: can release day's fill actually be completed? =="
echo "tree:   HEAD $sha + both frozen passes"
echo "chain:  anvil at $RPC ($ANVIL_BIN)"
echo "fill:   scripts/release-fill.sh"

# ---- the tree release day will be looking at -------------------------------
work="$ROOT/tree"
mkdir -p "$work"
git -C "$REPO_ROOT" -c core.autocrlf=false archive HEAD | tar -x -C "$work"
git init -q "$work"

# The fill driver is not part of what is being rehearsed — it IS the thing under
# test — so it comes from the checkout that invoked this script, not from HEAD.
# That also lets the rehearsal run against a driver that is not committed yet,
# which is exactly when you want to run it; in CI the copy is a no-op. The
# referee's marker-coverage test reads the driver from the tree, so it has to be
# there either way.
for s in scripts/release-fill.sh scripts/release-fill-rehearsal.sh; do
  [ -f "$REPO_ROOT/$s" ] || continue
  mkdir -p "$work/$(dirname "$s")"
  cp "$REPO_ROOT/$s" "$work/$s"
done

cd "$work"
step "apply both frozen passes (the release-day starting state)"
gitx apply "$REPO_ROOT/$PATCH_FLIP" || fail "the frozen flip does not apply to HEAD $sha"
gitx apply "$REPO_ROOT/$PATCH_FEE" || fail "the fee patch does not apply on top of the flip"

# The release surfaces are whatever the two passes write — the same derivation
# scripts/release-fill.sh and scripts/release-placeholders.sh use, so a surface
# cannot be filled here and missed there.
SURFACES=$(awk '/^\+\+\+ /{print $2}' "$PATCH_FLIP" "$PATCH_FEE" | sed 's|^b/||' | sort -u)
MARKER_RE='<DRYRUN-[A-Za-z0-9 -]*>|<<[A-Za-z0-9 _-]*>>|0x0{30,}'
# `|| true`: with pipefail an empty match is a non-zero pipeline, and set -e
# would then kill the rehearsal instead of reporting the count.
markers=$(grep -ohE "$MARKER_RE" $SURFACES 2>/dev/null | wc -l | tr -d ' ' || true)
[ "$markers" -gt 0 ] || fail "the applied tree carries no markers — there is nothing for this rehearsal to prove"
ok "flip + fees applied; $markers marker line(s) to fill"

# A snapshot of the UNFILLED surfaces, for the refusal control. The filler
# short-circuits to "nothing to fill" on an already-filled tree — right for a
# re-run, but it would make that control vacuous.
prefill="$ROOT/prefill"
for f in $SURFACES; do
  mkdir -p "$prefill/$(dirname "$f")"
  cp "$work/$f" "$prefill/$f"
done
mkdir -p "$prefill/release-designs"
cp "$PATCH_FLIP" "$PATCH_FEE" "$prefill/release-designs/"

step "build: the scratch tree's own spore"
if [ -z "$SPORE" ]; then
  SPORE="$ROOT/spore"
  go build -o "$SPORE" ./cmd/spore || fail "go build failed"
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
ok "chain $((CHAIN_ID)) up"

step "the receipt: a real deploy and two real transactions"
SPORE_EVM_PRIVATE_KEY="$KEY_A" "$SPORE" contract deploy-mycelium \
  -rpc "$RPC" -wait 2m -bin "$work/tools/mycelium.bin" >"$ROOT/deploy.log" 2>&1 ||
  { cat "$ROOT/deploy.log"; fail "deploy-mycelium failed"; }
MAINNET_ADDR="$(grep 'contract addr:' "$ROOT/deploy.log" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)"
MAINNET_TX="$(grep -oE '0x[0-9a-f]{64}' "$ROOT/deploy.log" | head -1)"
[ -n "$MAINNET_ADDR" ] && [ -n "$MAINNET_TX" ] ||
  { cat "$ROOT/deploy.log"; fail "the deploy printed no address/txid to fill the receipt with"; }

# Two more real transactions, so every value the filler accepts is a real hash
# from a real tx rather than a plausible-looking constant.
send_tx() {
  # anvil takes by-position params for this method: a bare object is rejected
  # with "invalid type: map, expected a sequence".
  rpc_call eth_sendTransaction \
    "[{\"from\":\"$ADDR_A\",\"to\":\"$ADDR_B\",\"value\":\"0x1\"}]" | rpc_result
}
SEPOLIA_TX="$(send_tx)"
DELIVER_TX="$(send_tx)"
for h in "$SEPOLIA_TX" "$DELIVER_TX"; do
  case "$h" in 0x*) ;; *) fail "anvil returned no tx hash for a rehearsal transaction" ;; esac
done
DEPLOYER="$(printf '%s' "$ADDR_A" | tr 'A-F' 'a-f')"
SEPOLIA_ADDR="$(printf '%s' "$ADDR_B" | tr 'A-F' 'a-f')"
ok "mailbox $MAINNET_ADDR (tx $MAINNET_TX) + 2 fills; $MAINNET_TX != $SEPOLIA_TX != $DELIVER_TX"

step "the runbook's own command, run the way it says to run it"
# LIVE_NODES §3 step 1: once with -from only for the deploy row, then again with
# -mailbox for deliver/burn and the funding total. Doing it in that order is the
# point — the fee block is filled from the command it quotes.
(cd "$work" && "$SPORE" contract estimate -rpc "$RPC" -from "$DEPLOYER" -rounds 5) \
  >"$ROOT/estimate-pre.log" 2>&1 || { cat "$ROOT/estimate-pre.log"; fail "the pre-deploy estimate failed"; }
grep -q '^deploy ' "$ROOT/estimate-pre.log" || { cat "$ROOT/estimate-pre.log"; fail "the pre-deploy estimate printed no deploy row"; }
(cd "$work" && "$SPORE" contract estimate -rpc "$RPC" -from "$DEPLOYER" \
  -mailbox "$MAINNET_ADDR" -rounds 5) >"$ROOT/estimate.log" 2>&1 ||
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
EST_DATE="$(date -u +%Y-%m-%d)"
for v in EST_GAS_PRICE EST_DEPLOY_GAS EST_DEPLOY_ETH EST_DELIVER_GAS EST_DELIVER_ETH \
         EST_BURN_GAS EST_BURN_ETH EST_ROUND_ETH EST_N_ROUNDS EST_FUNDING_TOTAL; do
  [ -n "${!v:-}" ] || { cat "$ROOT/estimate.log"; fail "could not parse $v out of the estimator output"; }
done
[ "$EST_N_ROUNDS" = "5" ] || fail "the funding total reports $EST_N_ROUNDS rounds, asked for 5 — the parse is wrong"
ok "gas price $EST_GAS_PRICE wei; deploy $EST_DEPLOY_GAS gas; round $EST_ROUND_ETH; total $EST_FUNDING_TOTAL ($EST_N_ROUNDS rounds)"

cat >"$ROOT/values" <<VALUES
# generated by scripts/release-fill-rehearsal.sh from a real local deployment.
# The Sepolia row carries anvil's second account and a real tx hash: the two
# receipt rows must hold different values, and the rehearsal is about the
# substitution, not about which chain produced a number.
SEPOLIA_ADDR=$SEPOLIA_ADDR
SEPOLIA_TX=$SEPOLIA_TX
SEPOLIA_DATE=$EST_DATE
MAINNET_ADDR=$MAINNET_ADDR
MAINNET_TX=$MAINNET_TX
MAINNET_DATE=$EST_DATE
DEPLOYER=$DEPLOYER
DELIVER_TX=$DELIVER_TX
EST_DATE=$EST_DATE
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
VALUES

# ---- the direction nobody had proven ---------------------------------------
step "fill the tree, then require the tree to be CLEAN"
# readiness is read before and after: the fill must clear exactly the marker
# blocker and leave the tag-body blocker alone. A fill that cleared both would
# mean the aggregator is blind; one that cleared neither would mean the fill
# did nothing the aggregator can see.
# readiness exits 1 while blocked, which is the normal state here: `|| true`
# keeps pipefail from turning the count into a dead rehearsal.
blockers() {
  (cd "$work" && bash scripts/release-readiness.sh 2>/dev/null || true) |
    sed -n 's/^NOT READY TO TAG — \([0-9]*\) blocker.*/\1/p'
}
[ -f "$work/scripts/release-readiness.sh" ] || fail "the rehearsed tree has no readiness aggregator to measure against"
b0="$(blockers)"
[ -n "$b0" ] || fail "release-readiness.sh reported nothing parseable before the fill"
ok "readiness before the fill: $b0 blocker(s)"

# --local-proof: every value here is anvil's, which is the point of the
# rehearsal. release-fill.sh refuses those accounts by default, so a receipt
# that could only have come from a local run cannot be shipped by accident.
if ! bash "$REPO_ROOT/scripts/release-fill.sh" -C "$work" --local-proof \
  -in "$ROOT/values" >"$ROOT/fill.log" 2>&1; then
  cat "$ROOT/fill.log" >&2
  fail "the fill refused a complete set of values taken from a real deployment"
fi
ok "the fill ran: $(grep -c '  <--  ' "$ROOT/fill.log") rule(s) applied"

if ! (cd "$work" && bash scripts/release-placeholders.sh --quiet); then
  (cd "$work" && bash scripts/release-placeholders.sh) >&2 || true
  fail "the placeholder sweep still flags the filled tree — the fill cannot be completed"
fi
ok "the placeholder sweep is CLEAN on the filled tree (first time this direction is proven)"

step "the referee: filled values must satisfy the receipt gate"
t0=$SECONDS
if ! (cd "$work" && go test ./internal/evm ./cmd/spore -count=1) >"$ROOT/referee.log" 2>&1; then
  grep -E '^(---|    |#)' "$ROOT/referee.log" | head -30 >&2
  fail "the receipt gate rejects the filled tree"
fi
ok "receipt gate GREEN on the filled tree ($((SECONDS - t0))s)"

b1="$(blockers)"
[ -n "$b1" ] || fail "release-readiness.sh reported nothing parseable after the fill"
if [ "$b1" -ne $((b0 - 1)) ]; then
  fail "readiness went $b0 -> $b1; the fill must clear exactly the marker blocker"
fi
[ "$b1" -ge 1 ] || fail "readiness called the filled tree ready to tag — the tag body is still unfilled"
ok "readiness $b0 -> $b1: the marker blocker cleared, the unfilled tag body still blocks"

# ---- the mistakes no shape check can see -----------------------------------
step "negative control 1: the filler refuses a copy-pasted receipt row"
# The failure this catches: the Base mainnet row filled from the Sepolia row.
# Both addresses are valid, both are cited in §3, and the registry would ship a
# TESTNET mailbox as the mainnet default with every existing gate satisfied.
# It runs against the UNFILLED snapshot, where the markers still are.
sed "s/^MAINNET_ADDR=.*/MAINNET_ADDR=$SEPOLIA_ADDR/" "$ROOT/values" >"$ROOT/values-dup"
pre_sha="$(sha256sum "$prefill/docs/LIVE_NODES.md" | awk '{print $1}')"
if bash "$REPO_ROOT/scripts/release-fill.sh" -C "$prefill" --local-proof \
  -in "$ROOT/values-dup" >"$ROOT/dup.log" 2>&1; then
  fail "the filler accepted a values file whose mainnet row IS the Sepolia row"
fi
grep -q 'the same mailbox addresses' "$ROOT/dup.log" ||
  { cat "$ROOT/dup.log" >&2; fail "the filler refused the duplicate row for the wrong reason"; }
[ "$pre_sha" = "$(sha256sum "$prefill/docs/LIVE_NODES.md" | awk '{print $1}')" ] ||
  fail "the refused fill still modified the tree"
ok "refused, and left the unfilled tree byte-identical"

# before_sha guards the second control's perturbation and its restore.
before_sha="$(sha256sum "$work/internal/evm/mailboxdefaults.go" | awk '{print $1}')"

step "negative control 2: the gate refuses a registry address §3 does not cite"
cp "$work/internal/evm/mailboxdefaults.go" "$ROOT/registry.bak"
perturbed="0xdead000000000000000000000000000000000001"
# the shipped address appears exactly once in the registry, so a plain
# substitution cannot miss
sed "s|\"$MAINNET_ADDR\"|\"$perturbed\"|" "$ROOT/registry.bak" >"$work/internal/evm/mailboxdefaults.go"
grep -q "$perturbed" "$work/internal/evm/mailboxdefaults.go" || fail "could not perturb the registry address"
rc=0
(cd "$work" && go test ./internal/evm -run TestShippedMailboxDefaultsCarryReceipts -count=1) \
  >"$ROOT/neg.log" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "  the gate passed with registry address $perturbed, which no receipt cites" >&2
  fail "the receipt gate does not tie the shipped address to the §3 receipt"
fi
grep -q 'is not cited anywhere in docs/LIVE_NODES.md' "$ROOT/neg.log" ||
  { grep -E '^(---|    )' "$ROOT/neg.log" | head -20 >&2; fail "the gate failed, but not on the missing receipt citation"; }
cp "$ROOT/registry.bak" "$work/internal/evm/mailboxdefaults.go"
[ "$before_sha" = "$(sha256sum "$work/internal/evm/mailboxdefaults.go" | awk '{print $1}')" ] ||
  fail "the registry was not restored byte-identically after the negative control"
ok "gate RED without its receipt, and the registry restored byte-identically"

printf '\n\033[1;32mRELEASE-FILL REHEARSAL GREEN\033[0m — %d checks. A complete fill of HEAD %s clears the sweep and keeps the receipt gate green.\n' \
  "$PASS" "$sha"
printf 'Remaining before the tag: the §3 receipt values themselves (this proved the machinery, not the chain).\n'
