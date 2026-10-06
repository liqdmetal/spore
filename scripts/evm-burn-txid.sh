#!/usr/bin/env bash
# scripts/evm-burn-txid.sh — recover the burn transaction chain.Watch issues and
# deliberately never logs.
#
# The E2 receive path erases a delivered mailbox slot with a real
# `burn(to, seq)` transaction, best-effort and UNLOGGED by design: neither
# `spore msg recv-e2` nor the loopback `spore evm-proxy` prints the txid,
# because a burn failure must never look like a delivery failure. The chain
# keeps the transaction anyway — a burn is an ordinary tx from the recipient to
# the mailbox — and this is what reads it back out:
#
#   burn(address,uint256)  selector 0x9dc29fac
#   calldata               <selector><to word><seq word>
#   from                   the RECIPIENT's own address (the contract requires
#                          msg.sender == to, so only the recipient can burn its
#                          slot, which is what makes the match unambiguous)
#
# It exists because the §3 receipt used to describe the burn's ABSENCE —
# "unlogged by design, see the explorer" — in the one document whose job is to
# name what happened. A receipt that names the transaction is evidence; a
# receipt that explains why it cannot name it is a caveat. scripts/anvil_e2e.sh
# calls this and writes the txid into the receipt it produces, so the shipped
# burn note cites a real hash instead of an absence.
#
# Usage:
#   scripts/evm-burn-txid.sh -rpc URL -mailbox 0x… -recipient 0x… \
#                            [-from-block N] [-to-block N]
#     -rpc          JSON-RPC endpoint (any EVM chain)
#     -mailbox      the MyceliumMailbox address
#     -recipient    the address that signed the burn (party B)
#     -from-block   first block to scan (default 0 — pass the deliver tx's
#                   block, which is where a burn for that delivery can start)
#     -to-block     last block to scan (default: the current head)
#     -h, --help    this message
#
# Prints one line per matching burn, oldest first:
#   <txid> <seq> <block>
# Exit codes: 0 at least one burn found, 1 none found (an empty result is never
# a silent success), 2 cannot check (no RPC answer, or an unbounded window),
# 3 usage.
set -euo pipefail

RPC=""
MAILBOX=""
RECIPIENT=""
FROM_BLOCK=""
TO_BLOCK=""

# The selector is keccak256("burn(address,uint256)")[:4], the same signature
# internal/evm encodes (mailboxBurnSig in internal/evm/mailbox.go). If it ever
# drifts this finds nothing and exits 1 — a refusal, which is the failure
# direction a proof wants, never a quiet fallback to the old wording.
BURN_SEL="0x9dc29fac"

usage() { sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'; }

need() { # need FLAG VALUE
  [ $# -ge 2 ] || { echo "evm-burn-txid: $1 needs a value" >&2; exit 3; }
}
while [ $# -gt 0 ]; do
  case "$1" in
    -rpc) need "$@"; RPC=$2; shift 2 ;;
    -mailbox) need "$@"; MAILBOX=$2; shift 2 ;;
    -recipient) need "$@"; RECIPIENT=$2; shift 2 ;;
    -from-block) need "$@"; FROM_BLOCK=$2; shift 2 ;;
    -to-block) need "$@"; TO_BLOCK=$2; shift 2 ;;
    -h | --help | help) usage; exit 0 ;;
    *) echo "evm-burn-txid: unknown argument: $1 (see --help)" >&2; usage >&2; exit 3 ;;
  esac
done

[ -n "$RPC" ] || { echo "evm-burn-txid: -rpc is required (see --help)" >&2; exit 3; }
[ -n "$MAILBOX" ] || { echo "evm-burn-txid: -mailbox is required (see --help)" >&2; exit 3; }
[ -n "$RECIPIENT" ] || { echo "evm-burn-txid: -recipient is required (see --help)" >&2; exit 3; }
command -v curl >/dev/null 2>&1 || { echo "evm-burn-txid: curl is required" >&2; exit 2; }

is_addr() {
  local h=${1#0x}
  case "$1" in 0x*) ;; *) return 1 ;; esac
  [ ${#h} -eq 40 ] || return 1
  case "$h" in *[!0-9a-fA-F]*) return 1 ;; esac
  return 0
}
for v in MAILBOX RECIPIENT; do
  is_addr "${!v}" || { echo "evm-burn-txid: $v must be 0x + 40 hex, got '${!v}'" >&2; exit 3; }
done

lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }

rpc_call() { # rpc_call METHOD [PARAMS-JSON]
  curl -sf -m 20 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}
# rpc_result extracts a scalar "result" without jq: the result is a string.
rpc_result() { sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'; }
hex_to_dec() { # bash arithmetic reads 0x… as hex
  local h="$1"
  case "$h" in 0x[0-9a-fA-F]*) echo $(( h )) ;; *) echo "" ;; esac
}

# ---- the window ------------------------------------------------------------
# A burn cannot precede the delivery it composts, so callers pass the deliver
# tx's block. Scanning from genesis is only meaningful on a chain with a
# handful of blocks; refuse the unbounded form rather than spend an hour on a
# public RPC and then time out — an unanswerable question is exit 2, never an
# empty success.
# Both bounds are decimal block numbers; a 0x… form is accepted and converted,
# because that is the shape an RPC response carries and a 0x value pasted from
# one should not silently become a different block.
as_dec() { # as_dec VALUE -> decimal, or empty when it is not a block number
  case "$1" in
    '' ) echo "" ;;
    0x* ) hex_to_dec "$1" ;;
    *[!0-9]* ) echo "" ;;
    * ) echo "$1" ;;
  esac
}
for v in FROM_BLOCK TO_BLOCK; do
  val="$(as_dec "${!v}")"
  [ -n "$val" ] || [ -z "${!v}" ] ||
    { echo "evm-burn-txid: $v must be a block number, got '${!v}'" >&2; exit 3; }
  printf -v "$v" '%s' "$val"
done
if [ -z "$TO_BLOCK" ]; then
  HEAD_HEX="$(rpc_call eth_blockNumber | rpc_result || true)"
  TO_BLOCK="$(hex_to_dec "${HEAD_HEX:-}")"
  [ -n "$TO_BLOCK" ] || { echo "evm-burn-txid: the RPC never answered eth_blockNumber at $RPC" >&2; exit 2; }
fi
[ -n "$FROM_BLOCK" ] || FROM_BLOCK=0
WINDOW=$(( TO_BLOCK - FROM_BLOCK + 1 ))
if [ "$WINDOW" -gt 2000 ]; then
  echo "evm-burn-txid: the window is $WINDOW blocks ($FROM_BLOCK..$TO_BLOCK), too wide to scan block by block." >&2
  echo "  -> pass -from-block <the deliver tx's block>; a burn lands seconds after its delivery." >&2
  exit 2
fi

# ---- the scan --------------------------------------------------------------
# scan_txs BLOCK-JSON N prints one "txid seq block" line per burn in the block.
# It returns 1 when an RPC call inside it failed: a query that could not be
# made must never read as "no burn in this transaction", which is the one error
# this script cannot afford to swallow.
scan_txs() {
  local bjson=$1 n=$2 h tx tfrom tto tin word toword seqword bad=0
  # The block's own "hash" is in this list too; getTransactionByHash returns
  # null for it and the tx loop skips it. Matching only "hash" (not
  # parentHash/stateRoot/…) keeps the candidate list short.
  for h in $(printf '%s' "$bjson" | grep -oE '"hash":"0x[0-9a-fA-F]{64}"' | sed 's/"hash":"//; s/"//'); do
    tx="$(rpc_call eth_getTransactionByHash "[\"$h\"]" || true)"
    case "$tx" in
      ''|*'"error"'*) bad=1; continue ;;
      *'"result":null'*) continue ;;
    esac
    tfrom="$(printf '%s' "$tx" | sed -n 's/.*"from":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
    tto="$(printf '%s' "$tx" | sed -n 's/.*"to":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
    # Some clients answer "input", others "data"; take whichever is present.
    tin="$(printf '%s' "$tx" | sed -n 's/.*"input":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
    [ -n "$tin" ] || tin="$(printf '%s' "$tx" | sed -n 's/.*"data":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
    [ "$(lower "$tfrom")" = "$(lower "$RECIPIENT")" ] || continue
    [ "$(lower "$tto")" = "$(lower "$MAILBOX")" ] || continue
    case "$tin" in "$BURN_SEL"*) ;; *) continue ;; esac
    word="${tin#"$BURN_SEL"}"
    [ ${#word} -eq 128 ] || continue          # <to word><seq word>
    toword="${word:0:64}"
    seqword="${word:64}"
    # The ABI word carries the recipient's address right-aligned: the burn is
    # for the recipient's OWN slot, which is the contract's rule, not ours.
    case "$(lower "$toword")" in
      *"$(lower "${RECIPIENT#0x}")") ;;
      *) continue ;;
    esac
    seqword="$(printf '%s' "$seqword" | sed 's/^0*//')"
    [ -n "$seqword" ] || seqword=0
    printf '%s %d %d\n' "$h" "$(( 16#$seqword ))" "$n"
  done
  [ "$bad" -eq 0 ]
}

FOUND=0
n="$FROM_BLOCK"
while [ "$n" -le "$TO_BLOCK" ]; do
  BJSON="$(rpc_call eth_getBlockByNumber "[\"$(printf '0x%x' "$n")\",true]" || true)"
  case "$BJSON" in
    '' | *'"error"'*)
      echo "evm-burn-txid: no usable answer for block $n (eth_getBlockByNumber) — cannot tell a burn from an RPC error" >&2
      exit 2
      ;;
    *'"result":null'*)
      : ;;   # past the head: nothing mined, nothing to scan
    *)
      if ! OUT="$(scan_txs "$BJSON" "$n")"; then
        echo "evm-burn-txid: an eth_getTransactionByHash call failed while scanning block $n" >&2
        exit 2
      fi
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s\n' "$line"
        FOUND=$((FOUND + 1))
      done <<HITS
$OUT
HITS
      ;;
  esac
  n=$((n + 1))
done

if [ "$FOUND" -eq 0 ]; then
  echo "evm-burn-txid: no burn from $RECIPIENT to $MAILBOX in blocks $FROM_BLOCK..$TO_BLOCK ($RPC)" >&2
  echo "  -> the slot may never have been delivered, or the burn never landed (it is best-effort)." >&2
  exit 1
fi
