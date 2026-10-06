#!/usr/bin/env bash
# release-fill.sh — the last release step that was still prose: "fill them in".
#
# The two frozen passes are deliberately full of markers, because they have to
# apply before the deployment exists:
#
#   <DRYRUN-…>      the dry run's synthetic receipt values (addresses, txids)
#   0x000…8e2a      the dry run's Sepolia placeholder mailbox address
#   0x000…8453      the dry run's Base placeholder mailbox address
#   2026-10-06      the dry run's date, hardcoded on the two receipt rows
#   <<EST-…>>       the measured fee numbers, plus <<ADDR>>/<<DEPLOYER>>
#
# Every one has to become a real value before the tag, and `scripts/
# release-placeholders.sh` can only say THAT markers remain — not what to put
# there. So the substitution was a hand edit under time pressure, on the one
# day the repository must not lie, with a placeholder address as the failure
# mode (a 0x + 40-hex placeholder satisfies every other check in the repo).
#
# This script makes it a command with two guarantees a hand edit cannot give:
#
#   total     after it runs, ZERO markers remain on the release surfaces, or
#             it refuses and restores every file it touched.
#   anchored  every rule fires EXACTLY the expected number of times, so a
#             marker that moved (the patches were re-derived) is a refusal,
#             never a silently missed line. The date counts as a value for the
#             same reason: it was a hardcoded 2026-10-06 that no gate could
#             see, and it is now a fill value, so forgetting it refuses.
#
# The surfaces are read straight out of the two patches' `+++ b/…` headers, so
# the list cannot rot: whatever the passes write is what gets filled.
#
#   bash scripts/release-fill.sh --keys               # the values-file template
#   bash scripts/release-fill.sh --check              # do the anchors resolve? (no values needed)
#   bash scripts/release-fill.sh --check -in values   # dry run: validate + simulate, write nothing
#   bash scripts/release-fill.sh -in values           # fill this tree
#   bash scripts/release-fill.sh -C /path/tree -in values
#
# --check with no values is the drift guard CI can afford: it proves the
# recipe still matches the frozen patches without touching anything, and it
# exits 0 on a tree where the passes are not applied (nothing to fill).
#
# The values file is a receipt, and scripts/anvil_e2e.sh now WRITES one from its
# own proof (`-r FILE`), so the hex strings stop being hand-typed — including
# BURN_TX, the one the receive path issues and never logs, which the proof
# recovers from chain state via scripts/evm-burn-txid.sh rather than leaving the
# §3 burn note to describe the burn's absence. Two rules follow from that, and
# they are the reason this script is the receipt's definition rather than a
# second copy of its format:
#
#   * a receipt naming anvil's documented dev accounts is refused, because
#     those addresses can only come from a local proof and would otherwise ship
#     as the default mailbox. --local-proof accepts them, for the rehearsals
#     whose whole point is a local proof.
#   * -in on a tree with nothing to fill still validates the receipt, so the
#     artifact the proof writes is checked on every push instead of on the one
#     day it is used for real.
#
# Exit codes: 0 filled (or nothing to fill), 1 refused — incomplete values,
# a marker whose anchor moved, or a marker left behind; 2 cannot check
# (patch missing); 3 usage.
set -euo pipefail

ROOT="."
VALUES=""
CHECK=0
SHOW_KEYS=0
LOCAL_PROOF=0

usage() {
  cat <<'USAGE'
usage: bash scripts/release-fill.sh [-C DIR] [-in FILE] [--check] [--keys] [--local-proof]

  -C DIR      the tree to fill (default: the current directory). The two frozen
              patches must be present at release-designs/ under it.
  -in FILE    key=value values file. See --keys for the keys and their shapes.
              On a tree with nothing to fill it is still validated, not applied.
  --check     verify the recipe against the tree and write nothing. With -in,
              also validate the values and simulate the whole fill; without
              -in, only prove every marker's anchor still resolves.
  --local-proof
              accept a receipt whose addresses are anvil's documented dev
              accounts — a local proof, never a deployment. Rehearsals pass it;
              release day must not.
  --keys      print the values-file template
  -h, --help  this message
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -C)
      [ $# -ge 2 ] || { echo "release-fill: -C needs a directory" >&2; exit 3; }
      ROOT=$2; shift 2 ;;
    -in | --in)
      [ $# -ge 2 ] || { echo "release-fill: -in needs a file" >&2; exit 3; }
      VALUES=$2; shift 2 ;;
    --check) CHECK=1; shift ;;
    --local-proof) LOCAL_PROOF=1; shift ;;
    --keys) SHOW_KEYS=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "release-fill: unknown argument: $1 (see --help)" >&2; usage >&2; exit 3 ;;
  esac
done

PATCH_FLIP=release-designs/v0.9.0-doc-flips.patch
PATCH_FEE=release-designs/v0.9.0-fee-notes.patch

# The same shape release-placeholders.sh sweeps for. Kept in step with it on
# purpose: this script's post-condition is that the shipped sweep has nothing
# left to find.
MARKER_RE='<DRYRUN-[A-Za-z0-9 -]*>|<<[A-Za-z0-9 _-]*>>|0x0{30,}'

# Addresses only a local anvil run can produce: its two well-known dev accounts
# (public, funded by nobody) and 0x5fbd…aa03, which is where account 0's first
# deployment deterministically lands — the address every local mailbox in this
# repo has been deployed at. A real deployment cannot be any of them, so a
# receipt naming one is a local proof, and a local proof shipped as the default
# mailbox is precisely the failure this repository's release gates exist to
# prevent. Refused unless --local-proof says the caller means it.
ANVIL_ONLY_ADDRS='0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266|0x70997970c51812dc3a010c7d01b50e0d17dc79c8|0x5fbdb2315678afecb367f032d93f642f64180aa3'

# ---- the rule table --------------------------------------------------------
# VALUE | MARKER (written verbatim, exactly as the patches write it) | how many
# times it must fire | the line it belongs to (empty = anywhere).
#
# VALUE is either a values-file key, or a literal the recipe carries itself
# when prefixed with '='. The literal form exists for prose the frozen patch
# writes that is only true BEFORE the fill — the registry comment that calls
# the shipped address a "dry-run placeholder". That is a claim, not a
# placeholder, and no sweep can see it (it is ordinary prose), yet it would sit
# next to the real address in the shipped source. The filler owns it, so the
# operator never has to retype prose from a receipt.
#
# The order matters only for readability: every marker is distinct, and no
# substituted value can invent another rule's marker (values are validated
# against MARKER_RE before anything is written).
#
# The two creation-tx markers are the reason lines are anchored at all: the
# dry run wrote the SAME `0x<DRYRUN-TX>` on the Sepolia row and the mainnet
# row, so a global replace would have published one chain's txid as the
# other's. Same for the two dates.
RULES=(
  "SEPOLIA_ADDR|0x0000000000000000000000000000000000008e2a|1|"
  "MAINNET_ADDR|0x0000000000000000000000000000000000008453|3|"
  "SEPOLIA_TX|0x<DRYRUN-TX>|1|Base Sepolia rehearsal"
  "MAINNET_TX|0x<DRYRUN-TX>|1|- Base mainnet"
  "SEPOLIA_DATE|2026-10-06|1|Base Sepolia rehearsal"
  "MAINNET_DATE|2026-10-06|1|- Base mainnet"
  "DEPLOYER|0x<DRYRUN-DEPLOYER>|1|"
  "DELIVER_TX|0x<DRYRUN-DELIVER-TX>|1|"
  # The burn txid the receive path does not log (chain.Watch issues the burn
  # best-effort and prints nothing). It rides the same §3 proof line as the
  # deliver txid, so a published burn note can name the transaction instead of
  # explaining that it cannot.
  "BURN_TX|0x<DRYRUN-BURN-TX>|1|"
  "EST_DATE|<<EST-DATE>>|1|"
  "EST_GAS_PRICE|<<EST-GAS-PRICE>>|1|"
  "EST_DEPLOY_GAS|<<EST-DEPLOY-GAS>>|1|"
  "EST_DEPLOY_ETH|<<EST-DEPLOY-ETH>>|1|"
  "EST_DELIVER_GAS|<<EST-DELIVER-GAS>>|1|"
  "EST_DELIVER_ETH|<<EST-DELIVER-ETH>>|1|"
  "EST_BURN_GAS|<<EST-BURN-GAS>>|1|"
  "EST_BURN_ETH|<<EST-BURN-ETH>>|1|"
  "EST_ROUND_ETH|<<EST-ROUND-ETH>>|1|"
  "EST_N_ROUNDS|<<EST-N-ROUNDS>>|1|"
  "EST_FUNDING_TOTAL|<<EST-FUNDING-TOTAL>>|1|"
  # The fee block quotes the receipt address and deployer inside its own
  # command line. They are filled from the SAME values the receipt rows use,
  # so the two can never disagree.
  "MAINNET_ADDR|<<ADDR>>|1|"
  "DEPLOYER|<<DEPLOYER>>|1|"
  # Not a marker: a comment the flip installs alongside the placeholder address
  # that would otherwise ship next to the real one.
  "=// the shipped Base mainnet default (lowercase, 0x + 40 hex)|// dry-run placeholder (lowercase, 0x + 40 hex)|1|Address:"
)

if [ "$SHOW_KEYS" -eq 1 ]; then
  cat <<'TEMPLATE'
# release-fill values — fill from the LIVE_NODES section-3 receipt (Phase A and
# Phase B outputs) and the saved `spore contract estimate` output. Lowercase
# hex addresses/txids, no 0x-checksummed forms; the deployer is the funded key
# that sent the deployment.
#
# addresses: 0x + 40 lowercase hex    txids: 0x + 64 lowercase hex
# dates:     YYYY-MM-DD               EST_*: exactly as the command printed it
#            (estimate rows carry commas in gas and an " ETH" unit in cost)

SEPOLIA_ADDR=0x                                     # Sepolia mailbox address
SEPOLIA_TX=0x                                       # its creation txid
SEPOLIA_DATE=YYYY-MM-DD                             # the Sepolia rehearsal date
MAINNET_ADDR=0x                                     # Base mainnet mailbox address (also the registry entry)
MAINNET_TX=0x                                       # its creation txid
MAINNET_DATE=YYYY-MM-DD                             # the Base mainnet deployment date
DEPLOYER=0x                                         # the funded key that deployed it
DELIVER_TX=0x                                       # one deliver txid from the two-party proof
BURN_TX=0x                                          # the burn txid for that delivery (recovered from chain state)

# From the post-deploy `spore contract estimate -rpc … -from … -mailbox …` run.
EST_DATE=YYYY-MM-DD
EST_GAS_PRICE=                                      # wei, as printed
EST_DEPLOY_GAS=
EST_DEPLOY_ETH=
EST_DELIVER_GAS=
EST_DELIVER_ETH=
EST_BURN_GAS=
EST_BURN_ETH=
EST_ROUND_ETH=                                      # the deliver+burn row
EST_N_ROUNDS=                                       # the -rounds you funded for
EST_FUNDING_TOTAL=                                  # the command's funding total
TEMPLATE
  exit 0
fi

cd "$ROOT" 2>/dev/null || {
  echo "release-fill: no such directory: $ROOT" >&2
  exit 2
}

for p in "$PATCH_FLIP" "$PATCH_FEE"; do
  [ -f "$p" ] || {
    echo "release-fill: $p is missing — the frozen passes are what define the release surfaces" >&2
    exit 2
  }
done

# The surfaces, from the patches' own file headers: whatever the two passes
# write is exactly what release day has to fill.
SURFACES=$(awk '/^\+\+\+ /{print $2}' "$PATCH_FLIP" "$PATCH_FEE" | sed 's|^b/||' | sort -u)
[ -n "$SURFACES" ] || {
  echo "release-fill: the patches name no files — cannot derive the release surfaces" >&2
  exit 2
}
for f in $SURFACES; do
  [ -f "$f" ] || {
    echo "release-fill: a release surface named by the patches is not in $ROOT: $f" >&2
    echo "  (the passes are not applied to this tree yet — apply the flip, then the fees)" >&2
    exit 2
  }
done

# shellcheck disable=SC2086
markers_now() { grep -ohE "$MARKER_RE" $SURFACES 2>/dev/null | sort -u || true; }

# ---- counting, without a values file ---------------------------------------
# count_rule MARKER ANCHOR -> how many times the marker fires on lines carrying
# ANCHOR (empty ANCHOR = every line), across every release surface.
count_rule() {
  MARKER=$1 ANCHOR=${2:-} awk '
    BEGIN { m = ENVIRON["MARKER"]; a = ENVIRON["ANCHOR"]; lm = length(m); n = 0 }
    {
      if (a != "" && index($0, a) == 0) next
      s = $0
      while ((p = index(s, m)) > 0) { n++; s = substr(s, p + lm) }
    }
    END { print n + 0 }
  ' $SURFACES
}

# ---- values ----------------------------------------------------------------
declare -A V=()
REQUIRED_KEYS=""
for r in "${RULES[@]}"; do
  k=${r%%|*}
  case "$k" in =*) continue ;; esac   # a literal the recipe carries needs no values file
  case " $REQUIRED_KEYS " in *" $k "*) ;; *) REQUIRED_KEYS="$REQUIRED_KEYS $k" ;; esac
done

is_addr() {
  local h=${1#0x}
  case "$1" in 0x*) ;; *) return 1 ;; esac
  [ ${#h} -eq 40 ] || return 1
  case "$h" in *[!0-9a-f]*) return 1 ;; esac
  case "$h" in *[!0]*) return 0 ;; *) return 1 ;; esac   # reject the all-zero placeholder
}
is_tx() {
  local h=${1#0x}
  case "$1" in 0x*) ;; *) return 1 ;; esac
  [ ${#h} -eq 64 ] || return 1
  case "$h" in *[!0-9a-f]*) return 1 ;; esac
}
is_date() {
  case "$1" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) return 0 ;;
    *) return 1 ;;
  esac
}

load_values() {
  local line key val problems=0 a b what tx safe
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) echo "release-fill: not a key=value line: $line" >&2; problems=1; continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    # trim surrounding blanks so a trailing space cannot become part of a value
    key=$(printf '%s' "$key" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    val=$(printf '%s' "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$key" ] || continue
    case " $REQUIRED_KEYS " in
      *" $key "*) ;;
      *) echo "release-fill: '$key' is not a fill key (typo? see --keys)" >&2; problems=1; continue ;;
    esac
    V["$key"]=$val
  done < "$VALUES"
  # every key the rule table needs must be present, or the fill is incomplete
  for key in $REQUIRED_KEYS; do
    if [ -z "${V[$key]:-}" ]; then
      echo "release-fill: $VALUES has no value for $key — an incomplete receipt is a false claim, not a partial fill" >&2
      problems=1
    fi
  done
  # shapes: a value that is itself a marker would move the problem, not fix it
  for key in "${!V[@]}"; do
    val=${V[$key]}
    case "$val" in
      *'<'*|*'>'*)
        echo "release-fill: $key=$val still looks like a marker" >&2
        problems=1
        continue
        ;;
    esac
    case "$key" in
      DEPLOYER | *_ADDR)
        if ! is_addr "$val"; then
          echo "release-fill: $key must be 0x + 40 lowercase hex (and not all-zero), got '$val'" >&2
          problems=1
        elif printf '%s' "$val" | grep -qE "^($ANVIL_ONLY_ADDRS)$"; then
          if [ "$LOCAL_PROOF" -eq 1 ]; then
            :
          else
            echo "release-fill: $key is an address only a local anvil run produces ($val)." >&2
            echo "  -> it can never be a deployment receipt. Re-run against the real chain," >&2
            echo "     or pass --local-proof when the point IS a local proof." >&2
            problems=1
          fi
        fi ;;
      *_TX)
        is_tx "$val" || { echo "release-fill: $key must be 0x + 64 lowercase hex, got '$val'" >&2; problems=1; } ;;
      *_DATE)
        is_date "$val" || { echo "release-fill: $key must be YYYY-MM-DD, got '$val'" >&2; problems=1; } ;;
      EST_*)
        case "$val" in
          *[0-9]*) ;;
          *) echo "release-fill: $key='$val' has no digit — paste the estimator's value" >&2; problems=1 ;;
        esac ;;
      *)
        echo "release-fill: no shape rule for $key (internal error)" >&2; problems=1 ;;
    esac
  done

  # Cross-field consistency. Every value above is individually well shaped, so
  # these are the mistakes a shape check cannot see.
  #
  # The two receipt rows are two DIFFERENT chains' deployments. Pasting one
  # row's values into the other is the mistake this guard exists for: the
  # registry would then ship the TESTNET mailbox as the Base mainnet default,
  # and nothing else in the repo would notice — the address is still cited in
  # §3, so the receipt gate is satisfied by a receipt that is itself wrong.
  for pair in "SEPOLIA_ADDR MAINNET_ADDR:mailbox addresses" \
              "SEPOLIA_TX MAINNET_TX:creation txids"; do
    a=${pair%% *}
    b=${pair#* }
    b=${b%%:*}
    what=${pair#*:}
    [ -n "${V[$a]:-}" ] && [ -n "${V[$b]:-}" ] || continue
    if [ "${V[$a]}" = "${V[$b]}" ]; then
      echo "release-fill: $a and $b are the same $what (${V[$a]})" >&2
      echo "  -> that is one receipt row copied into the other; two chains cannot share it" >&2
      problems=1
    fi
  done
  for tx in SEPOLIA_TX MAINNET_TX; do
    [ -n "${V[$tx]:-}" ] && [ -n "${V[DELIVER_TX]:-}" ] || continue
    if [ "${V[DELIVER_TX]}" = "${V[$tx]}" ]; then
      echo "release-fill: DELIVER_TX equals $tx — a deliver is not a contract creation" >&2
      problems=1
    fi
  done
  # The burn txid is a fourth transaction. The DRY RUN wrote one
  # `0x<DRYRUN-TX>` marker for every txid in the patches, so a receipt that
  # leaves two of these equal is a receipt that was copied, not measured — and
  # a §3 note naming the wrong transaction as the burn is exactly the kind of
  # false claim this fill exists to make impossible.
  for pair in "DELIVER_TX BURN_TX:a deliver is not the burn" \
              "SEPOLIA_TX BURN_TX:a contract creation is not the burn" \
              "MAINNET_TX BURN_TX:a contract creation is not the burn"; do
    a=${pair%% *}
    b=${pair#* }
    b=${b%%:*}
    what=${pair#*:}
    [ -n "${V[$a]:-}" ] && [ -n "${V[$b]:-}" ] || continue
    if [ "${V[$a]}" = "${V[$b]}" ]; then
      echo "release-fill: $a and $b are the same txid (${V[$a]}) — $what" >&2
      problems=1
    fi
  done
  for safe in SEPOLIA_ADDR MAINNET_ADDR; do
    [ -n "${V[$safe]:-}" ] || continue
    if [ "${V[DEPLOYER]:-}" = "${V[$safe]}" ]; then
      echo "release-fill: DEPLOYER equals $safe — a contract's deployer is never the contract" >&2
      problems=1
    fi
  done
  return $((problems == 0 ? 0 : 1))
}

# ---- verification of the recipe against this tree --------------------------
# Every rule fires exactly as often as the rule table says. A mismatch is not a
# warning: it means the patches and this recipe have drifted, so a marker would
# be left behind (or a real value overwritten) by a confident-looking run.
verify_counts() {
  local r spec marker want anchor got total=0 bad=0 where
  for r in "${RULES[@]}"; do
    spec=${r%%|*}
    r=${r#*|}
    marker=${r%%|*}
    r=${r#*|}
    want=${r%%|*}
    anchor=${r#*|}
    got=$(count_rule "$marker" "$anchor")
    if [ "$got" -ne "$want" ]; then
      where="any line"
      case "$anchor" in '') ;; *) where="lines carrying \"$anchor\"" ;; esac
      echo "release-fill: '$marker' matched $got time(s) on $where, expected $want" >&2
      echo "  -> ${spec#=} would be left behind (or the wrong line filled). Re-derive the recipe" >&2
      echo "     against release-designs/ before release day." >&2
      bad=1
    fi
    total=$((total + got))
  done
  [ "$bad" -eq 0 ] || return 1
  printf '%s' "$total"
}

# ---- the substitution ------------------------------------------------------
# One marker, one value, on the lines the anchor names, with the count checked
# by verify_counts beforehand. Written to a sibling temp file and renamed so a
# failed run cannot leave a half-written document behind.
apply_rule() {
  local spec=$1 marker=$2 anchor=${3:-} val
  local f
  case "$spec" in
    =*) val=${spec#=} ;;
    *) val=${V[$spec]:-} ;;
  esac
  echo "   ${spec#=}  <--  $marker${anchor:+  (on \"$anchor\")}"
  for f in $SURFACES; do
    MARKER=$marker VALUE=$val ANCHOR=$anchor awk '
      BEGIN { m = ENVIRON["MARKER"]; v = ENVIRON["VALUE"]; a = ENVIRON["ANCHOR"]; lm = length(m) }
      {
        if (a != "" && index($0, a) == 0) { print; next }
        s = $0; out = ""
        while ((p = index(s, m)) > 0) { out = out substr(s, 1, p - 1) v; s = substr(s, p + lm) }
        print out s
      }
    ' "$f" > "$f.filltmp"
    mv "$f.filltmp" "$f"
  done
}

# ---- the dry run's mirror --------------------------------------------------
# --check -in validates and simulates on copies of the surfaces only: the rules
# touch nothing else, so a surface-only mirror is a faithful dry run.
dry_run() {
  local mirror="$tmp/dry" f
  for f in $SURFACES; do
    mkdir -p "$mirror/$(dirname "$f")"
    cp "$f" "$mirror/$f"
  done
  # Everything — the rules AND the post-condition — happens inside the mirror.
  # Checking the post-condition from the caller's directory would report the
  # markers of the tree we are standing in, not the ones we just filled.
  (
    cd "$mirror" || exit 2
    for r in "${RULES[@]}"; do
      spec=${r%%|*}
      r=${r#*|}
      marker=${r%%|*}
      r=${r#*|}
      anchor=${r#*|}
      apply_rule "$spec" "$marker" "$anchor"
    done
    # shellcheck disable=SC2086
    hits=$(grep -nHE "$MARKER_RE" $SURFACES 2>/dev/null || true)
    if [ -n "$hits" ]; then
      echo "release-fill: the dry run left markers behind — the rule table is incomplete:" >&2
      printf '%s\n' "$hits" >&2
      exit 1
    fi
  )
}

tmp=""
cleanup() {
  [ -n "$tmp" ] && rm -rf "$tmp"
  for f in $SURFACES; do rm -f "$f.filltmp"; done
}
trap cleanup EXIT

tmp=$(mktemp -d "${TMPDIR:-/tmp}/spore-release-fill.XXXXXX")

# Nothing to fill is a legitimate state: the passes are not applied here yet
# (this is what makes --check safe as an every-push gate). A values file that WAS
# given is validated anyway: that is how the receipt scripts/anvil_e2e.sh writes
# is held to this script's own rules on every push, rather than on release day.
if [ -z "$(markers_now)" ]; then
  if [ -n "$VALUES" ]; then
    [ -f "$VALUES" ] || {
      echo "release-fill: no such values file: $VALUES" >&2
      exit 2
    }
    load_values || exit 1
    echo "release-fill: values ok — a complete receipt ($(printf '%s' "$REQUIRED_KEYS" | wc -w | tr -d ' ') keys: shapes and cross-field checks pass)"
    echo "             nothing to fill in $ROOT — the frozen passes are not applied here yet"
    exit 0
  fi
  echo "release-fill: nothing to fill — no rehearsal marker on the release surfaces in $ROOT"
  exit 0
fi

# 1. the recipe must match this tree, values or not
total=$(verify_counts) || exit 1

if [ "$CHECK" -eq 1 ] && [ -z "$VALUES" ]; then
  echo "release-fill: recipe ok — $total marker occurrence(s) match the rule table exactly"
  echo "             (surfaces: $(printf '%s' "$SURFACES" | tr '\n' ' '))"
  echo "             fill with: bash scripts/release-fill.sh -in <values>"
  exit 0
fi

[ -n "$VALUES" ] || {
  echo "release-fill: $total marker(s) need filling, but no values file was given (see --keys)" >&2
  exit 3
}
[ -f "$VALUES" ] || {
  echo "release-fill: no such values file: $VALUES" >&2
  exit 2
}

# 2. the values themselves, before anything is written
load_values || exit 1

if [ "$CHECK" -eq 1 ]; then
  dry_run || exit 1
  echo "release-fill: dry run ok — $total marker occurrence(s) would be filled and none left behind"
  echo "             run without --check to write."
  exit 0
fi

# 3. back up, fill, and restore everything if the result is not clean
for f in $SURFACES; do
  mkdir -p "$tmp/bak/$(dirname "$f")"
  cp "$f" "$tmp/bak/$f"
done
restore() {
  local f
  for f in $SURFACES; do cp "$tmp/bak/$f" "$f"; done
  echo "release-fill: restored every surface — nothing was left half-filled." >&2
}

echo "release-fill: filling $total marker occurrence(s) from $VALUES"
for r in "${RULES[@]}"; do
  spec=${r%%|*}
  r=${r#*|}
  marker=${r%%|*}
  r=${r#*|}
  anchor=${r#*|}
  apply_rule "$spec" "$marker" "$anchor" || { rc=$?; restore; exit "${rc:-1}"; }
done

# 4. the guarantee: no marker survives, on any surface
hits=""
# shellcheck disable=SC2086
hits=$(grep -nHE "$MARKER_RE" $SURFACES 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "release-fill: markers survived the fill — refusing to leave a placeholder in a release:" >&2
  printf '%s\n' "$hits" >&2
  restore
  exit 1
fi

echo "release-fill: done — 0 markers left on the release surfaces:"
for f in $SURFACES; do echo "   $f"; done
echo
echo "next: bash scripts/release-placeholders.sh   (must report clean)"
echo "      go test ./internal/evm ./cmd/spore     (must be green)"
echo "      bash scripts/release-readiness.sh      (the registry blocker must be gone)"
