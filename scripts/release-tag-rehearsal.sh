#!/usr/bin/env bash
# release-tag-rehearsal.sh — prove the tag pass end to end, before the tag exists.
#
# The tag is the one release artifact nothing else in this repository reads. The
# receipt gate reads the docs; the placeholder sweep reads the release surfaces;
# the rehearsals read the frozen patches. Nobody reads the tag body — and a tag
# is immutable once pushed, so an unfilled field, a pasted <release> or a wrong
# address is permanent, and no gate will ever tell you.
#
# release-tag-message.sh already strips the draft and validates the body. What
# had never been shown is the thing release day actually does: fill all nine
# fields from a receipt, strip, and end up with something a human could sign and
# push. This rehearses exactly that, on the real draft, and then signs it:
#
#   1. fill the nine <<FILL: …>> fields of release-designs/v0.9.0-tag-message.txt
#      from a values file (one key per field, in document order)
#   2. strip with the SHIPPED script (bash scripts/release-tag-message.sh --write),
#      so the rehearsal tests the real validator rather than a copy of it
#   3. check the body independently: no marker of any shape, and every value that
#      was supplied actually present — "no markers" alone would pass on a body
#      that silently dropped a field
#   4. create a REAL signed tag in a throwaway repository and require
#      `git verify-tag` to accept the signature, so "signable" is a fact and not
#      an adjective
#
# and then proves the checks have teeth, which is the whole reason the pass
# exists:
#
#   * the unfilled draft is refused, and writes no file
#   * a body carrying <release>/<address>/<date> is refused (single-angle
#     placeholders are what the runbooks use, and `git` will happily sign them)
#   * a body that never cites docs/LIVE_NODES.md §3 is refused
#   * a body that STILL carries <<FILL: …>> signs and VERIFIES green — the
#     signature is not a correctness check, so the validators are the only teeth
#
#   bash scripts/release-tag-rehearsal.sh -in values
#   bash scripts/release-tag-rehearsal.sh -in values -receipt fillvalues
#   bash scripts/release-tag-rehearsal.sh --keys            # the values template
#   bash scripts/release-tag-rehearsal.sh --self-check      # synthetic fixture (gates)
#   bash scripts/release-tag-rehearsal.sh -s                # self-skip without ssh-keygen
#
# --self-check writes its own deliberately synthetic values file and matching
# receipt and runs the same twenty steps against the REAL draft. That is what
# the pre-push gate runs: no operator receipt exists on a normal push, and a
# draft edit (a tenth field, a reflowed sentence) must fail the push rather than
# wait until the only run that matters. -in is for the operator, with receipt in
# hand.
#
# -receipt cross-checks the six receipt-shaped fields against the values file
# scripts/release-fill.sh consumes, so the tag, the §3 doc and the registry are
# provably filled from ONE receipt rather than three transcriptions of it.
#
# The signing uses an ephemeral ssh key in a throwaway repo: it never touches the
# operator's own signing key, and it never writes inside the real checkout. ssh
# signing is what the release runbook uses (`gpg.format=ssh`), so the rehearsal
# exercises the real mechanism with a key that cannot leak.
#
# Exit codes: 0 green (or self-skipped), 1 a proof step failed, 2 cannot check
# (no draft, no tag script), 3 usage, 130 interrupted.
set -euo pipefail

VALUES=""
RECEIPT=""
SELF_SKIP=0
SELF_CHECK=0
KEEP=0
SHOW_KEYS=0
TAGNAME="v0.9.0"

usage() {
  cat <<'USAGE'
usage: bash scripts/release-tag-rehearsal.sh -in VALUES [-receipt FILLVALUES]
                                                  [-t TAGNAME] [-s] [--keep] [--keys]
       bash scripts/release-tag-rehearsal.sh --self-check

  -in FILE       the nine tag fields, one key=value per field, in document order
                 (see --keys). Required unless --self-check.
  -receipt FILE  optionally the values file scripts/release-fill.sh consumes; the
                 six receipt-shaped fields must agree with it.
  -t TAG         tag name to create (default: v0.9.0)
  -s             self-skip (exit 0) when ssh-keygen is unavailable
  --self-check   run against a synthetic fixture written here, on the real draft:
                 what the pre-push gate runs, where no receipt exists
  --keep         keep the scratch directory and print its path
  --keys         print the values-file template and exit
  -h, --help     this message
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -in | --in)
      shift
      [ $# -ge 1 ] || { echo "release-tag-rehearsal: -in needs a file" >&2; exit 3; }
      VALUES=$1
      ;;
    -receipt | --receipt)
      shift
      [ $# -ge 1 ] || { echo "release-tag-rehearsal: -receipt needs a file" >&2; exit 3; }
      RECEIPT=$1
      ;;
    -t | --tag)
      shift
      [ $# -ge 1 ] || { echo "release-tag-rehearsal: -t needs a tag name" >&2; exit 3; }
      TAGNAME=$1
      ;;
    -s | --self-skip) SELF_SKIP=1 ;;
    --self-check) SELF_CHECK=1 ;;
    --keep) KEEP=1 ;;
    --keys) SHOW_KEYS=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "release-tag-rehearsal: unknown argument: $1 (see --help)" >&2; usage >&2; exit 3 ;;
  esac
  shift
done

# One key per field, in the order the fields appear in the draft's body.
KEYS=(
  TAG_CONTRACT      # 1. the MyceliumMailbox address
  TAG_CREATION_TX   # 2. the creation txid
  TAG_DEPLOYER      # 3. the funded key that deployed it
  TAG_DATE          # 4. the deployment date
  TAG_DELIVER_TX    # 5. one deliver txid from the two-party proof
  TAG_BURN_TX       # 6. the burn txid, or the "unlogged by design" phrase
  TAG_DOCS_BULLET   # 7. the docs/fee-notes bullet
  TAG_EXTRA_BULLET  # 8. anything else that landed (one user-visible bullet)
  TAG_FEES          # 9. the measured funding total, in prose
)

if [ "$SHOW_KEYS" -eq 1 ]; then
  cat <<'TEMPLATE'
# release-tag-rehearsal values — one key per <<FILL: …>> field of
# release-designs/v0.9.0-tag-message.txt, in document order. The six
# receipt-shaped fields are the §3 STATUS lines (addresses lowercase 0x+40,
# txids 0x+64, dates YYYY-MM-DD); the other three are prose you write, and every
# value must be a single line with no placeholder of any shape in it.

TAG_CONTRACT=0x                                    # the mailbox address
TAG_CREATION_TX=0x                                 # its creation txid
TAG_DEPLOYER=0x                                    # the deploying key
TAG_DATE=YYYY-MM-DD                                # the deployment date
TAG_DELIVER_TX=0x                                  # a deliver txid
TAG_BURN_TX=                                       # the burn txid, or: unlogged by design — see the contract's explorer history
TAG_DOCS_BULLET=                                   # the docs/fee-notes bullet, one line
TAG_EXTRA_BULLET=                                  # one user-visible change, one line
TAG_FEES=                                          # the measured funding total, in prose
TEMPLATE
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRAFT="release-designs/v0.9.0-tag-message.txt"
TAG_SCRIPT="$REPO_ROOT/scripts/release-tag-message.sh"
# The phrase the draft's comment block promises, and the line the shipped pass
# strips at. The fill works on the BODY only: the comment block's own
# "<<FILL:···>>" (the do-not-tag warning) is not a field, and counting it would
# shift every field by one.
MARKER='strip EVERYTHING above this line'

PASS=0
ROOT=""
FIXDIR=""
cleanup() {
  [ -n "$FIXDIR" ] && rm -rf "$FIXDIR"
  if [ -n "$ROOT" ] && [ "$KEEP" -eq 1 ]; then
    printf 'scratch kept: %s\n' "$ROOT"
    return
  fi
  [ -n "$ROOT" ] && rm -rf "$ROOT"
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok:\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- preconditions ---------------------------------------------------------
for tool in git mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "release-tag-rehearsal: $tool not found — cannot check" >&2
    exit 2
  }
done
if ! command -v ssh-keygen >/dev/null 2>&1; then
  if [ "$SELF_SKIP" -eq 1 ]; then
    echo "SKIP release-tag rehearsal: ssh-keygen not found (self-skip)"
    exit 0
  fi
  echo "release-tag-rehearsal: ssh-keygen not found — install openssh, or pass -s to skip" >&2
  exit 3
fi

for p in "$REPO_ROOT/$DRAFT" "$TAG_SCRIPT"; do
  [ -f "$p" ] || {
    echo "release-tag-rehearsal: $p is missing — there is no tag pass to rehearse" >&2
    exit 2
  }
done
# --self-check: a synthetic receipt, written here, in the exact shape the
# operator's would have. 0x1111…/0x2222… and 2026-01-01 are not plausible
# deployment data, so a green gate run cannot be mistaken for a real receipt.
if [ "$SELF_CHECK" -eq 1 ]; then
  FIXDIR=$(mktemp -d "${TMPDIR:-/tmp}/spore-tag-fixture.XXXXXX")
  CONTRACT=0x1111111111111111111111111111111111111111
  CREATION=0x2222222222222222222222222222222222222222222222222222222222222222
  DEPLOYER=0x3333333333333333333333333333333333333333
  DELIVER=0x4444444444444444444444444444444444444444444444444444444444444444
  cat > "$FIXDIR/values" <<FIXTURE
# SYNTHETIC (--self-check): a fixture, never a receipt.
TAG_CONTRACT=$CONTRACT
TAG_CREATION_TX=$CREATION
TAG_DEPLOYER=$DEPLOYER
TAG_DATE=2026-01-01
TAG_DELIVER_TX=$DELIVER
TAG_BURN_TX=unlogged by design — see the contract's explorer history
TAG_DOCS_BULLET=docs: honest fee and limit notes (must-do #4) with the measured numbers; the CARRIER_MATRIX and README EVM rows flipped to live
TAG_EXTRA_BULLET=fix(ci): run only the fast gate on a push to main; the heavy jobs stay dispatch-only
TAG_FEES=0.0001 ETH deploy + 12 x (deliver+burn) = 0.00012 ETH at 1 gwei
FIXTURE
  cat > "$FIXDIR/receipt" <<FIXTURE
# SYNTHETIC (--self-check): the same deployment as the values file above.
MAINNET_ADDR=$CONTRACT
MAINNET_TX=$CREATION
MAINNET_DATE=2026-01-01
DEPLOYER=$DEPLOYER
DELIVER_TX=$DELIVER
EST_FUNDING_TOTAL=0.00012 ETH
FIXTURE
  VALUES="$FIXDIR/values"
  RECEIPT="$FIXDIR/receipt"
fi

[ -n "$VALUES" ] || {
  echo "release-tag-rehearsal: -in VALUES is required (see --keys), or --self-check" >&2
  exit 3
}
[ -f "$VALUES" ] || {
  echo "release-tag-rehearsal: no such values file: $VALUES" >&2
  exit 2
}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/spore-tag-rehearsal.XXXXXX")
echo "== release-tag rehearsal: fill all nine fields, strip, sign, verify =="
echo "draft:  $DRAFT"
echo "tag:    $TAGNAME (in a throwaway repository)"
if [ "$SELF_CHECK" -eq 1 ]; then
  echo "values: synthetic fixture (--self-check) — this is a gate run, not a receipt"
else
  echo "values: $VALUES"
fi

# ---- values ----------------------------------------------------------------
declare -A V=()
is_addr() {
  local h=${1#0x}
  case "$1" in 0x*) ;; *) return 1 ;; esac
  [ ${#h} -eq 40 ] || return 1
  case "$h" in *[!0-9a-f]*) return 1 ;; esac
  case "$h" in *[!0]*) return 0 ;; *) return 1 ;; esac
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

step "the nine values"
problems=0
line_no=0
while IFS= read -r line || [ -n "$line" ]; do
  line_no=$((line_no + 1))
  line=${line%$'\r'}
  case "$line" in ''|'#'*) continue ;; esac
  case "$line" in
    *=*) ;;
    *) echo "  line $line_no is not key=value: $line" >&2; problems=1; continue ;;
  esac
  key=${line%%=*}
  val=${line#*=}
  key=$(printf '%s' "$key" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  val=$(printf '%s' "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  known=0
  for k in "${KEYS[@]}"; do [ "$k" = "$key" ] && known=1; done
  if [ "$known" -eq 0 ]; then
    echo "  '$key' is not a tag field (typo? see --keys)" >&2
    problems=1
    continue
  fi
  V["$key"]=$val
done < "$VALUES"

for k in "${KEYS[@]}"; do
  if [ -z "${V[$k]:-}" ]; then
    echo "  no value for $k — all nine fields must be filled" >&2
    problems=1
    continue
  fi
  val=${V[$k]}
  # A value may not itself be a placeholder: that moves the problem into the tag.
  case "$val" in
    *'<<'*|*'>>'*|'<'[a-z]*'>'|*'<DRYRUN-'*|*'\'*)
      echo "  $k still looks like a marker or a placeholder: $val" >&2
      problems=1
      continue
      ;;
  esac
  case "$val" in *$'\n'*) echo "  $k spans lines — one line per value" >&2; problems=1; continue ;; esac
  case "$k" in
    TAG_CONTRACT | TAG_DEPLOYER) is_addr "$val" || { echo "  $k must be 0x + 40 lowercase hex, got '$val'" >&2; problems=1; } ;;
    TAG_CREATION_TX | TAG_DELIVER_TX) is_tx "$val" || { echo "  $k must be 0x + 64 lowercase hex, got '$val'" >&2; problems=1; } ;;
    TAG_DATE) is_date "$val" || { echo "  $k must be YYYY-MM-DD, got '$val'" >&2; problems=1; } ;;
    # TAG_BURN_TX is either a txid or the documented "unlogged by design" phrase.
    TAG_BURN_TX)
      case "$val" in 0x*) is_tx "$val" || { echo "  TAG_BURN_TX must be 0x + 64 lowercase hex, or the unlogged-by-design phrase" >&2; problems=1; } ;; esac ;;
    *)
      case "$val" in *[0-9A-Za-z]*) ;; *) echo "  $k has no content" >&2; problems=1 ;; esac ;;
  esac
done
[ "$problems" -eq 0 ] || fail "the values file is not a complete receipt"

if [ -n "$RECEIPT" ]; then
  [ -f "$RECEIPT" ] || fail "no such receipt file: $RECEIPT"
  # One receipt, three artifacts: the tag must carry the same numbers the fill
  # wrote into the docs and the registry, or the tag is the odd one out.
  declare -A R=()
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac
    k=${line%%=*}
    v=${line#*=}
    k=$(printf '%s' "$k" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    v=$(printf '%s' "$v" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    R["$k"]=$v
  done < "$RECEIPT"
  for pair in "TAG_CONTRACT:MAINNET_ADDR" "TAG_CREATION_TX:MAINNET_TX" \
              "TAG_DEPLOYER:DEPLOYER" "TAG_DATE:MAINNET_DATE" "TAG_DELIVER_TX:DELIVER_TX"; do
    tag_key=${pair%%:*}
    fill_key=${pair#*:}
    [ -n "${R[$fill_key]:-}" ] || continue
    if [ "${V[$tag_key]}" != "${R[$fill_key]}" ]; then
      fail "$tag_key (${V[$tag_key]}) disagrees with the fill receipt's $fill_key (${R[$fill_key]}) — one deployment, one value"
    fi
  done
  if [ -n "${R[EST_FUNDING_TOTAL]:-}" ]; then
    case "${V[TAG_FEES]}" in
      *"${R[EST_FUNDING_TOTAL]}"*) ;;
      *) fail "TAG_FEES does not quote the fill receipt's measured EST_FUNDING_TOTAL (${R[EST_FUNDING_TOTAL]})" ;;
    esac
  fi
  ok "all six receipt-shaped fields agree with the fill receipt (one receipt, one deployment)"
fi
ok "nine values, all present, none of them a placeholder"

# ---- fill the draft --------------------------------------------------------
step "fill the nine fields (in document order)"
# Three of the nine fields wrap in the draft. A wrapped field is collapsed onto
# the line it opened on — the text before the field, then the value, then
# whatever followed the closing >> — so the surrounding prose reads the way the
# author wrote it instead of leaving the tail stranded on its own line.
FILLED="$ROOT/filled.txt"
V1=${V[TAG_CONTRACT]} V2=${V[TAG_CREATION_TX]} V3=${V[TAG_DEPLOYER]} V4=${V[TAG_DATE]} \
  V5=${V[TAG_DELIVER_TX]} V6=${V[TAG_BURN_TX]} V7=${V[TAG_DOCS_BULLET]} \
  V8=${V[TAG_EXTRA_BULLET]} V9=${V[TAG_FEES]} \
  awk -v m="$MARKER" '
    BEGIN {
      v[1] = ENVIRON["V1"]; v[2] = ENVIRON["V2"]; v[3] = ENVIRON["V3"]
      v[4] = ENVIRON["V4"]; v[5] = ENVIRON["V5"]; v[6] = ENVIRON["V6"]
      v[7] = ENVIRON["V7"]; v[8] = ENVIRON["V8"]; v[9] = ENVIRON["V9"]
      n = 0; body = 0; open = 0; pre = ""
    }
    {
      if (body) {
        if (open) {
          p = index($0, ">>")
          if (p == 0) next
          $0 = pre v[n] substr($0, p + 2)
          open = 0
        }
        while ((s = index($0, "<<FILL:")) > 0) {
          n++
          if (n > 9) { print "REHEARSAL-ERROR: more than nine fields" > "/dev/stderr"; exit 1 }
          pre = substr($0, 1, s - 1)
          rest = substr($0, s)
          p = index(rest, ">>")
          # The field wraps: hold the text that preceded it and drop this line,
          # so the value and the tail of the closing line land on one line.
          if (p == 0) { open = 1; next }
          $0 = pre v[n] substr(rest, p + 2)
        }
      }
      if (!body && index($0, m) > 0) body = 1
      print
    }
    END { print n > "/dev/stderr" }
  ' "$REPO_ROOT/$DRAFT" > "$FILLED" 2>"$ROOT/filled.count"

n=$(tr -dc '0-9' < "$ROOT/filled.count" || true)
[ "$n" = "9" ] || fail "the draft's body has $n <<FILL: …>> field(s), expected exactly 9 — the draft moved"
# Counted on the body, the same cut the shipped pass makes: the comment header
# carries a "<<FILL:···>>" of its own, which is prose, not a field.
left=$(awk -v m="$MARKER" 'index($0, m) { f = 1 } f' "$FILLED" | grep -c '<<FILL:' || true)
[ "$left" = "0" ] || fail "$left field(s) survived the fill"
ok "all 9 fields replaced, none left behind"

# The shipped counter must agree with the fill: this is the same number the
# runbook's --fields check reports on release day.
shipped_fields=$(bash "$TAG_SCRIPT" --fields --in "$FILLED")
[ "$shipped_fields" = "0" ] || fail "the shipped --fields counter still reports $shipped_fields unfilled field(s)"
ok "the shipped --fields counter reports 0"

# ---- strip and validate with the shipped script ----------------------------
step "strip with the shipped pass"
FINAL="$ROOT/final.txt"
bash "$TAG_SCRIPT" --write --in "$FILLED" --out "$FINAL" > "$ROOT/write.log" 2>&1 ||
  { cat "$ROOT/write.log" >&2; fail "the shipped tag pass refused a properly filled draft"; }
[ -f "$FINAL" ] || fail "--write reported success but produced no file"
ok "$(grep -c . "$FINAL" || true) non-blank lines, $(wc -c < "$FINAL" | tr -d ' ') bytes"

step "the body is gate-clean (checked independently of the pass)"
title=$(bash "$TAG_SCRIPT" --print | head -1)
[ "$(head -1 "$FINAL")" = "$title" ] ||
  fail "the body does not start at the draft's title (got '$(head -1 "$FINAL")')"
bad=0
for pat in '<<' '>>' '<DRYRUN-' '0x0{30,}' '<[a-z][a-z0-9 _-]*>'; do
  if hits=$(grep -nE "$pat" "$FINAL"); then
    echo "  body carries '$pat':" >&2
    printf '%s\n' "$hits" | sed 's/^/    /' >&2
    bad=1
  fi
done
[ "$bad" -eq 0 ] || fail "the body is not clean enough to sign"
[ "$(wc -c < "$FINAL" | tr -d ' ')" -ge 200 ] || fail "the body is implausibly short"
grep -q 'docs/LIVE_NODES.md' "$FINAL" || fail "the body never cites docs/LIVE_NODES.md §3"
ok "no marker of any shape, cites §3, starts at the title"

# "No markers" alone would pass on a body that silently dropped a field, so
# require every supplied receipt value to be present in the text that gets signed.
for k in TAG_CONTRACT TAG_CREATION_TX TAG_DEPLOYER TAG_DATE TAG_DELIVER_TX; do
  if ! grep -qF "${V[$k]}" "$FINAL"; then
    fail "$k (${V[$k]}) is missing from the body — the field was filled with something else"
  fi
done
ok "every receipt value the tag claims is actually in the signed text"

# ---- sign it for real ------------------------------------------------------
step "sign it (ephemeral ssh key, throwaway repository)"
REPO="$ROOT/tagrepo"
mkdir -p "$REPO"
git init -q "$REPO"
GITC=(-c commit.gpgsign=false -c user.name='spore release rehearsal' -c user.email='rehearsal@spore.invalid')
git -C "$REPO" "${GITC[@]}" commit -q --allow-empty -m 'rehearsal commit'
ssh-keygen -q -t ed25519 -N '' -C 'rehearsal@spore.invalid' -f "$ROOT/key" ||
  fail "could not generate the throwaway signing key"
SIGN=(-c gpg.format=ssh -c "user.signingkey=$ROOT/key.pub" -c commit.gpgsign=false
      -c user.name='spore release rehearsal' -c user.email='rehearsal@spore.invalid')
if ! git -C "$REPO" "${SIGN[@]}" tag -s "$TAGNAME" -F "$FINAL" > "$ROOT/sign.log" 2>&1; then
  sed 's/^/  /' "$ROOT/sign.log" >&2
  fail "git refused to sign the rehearsed body"
fi
printf '* %s\n' "$(cat "$ROOT/key.pub")" > "$ROOT/allowed"
if ! git -C "$REPO" -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$ROOT/allowed" \
  verify-tag "$TAGNAME" > "$ROOT/verify.log" 2>&1; then
  sed 's/^/  /' "$ROOT/verify.log" >&2
  fail "the signature on the rehearsed tag does not verify"
fi
grep -q 'Good' "$ROOT/verify.log" ||
  { sed 's/^/  /' "$ROOT/verify.log" >&2; fail "verify-tag did not report a good signature"; }
git -C "$REPO" cat-file -p "$TAGNAME" > "$ROOT/object.txt"
grep -q -- '-----BEGIN SSH SIGNATURE-----' "$ROOT/object.txt" ||
  fail "the tag object carries no signature block"
grep -qF "${V[TAG_CONTRACT]}" "$ROOT/object.txt" ||
  fail "the signed tag object does not carry the receipt address"
ok "signed and VERIFIED: $(head -1 "$ROOT/verify.log")"
ok "the tag object carries the receipt address"

# ---- teeth -----------------------------------------------------------------
step "teeth: the checks must refuse, and the signature must not be one of them"
refused() { # refused LABEL OUTFILE CMD...
  local label=$1 out=$2
  shift 2
  rm -f "$out"
  if "$@" > "$ROOT/neg.log" 2>&1; then
    return 1
  fi
  [ -e "$out" ] && return 1
  printf '  \033[32mok:\033[0m %s\n' "$label"
  PASS=$((PASS + 1))
  return 0
}

refused "the unfilled draft is refused, and writes nothing" "$ROOT/neg1.txt" \
  bash "$TAG_SCRIPT" --write --in "$REPO_ROOT/$DRAFT" --out "$ROOT/neg1.txt" ||
  fail "the unfilled draft was accepted"

# A single-angle placeholder is what the runbooks write, and git signs it happily.
# The injected line goes into an otherwise complete body, so the only reason
# this can be refused is the placeholder rule itself.
PLACEHOLDER="$ROOT/placeholder.txt"
awk -v m="$MARKER" '{ print; if (index($0, m)) { print "Shipped in <release>, deployer <address>."; print "" } }' \
  "$FILLED" > "$PLACEHOLDER"
grep -q '<release>' "$PLACEHOLDER" || fail "could not inject the <release> placeholder"
[ "$(awk -v m="$MARKER" 'index($0, m) { f = 1 } f' "$PLACEHOLDER" | grep -c 'docs/LIVE_NODES.md' || true)" != "0" ] ||
  fail "the placeholder control lost its citation — it would be refused for the wrong reason"
refused "a body carrying <release>/<address> is refused" "$ROOT/neg2.txt" \
  bash "$TAG_SCRIPT" --write --in "$PLACEHOLDER" --out "$ROOT/neg2.txt" ||
  fail "a single-angle placeholder was accepted — it would be signed into the tag"

NOCITE="$ROOT/nocite.txt"
grep -v 'docs/LIVE_NODES.md' "$FILLED" > "$NOCITE"
refused "a body that never cites §3 is refused" "$ROOT/neg3.txt" \
  bash "$TAG_SCRIPT" --write --in "$NOCITE" --out "$ROOT/neg3.txt" ||
  fail "a body with no receipt citation was accepted"

# Why this pass needs teeth at all: git signs anything, and verify-tag says the
# signature is good. Nothing about the signature is a correctness check.
UNFILLED_BODY="$ROOT/unfilled-body.txt"
printf 'leftover marker in the signed text: <<FILL: never filled>>\n\nreceipt: docs/LIVE_NODES.md §3\n' > "$UNFILLED_BODY"
if ! git -C "$REPO" "${SIGN[@]}" tag -s "$TAGNAME-bad" -F "$UNFILLED_BODY" >/dev/null 2>&1; then
  fail "expected git to sign a body carrying an unfilled marker (it signs anything)"
fi
if ! git -C "$REPO" -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$ROOT/allowed" \
  verify-tag "$TAGNAME-bad" >/dev/null 2>&1; then
  fail "expected the signature over a marker-carrying body to verify — the demonstration is wrong"
fi
ok "a marker-carrying body signs and VERIFIES green: the signature is not a correctness check"
ok "so the validators above are the only teeth — which is why this rehearsal exists"

printf '\n\033[1;32mRELEASE-TAG REHEARSAL GREEN\033[0m — %d checks. The nine fields fill, the strip validates,\nand the signed tag verifies: %s is signable and gate-clean on this tree.\n' \
  "$PASS" "$TAGNAME"
printf "Remaining before the tag: the real receipt values, and the operator's own signing key.\n"
