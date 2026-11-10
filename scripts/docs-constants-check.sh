#!/usr/bin/env bash
# docs-constants-check.sh — every size a doc quotes is the size the code enforces.
#
# WIRE_SPEC §5 stated the peer's request cap twice: "request capped at 4 KiB" in
# the frame layout and "over the 64 KiB request cap" in the 400 bad frame note.
# Both were in the same document, eleven lines apart, and both shipped for five
# releases. Every gate passed the whole time, because every gate reads one file:
# gofmt reads Go, go test reads Go, doc-refs checks that links resolve, and the
# release checks compare version pins. Nothing compared a number in prose with
# the constant that enforces it, so the prose was free to drift and did.
#
# This closes that hole for the sizes the prose actually quotes. Each row below
# names a constant in the source, the sentences that quote it, and the docs they
# live in; the value is read from the Go file at check time, converted to bytes,
# and compared against every claim found. A wrong doc fails, and so does a
# changed constant whether the doc was updated or not — the point is that the
# two cannot disagree, not that the doc is right.
#
# Claims are matched by shape, not by the number, so the check survives a doc
# that legitimately restates the same cap in a second sentence (the 4 KiB case
# had exactly two). A row that no longer finds any claim is a failure too: a
# silent loss of coverage is how this class of drift comes back.
#
#   bash scripts/docs-constants-check.sh             # report every disagreement
#   bash scripts/docs-constants-check.sh --quiet     # exit status only
#   bash scripts/docs-constants-check.sh --self-check  # prove the gate reads both sides
#
# --self-check copies the docs and the source files to a scratch tree and runs
# the same comparison three times: unmodified (must be green), with one doc
# number flipped (must be red), and with the Go constant moved instead (must be
# red again). That second rehearsal is the one that matters — a checker whose
# expected values are typed into it would pass the first two.
#
# Exit codes: 0 every claim matches, 1 a claim disagrees or a row lost its claim,
# 2 cannot check (no git repo, missing file, unreadable constant), 3 usage.
set -euo pipefail

QUIET=0
SELF_CHECK=0
ROOT=""

usage() {
  cat <<'EOF'
usage: bash scripts/docs-constants-check.sh [--quiet] [--self-check] [--root DIR]

  --quiet       exit status only; print nothing when clean
  --self-check  rehearse the gate on a scratch tree: clean copy green, a flipped
                doc number red, a moved code constant red
  --root DIR    check DIR instead of this git checkout (used by --self-check)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --self-check) SELF_CHECK=1 ;;
    --root)
      [ "$#" -ge 2 ] || { echo "docs-constants-check: --root needs a directory" >&2; exit 3; }
      ROOT=$2
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "docs-constants-check: unknown argument: $1 (see --help)" >&2
      exit 3
      ;;
  esac
  shift
done

if [ -z "$ROOT" ]; then
  ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "docs-constants-check: not inside a git repository" >&2
    exit 2
  }
fi
cd "$ROOT"

# ---- the table -------------------------------------------------------------
# name <TAB> go file <TAB> constant <TAB> claim shapes <TAB> docs
#
# Tabs, not pipes: the shapes are EREs and an alternation like (KiB|MiB) would
# split a pipe-separated row into the wrong fields — which it did, silently, on
# the first version of this table. Shapes are ;-separated and docs ,-separated.
#
# Every claim shape must END with the number and its unit: the last size token in
# the match is the claim, which is what lets one shape cover "capped at 4 KiB"
# without the extractor having to know where a group boundary is.
table() {
  printf '%s\t%s\t%s\t%s\t%s\n' \
    'peer request frame cap' 'internal/peerstore/server.go' 'maxRequestFrame' \
    'request capped at [0-9.]+ ?(KiB|MiB);[0-9.]+ ?(KiB|MiB) request cap' 'docs/WIRE_SPEC.md' \
    'peer response frame cap' 'internal/peerstore/peerstore.go' 'maxFrame' \
    'transport cap [0-9.]+ ?(KiB|MiB)' 'docs/WIRE_SPEC.md' \
    'peer body cap' 'internal/peerstore/server.go' 'maxPeerBodyBytes' \
    'caps bodies at [0-9.]+ ?(KiB|MiB)' 'docs/WIRE_SPEC.md' \
    'review artifact parser cap' 'internal/daoreview/review.go' 'MaxCertificate' \
    'capped at \*\*[0-9.]+ ?(KiB|MiB)' 'docs/DAO_REVIEW.md' \
    'http body store cap' 'internal/store/httpstore.go' 'maxBody' \
    '[0-9.]+ ?(KiB|MiB) HTTP body store' 'docs/PRIVATE_HANDOFF.md'
}

# ---- value handling --------------------------------------------------------
# human_bytes N — 4096 -> "4 KiB", 65536 -> "64 KiB", 300 -> "300 bytes".
human_bytes() {
  awk -v b="$1" 'BEGIN {
    if (b >= 1073741824 && b % 1073741824 == 0) printf "%d GiB\n", b / 1073741824
    else if (b >= 1048576 && b % 1048576 == 0) printf "%d MiB\n", b / 1048576
    else if (b >= 1024 && b % 1024 == 0)       printf "%d KiB\n", b / 1024
    else                                       printf "%d bytes\n", b
  }'
}

# token_bytes "64 KiB" — the documented size in bytes. A fractional size is
# allowed ("1.5 MiB") because prose uses it; the result is truncated, and the
# comparison is exact, so 1.5 MiB never quietly equals 1.6 MiB.
token_bytes() {
  printf '%s' "$1" | sed 's/\([0-9]\)\(B\|KiB\|MiB\|GiB\)/\1 \2/' | awk '{
    n = $(NF - 1); u = $NF
    m = 1
    if (u == "KiB")      m = 1024
    else if (u == "MiB") m = 1048576
    else if (u == "GiB") m = 1073741824
    printf "%.0f\n", n * m
  }'
}

# go_const FILE NAME — the bytes NAME is set to in FILE, or nonzero with a
# message on stderr. Accepts the three forms the source actually uses
# (`4 << 10`, `64 << 20`, a plain integer); anything else is refused rather than
# guessed at, because a checker that quietly reads 0 would pass every doc.
go_const() {
  awk -v name="$2" -v file="$1" '
    function value(rhs,   p, n, i, v) {
      gsub(/[ \t]/, "", rhs)
      if (rhs ~ /<</) {
        n = split(rhs, p, "<<")
        if (n != 2 || p[1] !~ /^[0-9]+$/ || p[2] !~ /^[0-9]+$/) return ""
        v = p[1]
        for (i = 0; i < p[2]; i++) v = v * 2
        return sprintf("%.0f", v)
      }
      if (rhs ~ /\*/) {
        n = split(rhs, p, "\\*")
        v = 1
        for (i = 1; i <= n; i++) {
          if (p[i] !~ /^[0-9]+$/) return ""
          v = v * p[i]
        }
        return sprintf("%.0f", v)
      }
      if (rhs ~ /^[0-9]+$/) return rhs
      return ""
    }
    {
      line = $0
      sub(/\r$/, "", line)
      sub(/\/\/.*$/, "", line)          # a trailing comment ("// 64 MiB, same cap") is not the value
      # The name may sit in a const block (`\tMaxCertificate    = 64 << 10`) or
      # carry its own keyword (`\tconst maxBody = 64 << 10`) — both forms are in
      # the tree, so both must parse or the row silently finds nothing.
      pat = "^[ \t]*(const[ \t]+|var[ \t]+)?" name "[ \t]*="
      if (line !~ pat) next
      rhs = line
      sub(pat, "", rhs)
      sub(/[ \t]+$/, "", rhs)
      v = value(rhs)
      if (v == "") { print "unreadable: " $0 > "/dev/stderr"; bad = 1; next }
      seen[v] = 1
      count++
    }
    END {
      if (bad) exit 2
      if (count == 0) { print "no assignment to " name " in " file > "/dev/stderr"; exit 2 }
      for (k in seen) { n++; vals = vals (n > 1 ? ", " : "") k }
      if (n > 1) { print "ambiguous: " name " is set to " vals " in " file > "/dev/stderr"; exit 2 }
      print vals
    }' "$1"
}

# ---- the comparison --------------------------------------------------------
# check_root ROOT — compare every row against ROOT. Returns 0 clean, 1 a
# disagreement, 2 a row that cannot be checked.
check_root() {
  local root=$1 rc=0 rows=0 claims=0
  local name gofile const shapes docs bytes want per_row

  while IFS=$'\t' read -r name gofile const shapes docs; do
    [ -n "$name" ] || continue
    rows=$((rows + 1))
    per_row=0

    if [ ! -f "$root/$gofile" ]; then
      echo "docs-constants-check: $gofile is missing — cannot read $const" >&2
      rc=2
      continue
    fi
    if ! bytes=$(go_const "$root/$gofile" "$const" 2>/dev/null); then
      echo "docs-constants-check: cannot read $const from $gofile" >&2
      go_const "$root/$gofile" "$const" >/dev/null || true
      rc=2
      continue
    fi
    want=$(human_bytes "$bytes")

    local d re hit lineno text token got
    local IFS_OLD=$IFS
    IFS=',' read -r -a doc_list <<<"$docs"
    IFS=';' read -r -a shape_list <<<"$shapes"
    IFS=$IFS_OLD

    for d in "${doc_list[@]}"; do
      if [ ! -f "$root/$d" ]; then
        echo "docs-constants-check: $d is missing — the $name claims live there" >&2
        rc=2
        continue
      fi
      for re in "${shape_list[@]}"; do
        while IFS= read -r hit; do
          [ -n "$hit" ] || continue
          lineno=${hit%%:*}
          text=${hit#*:}
          token=$(printf '%s\n' "$text" | grep -oE "$re" | grep -oE '[0-9.]+ ?(B|KiB|MiB|GiB)' | tail -1)
          [ -n "$token" ] || continue
          per_row=$((per_row + 1))
          claims=$((claims + 1))
          got=$(token_bytes "$token")
          if [ "$got" != "$bytes" ]; then
            rc=1
            ((QUIET)) || printf '  %s:%s says %s (%s bytes); %s %s is %s (%s bytes)\n' \
              "$d" "$lineno" "$token" "$got" "$gofile" "$const" "$want" "$bytes"
          fi
        done < <(grep -nE "$re" "$root/$d" 2>/dev/null || true)
      done
    done

    if [ "$per_row" -eq 0 ]; then
      rc=1
      ((QUIET)) || printf '  %s: no doc states this cap any more (%s %s = %s)\n' \
        "$name" "$gofile" "$const" "$want"
      ((QUIET)) || printf '    either restore the sentence or drop the row from scripts/docs-constants-check.sh\n'
    fi
  done < <(table)

  if [ "$rows" -eq 0 ]; then
    echo "docs-constants-check: the claim table is empty — nothing was checked" >&2
    return 2
  fi
  [ "$rc" -ne 0 ] && return "$rc"

  ((QUIET)) || printf 'docs-constants-check: clean — %s claim(s) across %s cap(s) match the code\n' "$claims" "$rows"
  return 0
}

# ---- rehearsal -------------------------------------------------------------
self_check() {
  local tmp
  tmp=$(mktemp -d) || { echo "docs-constants-check: mktemp failed" >&2; return 2; }
  # shellcheck disable=SC2064
  trap "rm -rf \"$tmp\"" EXIT

  local f
  for f in docs internal/peerstore/server.go internal/peerstore/peerstore.go \
    internal/daoreview/review.go internal/store/httpstore.go; do
    [ -e "$f" ] || { echo "docs-constants-check: self-check: $f is missing" >&2; return 2; }
    cp -r --parents "$f" "$tmp/" || return 2
  done

  local fail=0

  if check_root "$tmp" >/dev/null 2>&1; then
    echo "self-check: unmodified copy is green"
  else
    echo "self-check: FAILED — the unmodified copy does not pass, so the table does not describe this tree"
    check_root "$tmp" >&2 || true
    fail=1
  fi

  # A doc that drifts must go red. The flip is the exact shipped bug: 4 KiB
  # became 64 KiB in one of two sentences.
  sed -i 's/request capped at 4 KiB/request capped at 64 KiB/' "$tmp/docs/WIRE_SPEC.md"
  if check_root "$tmp" >/dev/null 2>&1; then
    echo "self-check: FAILED — a doc claiming 64 KiB for a 4 KiB cap passed"
    fail=1
  else
    echo "self-check: doc drift is red ($(check_root "$tmp" 2>&1 | grep -c 'WIRE_SPEC.md' || true) line(s) named)"
  fi
  sed -i 's/request capped at 64 KiB/request capped at 4 KiB/' "$tmp/docs/WIRE_SPEC.md"

  # The constant moving with the doc untouched must ALSO go red: this is what
  # separates a real comparison from expected values typed into the checker.
  sed -i 's/maxRequestFrame *= 4 << 10/maxRequestFrame = 8 << 10/' "$tmp/internal/peerstore/server.go"
  if grep -q 'maxRequestFrame *= 8 << 10' "$tmp/internal/peerstore/server.go"; then
    if check_root "$tmp" >/dev/null 2>&1; then
      echo "self-check: FAILED — the doc still passed after maxRequestFrame moved to 8 KiB"
      fail=1
    else
      echo "self-check: constant drift is red"
    fi
  else
    echo "self-check: FAILED — could not move maxRequestFrame in the scratch copy"
    fail=1
  fi
  sed -i 's/maxRequestFrame *= 8 << 10/maxRequestFrame = 4 << 10/' "$tmp/internal/peerstore/server.go"

  if check_root "$tmp" >/dev/null 2>&1; then
    echo "self-check: restored copy is green again"
  else
    echo "self-check: FAILED — the restored copy does not pass"
    fail=1
  fi

  [ "$fail" -eq 0 ] || return 1
  echo "self-check: the gate reads both sides"
  return 0
}

if [ "$SELF_CHECK" -eq 1 ]; then
  self_check
  exit $?
fi

check_root "$ROOT"
