#!/usr/bin/env bash
# release-tag-message.sh — the tag pass, executable.
#
# The last release-day step is the only one still done entirely by hand: fill
# release-designs/v0.9.0-tag-message.txt, strip its comment block at the
# "strip EVERYTHING above this line" marker into -final.txt, then
#   git tag -s v0.9.0 -F release-designs/v0.9.0-tag-message-final.txt
#
# Two things about that are worth a machine. The strip is a textual cut whose
# marker can move or vanish, and the filled body is the one release artifact
# that nothing else reads: a leftover <<FILL: …>> would be signed into an
# immutable tag, where the receipt gate cannot see it (it only reads the docs).
# The same holds for a single-angle placeholder — <release>, <address>, <date>
# are what the runbooks write, and git will happily sign them.
#
#   bash scripts/release-tag-message.sh              # structure only; safe on any tree
#   bash scripts/release-tag-message.sh --print      # the body the tag would carry
#   bash scripts/release-tag-message.sh --write      # strip + validate; refuses while fields are unfilled
#   bash scripts/release-tag-message.sh --self-test  # exercise strip+validate on a synthetically filled copy
#
# Exit codes: 0 ok, 1 refused (unresolved field, invalid body, or stale final),
# 2 cannot check, 3 usage.
set -euo pipefail

# Absolutize SELF before any cd, so --self-test can re-invoke this script.
SELF="${BASH_SOURCE[0]}"
case "$SELF" in
  /* | [A-Za-z]:*) ;;
  *) SELF="$(pwd)/$SELF" ;;
esac

top=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "release-tag-message: not inside a git repository" >&2
  exit 2
}
cd "$top"

DRAFT="release-designs/v0.9.0-tag-message.txt"
FINAL="release-designs/v0.9.0-tag-message-final.txt"
# The phrase the draft's own comment block promises; the strip keys on it.
MARKER='strip EVERYTHING above this line'

usage() {
  cat <<'USAGE'
usage: bash scripts/release-tag-message.sh [--check] [--print] [--write] [--self-test]
                                           [--in DRAFT] [--out FINAL]

  --check      (default) validate the draft's structure; report unfilled fields
  --print      print the message body the tag would carry
  --write      strip into -final.txt and validate it; refuses while markers remain
  --self-test  prove the strip+validate logic accepts a filled draft and refuses
               an unfilled one (writes only inside a temp dir)
  --fields     print the number of unfilled fields and exit (0 when none remain)
  --in PATH    draft to read (default: release-designs/v0.9.0-tag-message.txt)
  --out PATH   file --write produces (default: release-designs/v0.9.0-tag-message-final.txt)
  -h, --help   this message
USAGE
}

MODE=check
IN="$DRAFT"
OUT="$FINAL"
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --print) MODE=print ;;
    --write) MODE=write ;;
    --self-test) MODE=self-test ;;
    --fields) MODE=fields ;;
    --in)
      shift
      IN="${1:-}"
      [ -n "$IN" ] || {
        echo "release-tag-message: --in needs a path" >&2
        exit 3
      }
      ;;
    --out)
      shift
      OUT="${1:-}"
      [ -n "$OUT" ] || {
        echo "release-tag-message: --out needs a path" >&2
        exit 3
      }
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "release-tag-message: unknown argument: $1" >&2
      usage >&2
      exit 3
      ;;
  esac
  shift
done

# body <file>: everything after the strip marker, with the leading blanks gone.
body() {
  awk -v m="$MARKER" 'f { print } index($0, m) { f = 1 }' "$1" |
    awk 'NF { p = 1 } p'
}

# fields <file>: how many <<FILL: …>> fields the body still carries. Each field
# opens once, even when its text spans lines.
fields() {
  body "$1" | grep -c '<<FILL:' || true
}

# strip_synthetic <file>: the body with every field replaced by a synthetic
# value, including fields whose text spans lines. This is what --self-test
# fills with; it doubles as the worked example of what "filled" looks like.
strip_synthetic() {
  awk '
    {
      if (open) {
        p = index($0, ">>")
        if (p == 0) next
        $0 = substr($0, p + 2)
        open = 0
      }
      while ((s = index($0, "<<FILL:")) > 0) {
        pre = substr($0, 1, s - 1)
        rest = substr($0, s)
        p = index(rest, ">>")
        if (p == 0) {
          $0 = pre "SYNTHETIC-VALUE"
          open = 1
          break
        }
        $0 = pre "SYNTHETIC-VALUE" substr(rest, p + 2)
      }
      print
    }' "$1"
}

# validate_body <file>: the checks that must hold for a body to be signable.
validate_body() {
  local f=$1 rc=0 count

  if ! grep -q . "$f"; then
    echo "release-tag-message: the stripped body is empty" >&2
    return 1
  fi
  if grep -q '<<' "$f"; then
    echo "release-tag-message: the stripped body still carries unresolved markers:" >&2
    grep -n '<<' "$f" | sed 's/^/  /' >&2
    rc=1
  fi
  if grep -qE '<DRYRUN-|0x0{30,}' "$f"; then
    echo "release-tag-message: the stripped body carries a rehearsal value (a <DRYRUN-…>" >&2
    echo "marker or an all-zeros placeholder address) — a tag is immutable once pushed" >&2
    grep -nE '<DRYRUN-|0x0{30,}' "$f" | sed 's/^/  /' >&2
    rc=1
  fi
  # A single-angle-bracket placeholder is as unsignable as a <<FILL: …>> one, and
  # nothing else in the repo ever reads the tag body: <release>, <address> and
  # <date> are the exact shapes the runbooks and the frozen patches use, so one
  # pasted line would be signed into an immutable tag. The class is lowercase
  # words, which deliberately spares a real mail-style trailer
  # ("Co-Authored-By: … <noreply@codebuff.com>") — the only angle-bracket token
  # the draft's own body legitimately carries.
  if grep -qE '<[a-z][a-z0-9 _-]*>' "$f"; then
    echo "release-tag-message: the stripped body still carries an unfilled placeholder:" >&2
    grep -noE '<[a-z][a-z0-9 _-]*>' "$f" | sed 's/^/  /' >&2
    echo "  fill it from docs/LIVE_NODES.md §3, or delete the line — a tag is immutable" >&2
    rc=1
  fi
  # The runbook requires the tag to cite the canonical receipt; a tag that
  # carries numbers without saying where they came from is not discoverable.
  if ! grep -q 'docs/LIVE_NODES.md' "$f"; then
    echo "release-tag-message: the stripped body never cites docs/LIVE_NODES.md §3 as the canonical receipt" >&2
    rc=1
  fi
  count=$(wc -c < "$f" | tr -d ' ')
  if [ "$count" -lt 200 ]; then
    echo "release-tag-message: the stripped body is implausibly short ($count bytes) — check the strip marker" >&2
    rc=1
  fi
  return "$rc"
}

case "$MODE" in
  self-test)
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/spore-tag-selftest.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    # 1. A filled draft must strip and validate.
    strip_synthetic "$DRAFT" > "$tmp/filled.txt"
    if [ "$(grep -c '<<' "$tmp/filled.txt" || true)" != "0" ]; then
      echo "RELEASE-TAG SELF-TEST FAILED: the synthetic fill left markers behind" >&2
      exit 1
    fi
    if ! bash "$SELF" --write --in "$tmp/filled.txt" --out "$tmp/final.txt" >/dev/null; then
      echo "RELEASE-TAG SELF-TEST FAILED: a fully filled draft was refused" >&2
      exit 1
    fi
    if grep -q '<<' "$tmp/final.txt"; then
      echo "RELEASE-TAG SELF-TEST FAILED: the stripped output still carries markers" >&2
      exit 1
    fi
    if [ "$(head -1 "$tmp/final.txt")" != "$(body "$DRAFT" | head -1)" ]; then
      echo "RELEASE-TAG SELF-TEST FAILED: the stripped body does not start at the draft's title" >&2
      exit 1
    fi
    # 2. The unfilled draft must be refused, and nothing may be left behind.
    if bash "$SELF" --write --in "$DRAFT" --out "$tmp/must-not-exist.txt" >/dev/null 2>&1; then
      echo "RELEASE-TAG SELF-TEST FAILED: the unfilled draft was accepted — the pass has no teeth" >&2
      exit 1
    fi
    if [ -e "$tmp/must-not-exist.txt" ]; then
      echo "RELEASE-TAG SELF-TEST FAILED: a refused draft still produced an output file" >&2
      exit 1
    fi
    # 3. A placeholder that is NOT a <<FILL: …>> field must be refused too. The
    #    runbooks write <release>, <address> and <date>, so one pasted line gets
    #    into a draft that otherwise looks complete — and the body is the one
    #    artifact nothing else in this repo reads.
    placeholder="$tmp/placeholder.txt"
    awk -v m="$MARKER" '{ print; if (index($0, m)) { print "Shipped in <release>."; print "" } }' \
      "$tmp/filled.txt" > "$placeholder"
    if ! grep -q '<release>' "$placeholder"; then
      echo "RELEASE-TAG SELF-TEST FAILED: could not inject the <release> placeholder" >&2
      exit 1
    fi
    if bash "$SELF" --write --in "$placeholder" --out "$tmp/placeholder-final.txt" >/dev/null 2>&1; then
      echo "RELEASE-TAG SELF-TEST FAILED: a body carrying <release> was accepted — a placeholder" >&2
      echo "would be signed into an immutable tag" >&2
      exit 1
    fi
    # The mail-style trailer is not a placeholder: a rule that refused it would
    # make every real draft unfillable.
    trailer="$tmp/trailer.txt"
    awk -v m="$MARKER" '{ print; if (index($0, m)) { print "Co-Authored-By: Codebuff <noreply@codebuff.com>"; print "" } }' \
      "$tmp/filled.txt" > "$trailer"
    if ! bash "$SELF" --write --in "$trailer" --out "$tmp/trailer-final.txt" >/dev/null 2>&1; then
      echo "RELEASE-TAG SELF-TEST FAILED: a mail-style trailer was mistaken for a placeholder" >&2
      exit 1
    fi
    echo "release-tag self-test: ok (a filled draft strips and validates; an unfilled one is"
    echo "  refused and writes nothing; a <release>/<address>-style placeholder is refused; a"
    echo "  mail-style <user@host> trailer is not)"
    exit 0
    ;;
  check)
    rc=0
    [ -f "$IN" ] || {
      echo "release-tag-message: $IN is missing — there is no tag message to strip" >&2
      exit 2
    }
    marks=$(grep -c "strip EVERYTHING above this line" "$IN" || true)
    if [ "$marks" != "1" ]; then
      echo "release-tag-message: the draft carries the strip marker $marks time(s), expected exactly 1 —" >&2
      echo "the strip would cut in the wrong place (or not at all)" >&2
      rc=1
    fi
    if [ "$(body "$IN" | head -1)" = "" ]; then
      echo "release-tag-message: the draft has no body after the strip marker" >&2
      rc=1
    fi
    # Any marker in the body that is NOT a <<FILL: …>> field is unexpected: the
    # draft is prose, and a stray << or >> means an edit broke a field span.
    stray=$(body "$IN" | grep -n '<<' | grep -v '<<FILL:' || true)
    if [ -n "$stray" ]; then
      echo "release-tag-message: the draft's body carries a marker that is not a <<FILL: …>> field:" >&2
      printf '%s\n' "$stray" | sed 's/^/  /' >&2
      rc=1
    fi
    # The runbook tells you to discard the dry run's fake scratch copy. If a
    # -final.txt is sitting there with markers in it, that is exactly that file.
    if [ -f "$OUT" ] && grep -qE '<<|<DRYRUN-|0x0{30,}|<[a-z][a-z0-9 _-]*>' "$OUT"; then
      echo "release-tag-message: $OUT exists and still carries markers or rehearsal values —" >&2
      echo "it is the dry run's scratch copy, not release material: delete it before tagging" >&2
      rc=1
    fi
    if [ "$rc" != "0" ]; then
      echo "RELEASE-TAG CHECK FAILED" >&2
      exit 1
    fi
    n=$(fields "$IN")
    if [ "$n" = "0" ]; then
      echo "release-tag-message: structure ok; every field is filled — run --write, then git tag -s"
    else
      echo "release-tag-message: structure ok; $n field(s) still unfilled (expected until release day):"
      body "$IN" | grep -o '<<FILL: [^>]*' | sed 's/^/     /' | cut -c1-96
    fi
    exit 0
    ;;
  fields)
    [ -f "$IN" ] || {
      echo "release-tag-message: $IN is missing" >&2
      exit 2
    }
    fields "$IN"
    exit 0
    ;;
  print)
    [ -f "$IN" ] || {
      echo "release-tag-message: $IN is missing" >&2
      exit 2
    }
    body "$IN"
    exit 0
    ;;
  write)
    [ -f "$IN" ] || {
      echo "release-tag-message: $IN is missing" >&2
      exit 2
    }
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/spore-tag.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    body "$IN" > "$tmp/body.txt"

    unresolved=$(body "$IN" | grep -c '<<FILL:' || true)
    if [ "$unresolved" != "0" ]; then
      echo "release-tag-message: refusing to strip — $unresolved <<FILL: …>> field(s) are still unfilled." >&2
      echo "A tag is immutable once pushed, so an unfilled field would be signed into it." >&2
      body "$IN" | grep -n '<<FILL:' | sed 's/^/  /' >&2
      echo "Fill them from docs/LIVE_NODES.md §3 (the receipt) and the saved estimator" >&2
      echo "output (the measured fee total), then re-run." >&2
      exit 1
    fi
    if ! validate_body "$tmp/body.txt"; then
      echo "RELEASE-TAG WRITE REFUSED: the stripped body is not signable." >&2
      exit 1
    fi
    mkdir -p "$(dirname "$OUT")"
    cp "$tmp/body.txt" "$OUT"
    echo "release-tag-message: wrote $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes, $(grep -c . "$OUT" || true) non-blank lines)"
    echo "  next: git tag -s v0.9.0 -F $OUT && git verify-tag v0.9.0"
    exit 0
    ;;
esac
