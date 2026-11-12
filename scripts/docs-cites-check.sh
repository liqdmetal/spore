#!/usr/bin/env bash
# docs-cites-check.sh — a doc may cite a path, flag or identifier only if it exists.
#
# The audit that preceded this gate was done by hand: every backticked path,
# flag and constant in the docs was grepped against the tree, and the ones that
# had outlived their code were fixed. That found `internal/routing` (a package
# that does not exist), a workflow file deleted with the rest of the CI, and a
# flag list that described the Rust relay while reading like this binary's. A
# one-off sweep cannot stop the next rename, and no other gate looks at prose:
# doc-refs checks commit hashes resolve, the constants gate checks sizes, and
# everything else reads Go. This closes the third hole.
#
# Three classes are checked, each by a rule narrow enough to stay out of prose:
#
#   paths       a token containing `/` whose FIRST SEGMENT is a directory in the
#               tree is a repo path and must exist. That one condition keeps
#               `Peer.FabricPut/Pop`, `I/C/D`, `src/p2p.rs`, `github.com/x/y`
#               and `/var/lib/monero` out of it — none starts with a directory
#               this repository has — while `internal/routing` and
#               `.github/workflows/gone.yml` are exactly what it catches. A path
#               that does not exist may still be a symbol path
#               (`internal/solana.DefaultProgramID`) or a signing domain
#               (`spore/attest/v1`, verified as a Go string literal), and a
#               `:line` suffix is stripped before the existence test.
#   flags       `-name` / `--name`, matched against flag registrations in Go
#               (`fs.String("name"`, `flag.Bool("name"`) and against dashes in
#               scripts and units. A flag of another tool (git, go test,
#               monerod) is not this repo's and must be declared.
#   identifiers `SweepOrphans`, `Pkg.Name`, `SPORE_PEER_BIN` — verified as a word
#               in the tree's own source (Go, shell, systemd, Solidity, vectors).
#               Rust-peer types and external APIs live elsewhere and are declared.
#
# Deliberately not checked: bare file names (`config.json`, `WIRE_SPEC.md`) —
# they are as often runtime state or a doc title as a citation, and the noisy
# first version of this gate drowned in them; absolute paths, home-relative
# paths, URLs, templates, globs and shell snippets, none of which this checkout
# can resolve.
#
# The release-prep set is read too, because it is the text that ships: the
# release-designs notes are prose an operator follows, the tag message is signed
# verbatim into an immutable tag, and the frozen patches are the flip applied by
# hand on release day. For a patch only the lines it INSTALLS are checked (the
# `+` lines); its context and `-` lines quote the tree the patch deletes, so
# requiring them to resolve today would fail on the very deletion it records.
# The patches stay out of the SOURCE corpus, though: a name that exists only in
# release text has not been verified, it has been echoed back, and a doc citing
# it must fail.
#
#   bash scripts/docs-cites-check.sh              # check the docs
#   bash scripts/docs-cites-check.sh --quiet      # exit status only
#   bash scripts/docs-cites-check.sh --list       # every token and its verdict
#   bash scripts/docs-cites-check.sh --self-check # prove the checker works
#
# --self-check builds a fixture tree (a doc citing a real path, a real flag, a
# real constant) and requires green, then breaks one citation of each class and
# requires red for each, then deletes the constant from the source and requires
# red again with the doc unchanged. A checker that only reads the docs passes
# the first case and fails that last one.
#
# The allowlist is scripts/docs-cites-allow.txt: `token  reason` per line. For a
# flag the token is the bare name (`pidfile`, not `--pidfile`), so one row covers
# every spelling a doc uses. An allowlist row no doc uses any more is itself a
# failure: otherwise the file quietly becomes a list of things nobody checks.
#
# The release set is also the only question a tree that is not this repository
# can answer. scripts/release-day-rehearsal.sh applies the frozen patches to a
# base that predates this repo's docs, so --release-only reads just the notes,
# the tag draft and the lines the patches install: exactly what release day
# publishes, resolved in the tree it publishes into. It also skips the unused-row
# check, because a partial corpus cannot prove a row outlived its reason.
#
# Exit codes: 0 every citation resolves, 1 a citation does not, 2 cannot check,
# 3 usage.
set -euo pipefail

QUIET=0
SELF_CHECK=0
LIST=0
CODE_ROOT=""
DOC_ROOT=""
ALLOW_FILE=""
RELEASE_ONLY=0

usage() {
  cat <<'EOF'
usage: bash scripts/docs-cites-check.sh [--quiet] [--list] [--self-check]
                                        [--code-root DIR] [--docs-root DIR]
                                        [--allow FILE]

  --quiet        exit status only
  --list         print every backticked token with its verdict
  --self-check   run the fixture rehearsal (green, then red per class, then red
                 after deleting the constant)
  --code-root    tree the citations resolve against (default: the repo)
  --docs-root    tree the docs are read from (default: the same tree)
  --allow        allowlist file (default: scripts/docs-cites-allow.txt)
  --release-only read only the text that ships (notes, tag draft, the lines the
                 patches install); the docs corpus and the unused-row check are
                 skipped, for a tree that is not this repository's docs

Docs checked: docs/*.md, README.md, design.md, solana-program/README.md,
release-designs/*.md, release-designs/*tag-message*.txt, and the lines each
release-designs/*.patch installs (its context and `-` lines describe a tree
that is already gone and are not checked)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --list) LIST=1 ;;
    --release-only) RELEASE_ONLY=1 ;;
    --self-check) SELF_CHECK=1 ;;
    --code-root)
      [ "$#" -ge 2 ] || { echo "docs-cites-check: --code-root needs a directory" >&2; exit 3; }
      CODE_ROOT=$2; shift ;;
    --docs-root)
      [ "$#" -ge 2 ] || { echo "docs-cites-check: --docs-root needs a directory" >&2; exit 3; }
      DOC_ROOT=$2; shift ;;
    --allow)
      [ "$#" -ge 2 ] || { echo "docs-cites-check: --allow needs a file" >&2; exit 3; }
      ALLOW_FILE=$2; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "docs-cites-check: unknown argument: $1 (see --help)" >&2; exit 3 ;;
  esac
  shift
done

if [ -z "$CODE_ROOT" ]; then
  CODE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "docs-cites-check: not inside a git repository" >&2
    exit 2
  }
fi
[ -d "$CODE_ROOT" ] || { echo "docs-cites-check: not a directory: $CODE_ROOT" >&2; exit 2; }
CODE_ROOT=$(cd "$CODE_ROOT" && pwd)
[ -n "$DOC_ROOT" ] || DOC_ROOT=$CODE_ROOT
[ -d "$DOC_ROOT" ] || { echo "docs-cites-check: not a directory: $DOC_ROOT" >&2; exit 2; }
DOC_ROOT=$(cd "$DOC_ROOT" && pwd)
[ -n "$ALLOW_FILE" ] || ALLOW_FILE="$CODE_ROOT/scripts/docs-cites-allow.txt"

WORK=$(mktemp -d) || exit 2
trap 'rm -rf "$WORK"' EXIT

CHECKED=0 FAILED=0 SKIPPED=0
declare -A WORDS FLAGS QUOTED ALLOW USED

# ---- the corpus ------------------------------------------------------------
# One pass over the tree's own source. Vendored trees (tools/), build output
# (target/), runtime state and frozen doc patches (release-designs/) are pruned.
build_sets() {
  local root=$1 line
  find "$root" \
    \( -name .git -o -name tools -o -name node_modules -o -name _review_tmp \
    -o -name .push-detached -o -name target -o -name .gate-run.lock \
    -o -name release-designs \) -prune -o \
    -type f ! -name docs-cites-allow.txt \( -name '*.go' -o -name '*.sh' -o -name '*.ps1' -o -name '*.py' \
    -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' -o -name '*.sol' \
    -o -name '*.service' -o -name '*.toml' -o -name '*.patch' -o -name '*.txt' \) \
    -print 2>/dev/null >"$WORK/files" || true

  if [ ! -s "$WORK/files" ]; then
    echo "docs-cites-check: no source files under $root — cannot check" >&2
    return 2
  fi
  tr '\n' '\0' <"$WORK/files" >"$WORK/files.z"

  xargs -0 -r grep -hoE --binary-files=without-match '[A-Za-z_][A-Za-z0-9_]*' \
    <"$WORK/files.z" | tr -d '\r' | sort -u >"$WORK/words" || true

  {
    # Flag registrations are quoted and dashless in Go; script and unit flags
    # carry the dashes. Both spellings are how a doc ends up citing one.
    xargs -0 -r grep -hoE --binary-files=without-match \
      '(fs|flag)\.(String|Bool|Int|Int64|Uint|Uint64|Duration|Float64|Var)\("[a-z0-9-]+"' \
      <"$WORK/files.z" | sed 's/.*("//; s/"$//' || true
    xargs -0 -r grep -hoE --binary-files=without-match -- '--?[a-z][a-z0-9-]*' \
      <"$WORK/files.z" | sed 's/^-*//' || true
  } | tr -d '\r' | sort -u >"$WORK/flags" || true

  xargs -0 -r grep -hoE --binary-files=without-match '"[^"]*"' <"$WORK/files.z" \
    | sed 's/^"//; s/"$//' | tr -d '\r' | sort -u >"$WORK/quoted" || true

  while IFS= read -r line; do [ -n "$line" ] && WORDS[$line]=1; done <"$WORK/words"
  while IFS= read -r line; do [ -n "$line" ] && FLAGS[$line]=1; done <"$WORK/flags"
  while IFS= read -r line; do [ -n "$line" ] && QUOTED[$line]=1; done <"$WORK/quoted"
  return 0
}

load_allow() {
  local token reason
  [ -f "$ALLOW_FILE" ] || return 0
  # Default IFS: token is the first field, the reason is the rest of the line.
  while read -r token reason; do
    case "$token" in '' | '#'*) continue ;; esac
    token=${token%$'\r'}
    [ -n "$token" ] || continue
    ALLOW[$token]=${reason:-no reason given}
  done <"$ALLOW_FILE"
}

# ---- verdicts --------------------------------------------------------------
fail() { # FILE:LINE TOKEN WHY
  FAILED=$((FAILED + 1))
  [ "$QUIET" -eq 1 ] && return 0
  printf '  %s:%s: `%s` %s\n' "$1" "$2" "$3" "$4"
  return 0
}

allowed() { # TOKEN — true when the allowlist covers it (and records the use)
  if [ -n "${ALLOW[$1]+x}" ]; then
    USED[$1]=1
    return 0
  fi
  return 1
}

skip() {
  SKIPPED=$((SKIPPED + 1))
  [ "$LIST" -eq 1 ] && printf 'skip    %s:%s %s\n' "$1" "$2" "$3"
  return 0
}

check_token() { # FILE LINE TOKEN
  local f=$1 ln=$2 tok=$3 name prefix tail probe
  tok=${tok#"${tok%%[![:space:]]*}"}
  tok=${tok%"${tok##*[![:space:]]}"}
  [ -n "$tok" ] || return 0

  # Not citations this checkout can resolve: shell, templates, globs, URLs,
  # absolute or home-relative paths, and directory references with a trailing
  # slash.
  case $tok in
    *' '* | *'*'* | *'$'* | *'<'* | *'>'* | *'{'* | *'}'* | *'|'* | *'('* | *')'* | *'='* | *'\'* | *'"'* | *"'"* | *://*)
      skip "$f" "$ln" "$tok"; return 0 ;;
    ../* | /* | '~'* | */) skip "$f" "$ln" "$tok"; return 0 ;;
  esac

  CHECKED=$((CHECKED + 1))

  if [[ $tok == */* ]]; then
    # `file.go:184` cites a line; the file is what has to exist.
    probe=$tok
    case $tok in *:[0-9]*) probe=${tok%:*} ;; esac
    if [ -e "$CODE_ROOT/$tok" ] || [ -e "$CODE_ROOT/$probe" ]; then
      [ "$LIST" -eq 1 ] && printf 'path    %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    # Only a token whose first segment is a real directory is a repo path. This
    # is what keeps prose slashes (`Peer.FabricPut/Pop`, `I/C/D`) and other
    # projects' trees (`src/p2p.rs`, `tests/x.rs`) out of the net.
    prefix=${tok%%/*}
    if [ ! -d "$CODE_ROOT/$prefix" ]; then
      CHECKED=$((CHECKED - 1))
      skip "$f" "$ln" "$tok"
      return 0
    fi
    # A symbol path: `internal/solana.DefaultProgramID` is a path plus `.Ident`.
    prefix=${tok%.*}
    tail=${tok##*.}
    if [ "$prefix" != "$tok" ] && [ -e "$CODE_ROOT/$prefix" ] && [ -n "${WORDS[$tail]+x}" ]; then
      [ "$LIST" -eq 1 ] && printf 'symbol  %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    # A signing domain: `spore/attest/v1` has no extension and is not a file,
    # but the code must carry the literal — a domain nothing signs under is
    # exactly the drift worth failing on.
    if [[ $tok != *.* ]] && [ -n "${QUOTED[$tok]+x}" ]; then
      [ "$LIST" -eq 1 ] && printf 'domain  %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    if allowed "$tok"; then
      [ "$LIST" -eq 1 ] && printf 'allow   %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    fail "$f" "$ln" "$tok" "is cited as a path but does not exist under $CODE_ROOT"
    return 0
  fi

  if [[ $tok =~ ^-{1,2}[a-z][a-z0-9-]*$ ]]; then
    name=${tok#-}
    name=${name#-}
    if [ -n "${FLAGS[$name]+x}" ]; then
      [ "$LIST" -eq 1 ] && printf 'flag    %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    # Allowlist rows name the flag without its dashes, so `pidfile` covers
    # `-pidfile` and `--pidfile`.
    if allowed "$name"; then
      [ "$LIST" -eq 1 ] && printf 'allow   %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    fail "$f" "$ln" "$tok" "is cited as a flag but no Go registration or script uses it"
    return 0
  fi

  # Identifiers: dotted (Pkg.Name, Type.Method) or shaped like Go (camel hump,
  # or an ALL_CAPS name with an underscore). Plain lowercase words and acronyms
  # are prose and stay out of the net — `spore`, `json`, `curl` are not claims.
  if [[ $tok =~ ^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$ ]] ||
    [[ $tok =~ ^[A-Za-z_][A-Za-z0-9_]*$ && ($tok =~ [a-z][A-Z] || $tok =~ _[A-Z0-9]) ]]; then
    tail=${tok##*.}
    if [ -n "${WORDS[$tail]+x}" ]; then
      [ "$LIST" -eq 1 ] && printf 'ident   %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    if allowed "$tok"; then
      [ "$LIST" -eq 1 ] && printf 'allow   %s:%s %s\n' "$f" "$ln" "$tok"
      return 0
    fi
    fail "$f" "$ln" "$tok" "is cited as an identifier but no source file defines it"
    return 0
  fi

  skip "$f" "$ln" "$tok"
  return 0
}

check_line() { # FILE LINE TEXT — every backticked token on one line
  local rest=$3 tok
  while [[ $rest == *'`'*'`'* ]]; do
    rest=${rest#*\`}
    tok=${rest%%\`*}
    rest=${rest#*\`}
    check_token "$1" "$2" "$tok"
  done
}

check_doc() { # FILE
  local line
  while IFS= read -r line; do
    check_line "$1" "${line%%:*}" "${line#*:}"
  done < <(grep -n '`' "$1" 2>/dev/null || true)
}

# check_patch FILE — only the lines the patch installs. Its context and `-` lines
# quote the tree the patch deletes; requiring them to resolve would fail on the
# deletion the patch exists to record, which is why they are not read at all.
check_patch() { # FILE
  local line
  while IFS= read -r line; do
    check_line "$1" "${line%%:*}" "${line#*:}"
  done < <(awk '/^\+/ && !/^\+\+\+/ { print NR ":" $0 }' "$1" 2>/dev/null || true)
}

# ---- the run ---------------------------------------------------------------
check_tree() {
  local f missing=0 extra docs_seen=0
  local rel_dir="$DOC_ROOT/release-designs" rel_md=0 rel_tag=0 rel_patch=0
  build_sets "$CODE_ROOT" || return 2
  load_allow

  # --release-only: the shipped text is read, the docs corpus is not. A tree that
  # is not this repository (the flipped release tree) cannot answer the docs
  # questions — it is older than the docs are — but it can answer the one that
  # matters on release day.
  if [ "$RELEASE_ONLY" -eq 0 ]; then
    for f in "$DOC_ROOT"/docs/*.md; do
      [ -f "$f" ] || continue
      check_doc "$f"
      docs_seen=$((docs_seen + 1))
    done
    for extra in README.md design.md solana-program/README.md; do
      if [ ! -f "$DOC_ROOT/$extra" ]; then
        echo "docs-cites-check: $extra is missing" >&2
        missing=1
        continue
      fi
      check_doc "$DOC_ROOT/$extra"
    done
  fi
  # The release-prep set: notes an operator follows, the tag message that is
  # signed verbatim, and the doc text each frozen patch installs on release day.
  for f in "$rel_dir"/*.md; do
    [ -f "$f" ] || continue
    check_doc "$f"
    rel_md=$((rel_md + 1))
  done
  for f in "$rel_dir"/*tag-message*.txt; do
    case $f in *-final.txt) continue ;; esac   # written at tag time, never committed
    [ -f "$f" ] || continue
    check_doc "$f"
    rel_tag=$((rel_tag + 1))
  done
  for f in "$rel_dir"/*.patch; do
    [ -f "$f" ] || continue
    check_patch "$f"
    rel_patch=$((rel_patch + 1))
  done
  # Zero of any of them is not "nothing to check": the text that ships is the
  # last thing that may be read as prose without being resolved.
  if [ "$rel_md" -eq 0 ] || [ "$rel_tag" -eq 0 ] || [ "$rel_patch" -eq 0 ]; then
    echo "docs-cites-check: release text missing under $rel_dir (notes=$rel_md tag-message=$rel_tag patches=$rel_patch) — the text that ships was not read" >&2
    return 2
  fi

  [ "$missing" -eq 1 ] && return 2

  if [ "$RELEASE_ONLY" -eq 0 ] && [ "$docs_seen" -eq 0 ]; then
    echo "docs-cites-check: no docs/*.md under $DOC_ROOT — nothing was checked" >&2
    return 2
  fi

  # An allowlist row nobody needs is a hole waiting to be reused: the entry
  # outlives its reason, and the next doc cites it freely.
  local t unused=0
  # A scoped run does not read most of what the rows exist for, so it cannot
  # judge them: leaving this on would fail every release-only run.
  if [ "$RELEASE_ONLY" -eq 0 ]; then
    for t in "${!ALLOW[@]}"; do
      if [ -z "${USED[$t]+x}" ]; then
        unused=$((unused + 1))
        [ "$QUIET" -eq 1 ] || printf '  %s: allowlist row is unused — delete it (%s)\n' "$ALLOW_FILE" "$t"
      fi
    done
  fi

  if [ "$FAILED" -gt 0 ]; then
    [ "$QUIET" -eq 1 ] || printf '\ndocs-cites-check: %s of %s citation(s) do not resolve; %s skipped\n' \
      "$FAILED" "$CHECKED" "$SKIPPED"
    return 1
  fi
  [ "$unused" -gt 0 ] && return 1
  [ "$QUIET" -eq 1 ] || printf 'docs-cites-check: clean — %s citation(s) resolve, %s skipped (prose, globs, out-of-tree); release text: %s notes, %s tag message, %s patch addition(s)\n' \
    "$CHECKED" "$SKIPPED" "$rel_md" "$rel_tag" "$rel_patch"
  return 0
}

# ---- the rehearsal ---------------------------------------------------------
self_check() {
  local tmp fail=0 cls tok target
  tmp=$(mktemp -d) || { echo "docs-cites-check: mktemp failed" >&2; return 2; }
  mkdir -p "$tmp/code/scripts" "$tmp/code/internal/known" "$tmp/proj/docs" \
    "$tmp/proj/solana-program" "$tmp/proj/release-designs"
  printf 'echo known\n' >"$tmp/code/scripts/known.sh"
  cat >"$tmp/code/internal/known/known.go" <<'GO'
package known

const KnownConstant = 1

func register(fs interface{ String(string, string, string) *string }) {
	fs.String("known-flag", "", "a flag the doc cites")
}
GO
  : >"$tmp/proj/README.md"
  : >"$tmp/proj/design.md"
  : >"$tmp/proj/solana-program/README.md"
  # The release set, including the two lines a patch may NOT be held to: its
  # context and its deletion both cite a name that is gone, and the green run
  # below is what proves they are left alone. The directory is named once and
  # joined from there: a literal `<set>/notes.md` in a tracked file would read as
  # a pointer to an artifact that does not exist, and scripts/release-designs-check.sh
  # fails the build on exactly that.
  local rel_dir="$tmp/proj/release-designs"
  cat >"$rel_dir/notes.md" <<'MD'
# fixture release notes

Flip `internal/known/known.go`; the runbook still names `scripts/known.sh`.
MD
  cat >"$tmp/proj/release-designs/v0.9.0-tag-message.txt" <<'TXT'
# fixture tag draft — do not tag
# (strip EVERYTHING above this line)

Tag for `scripts/known.sh` — receipt in `docs/sample.md`.
TXT
  cat >"$tmp/proj/release-designs/v0.9.0-doc-flips.patch" <<'PATCH'
--- a/docs/sample.md
+++ b/docs/sample.md
@@ -1,3 +1,3 @@
 A context line that still cites `scripts/gone.sh`.
-The removed line cited `scripts/gone.sh` and `KnownConstant`.
+The installed line cites `scripts/known.sh` and `KnownConstant`.
 A trailing context line.
PATCH
  cat >"$tmp/proj/docs/sample.md" <<'MD'
# fixture

A path `scripts/known.sh`, a flag `-known-flag`, a constant `KnownConstant`.
MD

  local saved_code=$CODE_ROOT saved_docs=$DOC_ROOT saved_allow=$ALLOW_FILE
  local saved_checked=$CHECKED saved_failed=$FAILED saved_skipped=$SKIPPED

  run_fixture() {
    CODE_ROOT=$tmp/code DOC_ROOT=$tmp/proj ALLOW_FILE=$tmp/allow
    CHECKED=0 FAILED=0 SKIPPED=0
    WORDS=() FLAGS=() QUOTED=() ALLOW=() USED=()
    check_tree >/dev/null 2>&1
    return $?
  }

  : >"$tmp/allow"
  if run_fixture; then
    echo "self-check: fixture citations resolve"
  else
    echo "self-check: FAILED — the fixture's own citations do not resolve"
    run_fixture >&2 || true
    fail=1
  fi

  # One class at a time, so a failure names the class it proves.
  for cls in path flag ident release patch; do
    case $cls in
      path) target="$tmp/proj/docs/sample.md"; tok='scripts/gone.sh' ;;
      flag) target="$tmp/proj/docs/sample.md"; tok='-gone-flag' ;;
      ident) target="$tmp/proj/docs/sample.md"; tok='GoneConstant' ;;
      release) target="$rel_dir/notes.md"; tok='scripts/release-gone.sh' ;;
      patch) target="$tmp/proj/release-designs/v0.9.0-doc-flips.patch"; tok='scripts/patch-gone.sh' ;;
    esac
    if [ "$cls" = patch ]; then
      printf '+The patch would install `%s`.\n' "$tok" >>"$target"
    else
      printf '\nAlso `%s`.\n' "$tok" >>"$target"
    fi
    if run_fixture; then
      echo "self-check: FAILED — a missing $cls (\"$tok\") passed"
      fail=1
    else
      echo "self-check: missing $cls is red"
    fi
    sed -i '$ d' "$target"
  done

  # The other direction: the doc is untouched and the code loses the name. A
  # checker that compares against values built into itself is still green here.
  sed -i '/KnownConstant/d' "$tmp/code/internal/known/known.go"
  if run_fixture; then
    echo "self-check: FAILED — deleting KnownConstant from the source left the doc green"
    fail=1
  else
    echo "self-check: code drift is red"
  fi

  # Release text must not verify itself. One tree, because that is the real
  # layout: with separate roots the corpus never held the patch to match in the
  # first place. The name lives ONLY in a patch deletion, so a corpus that still
  # read release-designs/ — or a patch reader that also read `-` lines — would
  # find it and pass the doc. Both must fail.
  local one="$tmp/one" one_rel="$tmp/one/release-designs"
  mkdir -p "$one/scripts" "$one/docs" "$one/solana-program" "$one_rel"
  printf 'echo known\n' >"$one/scripts/known.sh"
  : >"$one/README.md"
  : >"$one/design.md"
  : >"$one/solana-program/README.md"
  printf 'Cite `scripts/known.sh`.\n' >"$one/docs/sample.md"
  printf '# notes\n\nThe flip touches `scripts/known.sh`.\n' >"$one_rel/notes.md"
  printf '# draft\n# (strip EVERYTHING above this line)\n\nTag for `scripts/known.sh`.\n' \
    >"$one/release-designs/v0.9.0-tag-message.txt"
  printf -- '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-A line that mentions `PatchOnlyName`.\n+The line it installs.\n' \
    >"$one/release-designs/v0.9.0-doc-flips.patch"

  run_same_tree() {
    CODE_ROOT=$one DOC_ROOT=$one ALLOW_FILE=$tmp/allow
    CHECKED=0 FAILED=0 SKIPPED=0
    WORDS=() FLAGS=() QUOTED=() ALLOW=() USED=()
    check_tree >/dev/null 2>&1
    return $?
  }

  if run_same_tree; then
    echo "self-check: single tree with release text resolves"
  else
    echo "self-check: FAILED — the single-tree fixture does not resolve"
    run_same_tree >&2 || true
    fail=1
  fi
  printf 'Also `PatchOnlyName`.\n' >>"$one/docs/sample.md"
  if run_same_tree; then
    echo "self-check: FAILED — a doc verified against a name only release text carries"
    fail=1
  else
    echo "self-check: release text cannot verify a doc (echo is not evidence)"
  fi

  # --release-only must stop reading the docs corpus, not the shipped text. The
  # doc above already cites two names that are gone; the release set still
  # resolves, so a green run here is the corpus being skipped and nothing else.
  run_release_only() {
    RELEASE_ONLY=1
    run_same_tree
    local rc=$?
    RELEASE_ONLY=0
    return "$rc"
  }
  if run_release_only; then
    echo "self-check: release-only ignores the docs corpus"
  else
    echo "self-check: FAILED — release-only refused a release set that resolves"
    run_release_only >&2 || true
    fail=1
  fi
  printf '\nAlso `scripts/release-gone.sh`.\n' >>"$one_rel/notes.md"
  if run_release_only; then
    echo "self-check: FAILED — release-only passed a note citing a gone script"
    fail=1
  else
    echo "self-check: release-only still fails a note that cites a gone name"
  fi

  CODE_ROOT=$saved_code DOC_ROOT=$saved_docs ALLOW_FILE=$saved_allow
  CHECKED=$saved_checked FAILED=$saved_failed SKIPPED=$saved_skipped
  rm -rf "$tmp"

  [ "$fail" -eq 0 ] || return 1
  echo "self-check: the gate reads every class in both directions, the patch's"
  echo "  installed lines only, the release set without letting it verify itself,"
  echo "  and the shipped text alone when the tree is not this repo's docs"
  return 0
}

if [ "$SELF_CHECK" -eq 1 ]; then
  self_check
  exit $?
fi

check_tree
