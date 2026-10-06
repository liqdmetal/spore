#!/usr/bin/env bash
# scripts/fuzz-corpus.sh — keep the fuzz corpus compounding, and minimal.
#
# Go's fuzzer keeps every input it finds interesting in
# $GOCACHE/fuzz/<import path>/<Target>/. That compounds on one machine, but it
# dies with the build cache (`go clean -cache`, a fresh clone, a new box) and is
# invisible to review — and the ClusterFuzzLite `cfl-corpus` branch that used to
# publish it went away with the workflows. This script is the durable store: it
# copies the cache's corpus into each package's testdata/fuzz/<Target>/, which
# Go loads as seed corpus on the next `go test` or `go test -fuzz`. A saved
# corpus therefore compounds, survives a cache wipe, and travels with the clone.
#
#   usage: scripts/fuzz-corpus.sh [--status] [--save] [--minimize] [-q]
#     --status      (default) per-target counts — saved, cached, and new; read-only
#     --save        copy every cached entry the repo lacks, then minimize
#     --minimize    drop entries that add no coverage (no cache copy)
#     --no-minimize with --save: copy only, keep the whole corpus
#     -q            print nothing unless something is new (used by the runners)
#
# Entries are named after the sha256 of their contents, so "new" is exact: a
# file of that name in the repo is the same input. A save never rewrites or
# deletes an entry, and never touches a crash reproducer Go wrote there.
#
# A corpus that only ever grows stops being reviewable: the first harvest here
# added 515 files, 202 of them from one target. --minimize keeps a *covering*
# subset instead. It builds an instrumented test binary per package and runs
# every entry alone, recording the statement blocks that entry exercises (with
# libFuzzer-style hit-count buckets, so inputs differing only in how often they
# loop stay distinct). It then greedily keeps the entries that cover the union:
# anything the union does not need is dropped from the repo *and* from the
# cache, so the two stores agree and the next save does not copy it straight
# back. Coverage is preserved by construction, and the pass refuses to delete
# unless it can prove the kept entries cover the same union. Git history still
# has every dropped input, and the fuzzer re-finds one if a change to the code
# makes it interesting again.
#
# `go test` replays the corpus as subtests, so it is not free forever — but at
# this size the cost is in the noise (measured: the coverage pass runs in about
# seven seconds, and the minimized corpus is well under a second slower to
# replay than an empty one).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SAVE=0
MINIMIZE=0
QUIET=0
while [ $# -gt 0 ]; do
  case "$1" in
    --status) SAVE=0; MINIMIZE=0; shift ;;
    --save) SAVE=1; MINIMIZE=1; shift ;;
    --minimize) MINIMIZE=1; shift ;;
    --no-minimize) MINIMIZE=0; shift ;;
    -q | --quiet) QUIET=1; shift ;;
    -h | --help)
      cat <<'USAGE'
usage: scripts/fuzz-corpus.sh [--status] [--save] [--minimize] [-q]
  --status       list saved/cached/new counts per target (default)
  --save         copy new cached inputs into testdata/fuzz/<Target>/, then minimize
  --minimize     drop corpus entries that add no coverage
  --no-minimize  with --save, skip the coverage pass and keep every entry
  -q             print nothing unless something is new
USAGE
      exit 0
      ;;
    *)
      echo "fuzz-corpus: unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
done

# The same nine targets scripts/fuzz-smoke.sh runs; TestFuzzSmokeListsEveryTarget
# (internal/wirefuzz) keeps BOTH scripts' lists in step with the code.
TARGETS=(
  "./internal/wirefuzz:FuzzFrameParse"
  "./internal/wirefuzz:FuzzHandshakeUnmarshal"
  "./internal/wirefuzz:FuzzMessageUnmarshal"
  "./internal/wirefuzz:FuzzFabricRPC2Frame"
  "./internal/ratchetwire:FuzzWireRoundtrip"
  "./internal/ratchetwire:FuzzWirePinEnforcement"
  "./internal/ratchetwire:FuzzWireMalformedFrames"
  "./internal/ratchetwire:FuzzDurableEndpointRoundtrip"
  "./internal/ratchetwire:FuzzEndpointFullRoundTrip"
)

command -v go >/dev/null 2>&1 || {
  echo "fuzz-corpus: go not found on PATH" >&2
  exit 1
}
MOD="$(awk '$1 == "module" { print $2 }' go.mod)"
CACHE="$(go env GOCACHE)/fuzz/$MOD"

# Every package the target list touches, in list order. Derived, never typed, so
# it cannot drift from TARGETS.
PKGS=()
for entry in "${TARGETS[@]}"; do
  p="${entry%%:*}"
  case " ${PKGS[*]:-} " in
    *" $p "*) ;;
    *) PKGS+=("$p") ;;
  esac
done

SCRATCH=""
if [ "$MINIMIZE" -eq 1 ]; then
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/spore-fuzz-corpus.XXXXXX")"
  trap 'rm -rf "$SCRATCH"' EXIT
fi

files_in() {
  local n=0
  if [ -d "$1" ]; then n="$(find "$1" -maxdepth 1 -type f | wc -l)"; fi
  printf '%s' "$n"
}

names_in() {
  if [ -d "$1" ]; then find "$1" -maxdepth 1 -type f -printf '%f\n' | sort; fi
}

ADDED=0
harvest() {
  local entry pkg target dest src f name
  for entry in "${TARGETS[@]}"; do
    pkg="${entry%%:*}"
    target="${entry##*:}"
    dest="$pkg/testdata/fuzz/$target"
    src="$CACHE/$pkg/$target"
    [ -d "$src" ] || continue
    while IFS= read -r f; do
      name="$(basename "$f")"
      [ -e "$dest/$name" ] && continue
      mkdir -p "$dest"
      cp "$f" "$dest/$name"
      ADDED=$((ADDED + 1))
    done < <(find "$src" -maxdepth 1 -type f)
  done
}

MIN_KEPT=0
MIN_DROPPED=0
minimize() {
  local bucket_awk greedy_awk jobs p pkey bin entry pkg target dest name f
  local base base_set sets list out greedy_out kept_file summary all_n union_n kept_n
  bucket_awk="$SCRATCH/bucket.awk"
  greedy_awk="$SCRATCH/greedy.awk"

  # One signature line per covered block, tagged with a libFuzzer-style hit-count
  # bucket (1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+) so two inputs that differ
  # only in how often they loop are still distinguishable.
  cat > "$bucket_awk" <<'AWK'
NR > 1 && $NF + 0 > 0 {
  c = $NF + 0
  b = (c == 1) ? 1 : (c == 2) ? 2 : (c == 3) ? 3 : (c <= 7) ? 4 : (c <= 15) ? 5 : (c <= 31) ? 6 : (c <= 127) ? 7 : 8
  print $1 "|" b
}
AWK

  # Greedy set cover over one file per entry (the file name is the entry). Prints
  # a SUMMARY line and one KEEP line per chosen entry so the caller can delete
  # the rest; all= vs union= is the proof that the kept set covers everything.
  cat > "$greedy_awk" <<'AWK'
{
  if (!(FILENAME in seen)) { seen[FILENAME] = 1; n++; order[n] = FILENAME }
  if ($0 != "") { sets[FILENAME][$0] = 1; all[$0] = 1 }
}
END {
  for (m in all) total++
  while (1) {
    best = ""; bestc = 0
    for (i = 1; i <= n; i++) {
      f = order[i]
      if (f in picked) continue
      c = 0
      for (m in sets[f]) if (!(m in cov)) c++
      if (c > bestc) { bestc = c; best = f }
    }
    if (bestc == 0) break
    picked[best] = 1; np++
    for (m in sets[best]) cov[m] = 1
  }
  covn = 0; for (m in cov) covn++
  printf "SUMMARY all=%d union=%d selected=%d files=%d\n", total, covn, np, n
  for (i = 1; i <= n; i++) if (order[i] in picked) print "KEEP " order[i]
}
AWK

  jobs=8
  if command -v nproc >/dev/null 2>&1; then jobs="$(nproc)"; fi

  # Instrument every package in the module: the code the targets exercise lives
  # in their dependencies, not in the package that declares them.
  for p in "${PKGS[@]}"; do
    pkey="${p//[^A-Za-z0-9]/_}"
    if ! go test -c -covermode=count -coverpkg=./... -o "$SCRATCH/$pkey.test" "$p" >/dev/null 2>&1; then
      echo "fuzz-corpus: cannot build an instrumented test binary for $p — corpus unchanged" >&2
      return 1
    fi
  done

  for entry in "${TARGETS[@]}"; do
    pkg="${entry%%:*}"
    target="${entry##*:}"
    dest="$pkg/testdata/fuzz/$target"
    [ -d "$dest" ] || continue
    pkey="${pkg//[^A-Za-z0-9]/_}"
    bin="$SCRATCH/$pkey.test"
    base="$SCRATCH/base.$pkey.$target.out"
    base_set="$SCRATCH/base.$pkey.$target.set"
    sets="$SCRATCH/sets/$pkey/$target"
    list="$SCRATCH/list.$pkey.$target"
    mkdir -p "$sets"

    # What merely starting the harness covers, so an entry is credited only with
    # the blocks it adds on top.
    ( cd "$pkg" && "$bin" -test.run 'ZZZnomatch' -test.coverprofile="$base" >/dev/null 2>&1 ) || true
    awk -f "$bucket_awk" "$base" | sort -u > "$base_set"

    : > "$list"
    for f in "$dest"/*; do
      name="$(basename "$f")"
      printf '%s %s %s %s %s\n' \
        "$pkg" "$bin" "^$target/$name\$" "$SCRATCH/prof.$pkey.$target.$name.out" "$name" >> "$list"
    done
    [ -s "$list" ] || continue

    # One isolated run per entry, in parallel; $5 (the name) is unused here.
    xargs -P "$jobs" -n 5 bash -c \
      'cd "$1" && "$2" -test.run "$3" -test.coverprofile="$4" >/dev/null 2>&1' _ < "$list" || true

    while read -r _pkg _bin _re out name; do
      if [ -f "$out" ]; then
        awk -f "$bucket_awk" "$out" | sort -u > "$SCRATCH/one.$pkey.$target.set"
        comm -23 "$SCRATCH/one.$pkey.$target.set" "$base_set" > "$sets/$name.set"
      else
        : > "$sets/$name.set"
      fi
    done < "$list"

    greedy_out="$SCRATCH/greedy.$pkey.$target"
    awk -f "$greedy_awk" "$sets"/*.set > "$greedy_out"
    summary="$(grep '^SUMMARY' "$greedy_out")"
    all_n="${summary#*all=}"; all_n="${all_n%% *}"
    union_n="${summary#*union=}"; union_n="${union_n%% *}"
    if [ "$all_n" != "$union_n" ]; then
      echo "fuzz-corpus: keeping $target whole — the chosen entries cover $union_n of $all_n signature(s)" >&2
      continue
    fi

    kept_file="$SCRATCH/kept.$pkey.$target"
    grep '^KEEP ' "$greedy_out" | while read -r _ path; do basename "$path" .set; done > "$kept_file"
    # An entry that covers nothing new is redundant, but a target with no
    # coverage at all should still keep one seed rather than none.
    if [ ! -s "$kept_file" ]; then
      find "$dest" -maxdepth 1 -type f -printf '%f\n' | sort | head -n 1 > "$kept_file"
    fi

    while IFS= read -r f; do
      name="$(basename "$f")"
      if grep -qxF "$name" "$kept_file"; then
        MIN_KEPT=$((MIN_KEPT + 1))
        continue
      fi
      # Only the reproducible corpus format is ours to prune; anything else in
      # here (a crash reproducer, someone's note) is left exactly as it is.
      if head -n 1 "$f" 2>/dev/null | grep -q '^go test fuzz v1'; then
        rm -f "$f" "$CACHE/$pkg/$target/$name"
        MIN_DROPPED=$((MIN_DROPPED + 1))
      else
        MIN_KEPT=$((MIN_KEPT + 1))
      fi
    done < <(find "$dest" -maxdepth 1 -type f)
  done
}

if [ "$SAVE" -eq 1 ]; then harvest; fi
if [ "$MINIMIZE" -eq 1 ]; then minimize; fi

rows=""
new_total=0
saved_total=0
for entry in "${TARGETS[@]}"; do
  pkg="${entry%%:*}"
  target="${entry##*:}"
  dest="$pkg/testdata/fuzz/$target"
  src="$CACHE/$pkg/$target"

  saved="$(files_in "$dest")"
  cached="$(files_in "$src")"
  new=0
  if [ -d "$src" ]; then
    new="$(comm -13 <(names_in "$dest") <(names_in "$src") | wc -l)"
  fi

  rows="${rows}$(printf '  %-32s saved=%-4s cached=%-4s new=%s\n' "$target" "$saved" "$cached" "$new")"$'\n'
  new_total=$((new_total + new))
  saved_total=$((saved_total + saved))
done

if [ "$QUIET" -eq 1 ]; then
  # Called by a fuzz run: say something only when there is something to keep.
  if [ "$new_total" -gt 0 ]; then
    echo "fuzz-corpus: $new_total input(s) the fuzz cache gained are not in the repo — run scripts/fuzz-corpus.sh --save to keep them"
  fi
  exit 0
fi

printf '== fuzz corpus (repo testdata/fuzz vs the build cache)\n%s' "$rows"
if [ "$MINIMIZE" -eq 1 ]; then
  echo "keep $MIN_KEPT entr(ies) covering the same code; dropped $MIN_DROPPED redundant one(s) from the repo and the cache"
fi
if [ "$SAVE" -eq 1 ]; then
  echo "saved $ADDED new input(s) across ${#TARGETS[@]} target(s); corpus now $saved_total file(s)"
else
  echo "$new_total new input(s) available; run scripts/fuzz-corpus.sh --save to preserve them"
fi
