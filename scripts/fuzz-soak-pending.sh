#!/usr/bin/env bash
# Pending-corpus state for fuzz-soak.sh. The soak owns pass ordering; this helper
# owns cache snapshots, the local manifest, HEAD filtering, and report summary.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
SOAK_DIR="${FUZZ_SOAK_DIR:-$REPO_ROOT/.fuzz-soak}"
MANIFEST="$SOAK_DIR/pending-first-seen.tsv"
BEFORE="$SOAK_DIR/.pending-before"
BEFORE_CACHE_OK="$SOAK_DIR/.pending-before-cache-ok"
AFTER="$SOAK_DIR/.pending-after"

usage() { echo "usage: fuzz-soak-pending.sh begin | finish EPOCH" >&2; exit 2; }
[ "$#" -ge 1 ] || usage

corpus_dirs() { find internal -type d -path '*/testdata/fuzz' -print 2>/dev/null | sort; }

corpus_entries() {
  local d target f
  while IFS= read -r d; do
    for target in "$d"/Fuzz*; do
      [ -d "$target" ] || continue
      for f in "$target"/*; do
        [ -f "$f" ] && printf '%s\n' "$f"
      done
    done
  done < <(corpus_dirs) | sort -u
}

cache_entries() {
  local cache mod d pkg f target
  cache="$(go env GOCACHE)" || return 1
  if command -v cygpath >/dev/null 2>&1; then cache="$(cygpath -u "$cache")" || return 1; fi
  mod="$(awk '$1 == "module" { print $2; exit }' go.mod)"
  [ -n "$mod" ] || return 1
  cache="$cache/fuzz/$mod"
  while IFS= read -r d; do
    pkg="${d%/testdata/fuzz}"
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      target="${f%/*}"
      target="${target##*/}"
      case "$target" in Fuzz*) ;; *) continue ;; esac
      printf '%s/testdata/fuzz/%s/%s\n' "$pkg" "$target" "${f##*/}"
    done < <(find "$cache/$pkg" -type f 2>/dev/null)
  done < <(corpus_dirs) | sort -u
}

human() {
  local seconds="$1"
  if [ "$seconds" -ge 3600 ]; then printf '%dh%dm' "$((seconds / 3600))" "$((seconds % 3600 / 60))"
  elif [ "$seconds" -ge 60 ]; then printf '%dm%ds' "$((seconds / 60))" "$((seconds % 60))"
  else printf '%ds' "$seconds"; fi
}

begin() {
  mkdir -p "$SOAK_DIR"
  local tmp="$BEFORE.tmp.$$" cache_ok=0
  corpus_entries > "$tmp"
  if cache_entries > "$tmp.cache"; then cache_ok=1; else : > "$tmp.cache"; fi
  cat "$tmp.cache" >> "$tmp"
  sort -u -o "$tmp" "$tmp"
  mv "$tmp" "$BEFORE"
  rm -f "$tmp.cache"
  printf '%s\n' "$cache_ok" > "$BEFORE_CACHE_OK"
}

finish() {
  local now="$1" identity epoch oldest_epoch="" oldest_entry="" count=0 unknown=0
  local cache_ok=0 tmp="$MANIFEST.tmp.$$"
  case "$now" in '' | *[!0-9]*) echo "pending ages: epoch must be numeric" >&2; return 2 ;; esac
  local -A before=() tracked=() present=() first_seen=()
  while IFS= read -r identity; do before["$identity"]=1; done < "$BEFORE"
  cache_ok="$(cat "$BEFORE_CACHE_OK")"
  if [ -f "$MANIFEST" ]; then
    while IFS=$'\t' read -r identity epoch; do first_seen["$identity"]="$epoch"; done < "$MANIFEST"
  fi
  while IFS= read -r identity; do
    case "$identity" in internal/*/testdata/fuzz/Fuzz*/*) tracked["$identity"]=1 ;; esac
  done < <(git ls-tree -r --name-only HEAD -- internal)

  corpus_entries > "$AFTER"
  local after_cache_ok=0
  if cache_entries >> "$AFTER"; then after_cache_ok=1; fi
  sort -u -o "$AFTER" "$AFTER"
  while IFS= read -r identity; do present["$identity"]=1; done < "$AFTER"

  : > "$tmp"
  for identity in "${!present[@]}"; do
    [ -z "${tracked["$identity"]:-}" ] || continue
    count=$((count + 1))
    epoch="${first_seen["$identity"]:-}"
    if [ -z "$epoch" ]; then
      if [ "$cache_ok" = 1 ] && [ "$after_cache_ok" = 1 ] && [ -z "${before["$identity"]:-}" ]; then
        epoch="$now"
      else
        epoch='?'
      fi
    fi
    printf '%s\t%s\n' "$identity" "$epoch" >> "$tmp"
    if [ "$epoch" = '?' ]; then
      unknown=$((unknown + 1))
    elif [ -z "$oldest_epoch" ] || [ "$epoch" -lt "$oldest_epoch" ]; then
      oldest_epoch="$epoch"
      oldest_entry="$identity"
    fi
  done
  sort -o "$tmp" "$tmp"
  mv "$tmp" "$MANIFEST"

  printf -- '- unmerged entries: %s\n' "$count"
  if [ -n "$oldest_epoch" ]; then
    local age=$((now - oldest_epoch))
    [ "$age" -ge 0 ] || age=0
    printf -- '- oldest known age: %s (%s)\n' "$(human "$age")" "$oldest_entry"
  else
    printf -- '- oldest known age: none\n'
  fi
  printf -- '- age unknown: %s\n' "$unknown"
  rm -f "$BEFORE" "$BEFORE_CACHE_OK" "$AFTER"
}

case "$1" in
  begin) [ "$#" -eq 1 ] || usage; begin ;;
  finish) [ "$#" -eq 2 ] || usage; finish "$2" ;;
  *) usage ;;
esac
