#!/bin/sh
# verify-hooks.sh — detect drift between the committed hook checksum manifest
# (scripts/hooks-manifest.sha256) and the hooks actually installed on this
# machine. Run it after installing, after touching anything hook-adjacent, or
# whenever global hook behavior looks off.
#
#   usage: verify-hooks.sh [hooks-dir]
#
# The hooks dir defaults to the machine's EFFECTIVE core.hooksPath from git
# config — the directory git actually executes hooks from — so the check is
# against reality, not an assumption. Exit codes:
#   0  every manifest hook present and unmodified
#   1  drift: missing or modified hook, or manifest/checksum failure
#   2  environment error (no manifest, no hooks dir, no sha256sum)
#
# Extra executables in the hooks dir that the manifest does not know about
# are printed as a warning, not a failure: they may be legitimate local
# additions, but they run on every commit/push and deserve a look. One
# special case gets a second warning: a shim for a name git never invokes
# (real case: a scratch clone of a lefthook-using repo re-rendered its
# `lint` hook into this dir — see gen-hooks-backup.sh). Git never runs
# such a file; it is pure pollution and safe to delete.
set -eu

command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum not found" >&2; exit 2; }

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="$SELF_DIR/hooks-manifest.sha256"
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }

if [ -n "${1:-}" ]; then
  HOOKS="$1"
elif effective="$(git config --global --get core.hooksPath 2>/dev/null)" && [ -n "$effective" ]; then
  # Absolute paths are used as-is; a relative core.hooksPath is resolved
  # against $HOME (matching git's behavior for a global config).
  case "$effective" in
    /*|[A-Za-z]:*) HOOKS="$effective" ;;
    *) HOOKS="$HOME/$effective" ;;
  esac
else
  HOOKS="$HOME/.config/git/hooks"
fi

[ -d "$HOOKS" ] || { echo "hooks dir does not exist: $HOOKS" >&2; exit 2; }
echo "verifying: $HOOKS"

# Every file the manifest names must exist, then every checksum must match.
status=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if [ ! -f "$HOOKS/$f" ]; then
    echo "MISSING: $f"
    status=1
  fi
done < <(awk '{print $2}' "$MANIFEST")

if (cd "$HOOKS" && sha256sum -c "$MANIFEST"); then
  n=$(grep -c . "$MANIFEST" || true)
  echo "OK: $n/$(grep -c . "$MANIFEST" || true) hooks match the manifest"
else
  status=1
fi

# Files present but unknown to the manifest (excluding git's samples).
#
# Known git hook names, for the never-invoked check below. Baseline is
# the hooks documented in githooks(5) (git 2.x — git ships no *.sample
# for several of these, e.g. post-checkout); *.sample files from this
# repo's .git/hooks are unioned in so hooks added by newer git versions
# need no edit here. If neither source is available the check is skipped
# silently — a missing warning beats a false one.
KNOWN_HOOKS=" "
for h in applypatch-msg pre-applypatch post-applypatch pre-rebase \
         post-rewrite post-checkout post-merge pre-merge-commit pre-push \
         pre-receive update proc-receive post-receive post-update \
         reference-transaction push-to-checkout pre-auto-gc \
         prepare-commit-msg commit-msg post-commit fsmonitor-watchman \
         sendemail-validate p4-changelist p4-prepare-changelist \
         p4-post-changelist p4-pre-submit post-index-change
do
  KNOWN_HOOKS="$KNOWN_HOOKS$h "
done
if sample_dir="$(git rev-parse --git-path hooks 2>/dev/null)"; then
  for s in "$sample_dir"/*.sample; do
    [ -f "$s" ] || continue
    KNOWN_HOOKS="$KNOWN_HOOKS$(basename "$s" .sample) "
  done
fi

if ls "$HOOKS" >/dev/null 2>&1; then
  for f in "$HOOKS"/*; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in *.sample) continue ;; esac
    if ! grep -q " $b\$" "$MANIFEST"; then
      echo "WARNING: unmanaged executable-style file in hooks dir: $b"
      case "$KNOWN_HOOKS" in
        *" $b "*|' ') ;;
        *)
          echo "WARNING: $b is not a git hook name — git never invokes it."
          echo "  Likely cross-repo lefthook pollution; see gen-hooks-backup.sh."
          echo "  Safe to delete."
          ;;
      esac
    fi
  done
fi

if [ "$status" -eq 0 ]; then
  echo "no drift."
else
  echo "DRIFT DETECTED — compare against scripts/hooks-manifest.sha256" >&2
fi
exit "$status"
