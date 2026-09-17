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
# additions, but they run on every commit/push and deserve a look.
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
if ls "$HOOKS" >/dev/null 2>&1; then
  for f in "$HOOKS"/*; do
    [ -f "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in *.sample) continue ;; esac
    if ! grep -q " $b\$" "$MANIFEST"; then
      echo "WARNING: unmanaged executable-style file in hooks dir: $b"
    fi
  done
fi

if [ "$status" -eq 0 ]; then
  echo "no drift."
else
  echo "DRIFT DETECTED — compare against scripts/hooks-manifest.sha256" >&2
fi
exit "$status"
