#!/bin/sh
# gen-hooks-backup.sh — regenerate the global-hooks backup pair from the LIVE
# hooks on this (trusted) machine:
#
#   scripts/install-global-hooks.sh   the installer (hook bodies embedded,
#                                     self-verifies after installing)
#   scripts/hooks-manifest.sha256     sha256sum-format checksum manifest
#
# Run this after changing any hook under ~/.config/git/hooks, then commit the
# regenerated pair. Never hand-edit either generated file — the pair is only
# trustworthy because it is generated in one pass from the same source.
#
# KNOWN POLLUTION PATTERN (real case, 2026-09-17): the hooks dir is
# machine-global — one core.hooksPath serves every repo — and any
# lefthook-using repo on this machine re-renders ITS full hook set into it
# on the next commit, including repos that are not spore. A disposable
# clone of upstream lefthook (PR scratch work in /tmp) defined a `lint:`
# hook; committing there emitted a `lint` shim into ~/.config/git/hooks
# that no git version ever invokes, and re-rendered pre-commit and
# prepare-commit-msg (surfacing as manifest drift). Catch: verify-hooks.sh
# warnings. Cleanup: delete the stray file and the scratch clone, then
# re-run this script if real hooks were also re-rendered.
set -eu

command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum not found" >&2; exit 2; }

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "run this from inside the spore repository" >&2
  exit 2
}
HOOKS="$HOME/.config/git/hooks"

for h in commit-msg pre-commit prepare-commit-msg pre-push post-checkout post-commit post-merge; do
  [ -f "$HOOKS/$h" ] || { echo "missing live hook: $HOOKS/$h" >&2; exit 2; }
done
[ -f "$HOME/.config/git/pre-push.lfs.orig" ] || {
  echo "missing fallback: $HOME/.config/git/pre-push.lfs.orig" >&2
  exit 2
}

# ---- installer (hook bodies embedded verbatim) -----------------------------
{
  cat <<'HDR'
#!/bin/sh
# install-global-hooks.sh — recreate the global git hooks setup on a new machine.
#
# Installs, idempotently:
#   * core.hooksPath -> ~/.config/git/hooks
#   * lefthook binary (via `go install`) if not already on PATH
#   * commit-msg          — global Conventional Commits 1.0.0 + Conventional
#                           Branch 1.1.0 enforcer (applies to EVERY repo)
#   * pre-commit, prepare-commit-msg — lefthook shims (no-op unless a repo
#                           has a lefthook.yml)
#   * pre-push            — CHAINED hook: Git LFS first, then lefthook. It
#                           buffers stdin once and feeds both consumers;
#                           without that, LFS eats the ref lines and lefthook
#                           skips every command ("no matching push files").
#   * post-checkout/post-commit/post-merge — Git LFS hooks
#   * pre-push.lfs.orig   — the pristine LFS-only pre-push, kept as the
#                           documented fallback if you ever un-chain.
#
# Repos opt IN to pre-push gates by committing a lefthook.yml (see spore's
# scripts/gates.sh wiring and spore-peer's cargo gates). Escape hatches:
#   LEFTHOOK=0 git push ...   |   git push --no-verify   |   git commit --no-verify
#
# After installing, the script self-verifies against
# scripts/hooks-manifest.sha256 when it sits next to this installer, so a
# bad or tampered install is caught immediately. Drift on any machine can
# be checked anytime with scripts/verify-hooks.sh.
#
# This file is GENERATED from the live hooks on the source machine — do not
# hand-edit the embedded bodies; regenerate with scripts/gen-hooks-backup.sh.
set -eu

HOOKS="$HOME/.config/git/hooks"
mkdir -p "$HOOKS"

if ! command -v lefthook >/dev/null 2>&1; then
  echo "installing lefthook via go install ..."
  go install github.com/evilmartians/lefthook@latest
fi

git config --global core.hooksPath "$HOOKS"
echo "core.hooksPath -> $HOOKS"
HDR

  for h in commit-msg pre-commit prepare-commit-msg pre-push; do
    echo
    echo "# ----- $h (verbatim) -----"
    echo "cat > \"\$HOOKS/$h\" <<'HOOK_EOF_9x'"
    cat "$HOOKS/$h"
    echo "HOOK_EOF_9x"
    echo "chmod +x \"\$HOOKS/$h\""
  done

  # Git LFS post hooks — emitted verbatim via a temp file so the generator
  # never has to nest a second heredoc inside these heredocs.
  tmp="$(mktemp)"
  {
    echo
    echo "# ----- Git LFS post hooks (git-lfs's own standard shims) -----"
    for h in post-checkout post-commit post-merge; do
      echo "cat > \"\$HOOKS/$h\" <<'HOOK_EOF_9x'"
      cat "$HOOKS/$h"
      echo "HOOK_EOF_9x"
      echo "chmod +x \"\$HOOKS/$h\""
    done
  } > "$tmp"

  cat <<'FTR'

# ----- pristine LFS-only pre-push (fallback backup) -----
if [ ! -f "$HOME/.config/git/pre-push.lfs.orig" ]; then
  cat > "$HOME/.config/git/pre-push.lfs.orig" <<'HOOK_EOF_9x'
FTR
  cat "$HOME/.config/git/pre-push.lfs.orig"
  cat <<'FTR2'
HOOK_EOF_9x
  chmod +x "$HOME/.config/git/pre-push.lfs.orig"
fi
FTR2

  cat "$tmp"
  rm -f "$tmp"

  cat <<'FTR5'

# ----- self-check against the committed manifest -----
SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/hooks-manifest.sha256" ]; then
  echo
  echo "verifying installed hooks against the committed manifest ..."
  if (cd "$HOOKS" && sha256sum -c "$SELF_DIR/hooks-manifest.sha256"); then
    echo "self-check: all hooks verified."
  else
    echo "self-check: DRIFT detected — do not trust this install; investigate." >&2
    exit 1
  fi
else
  echo
  echo "note: hooks-manifest.sha256 not found next to the installer — self-check skipped."
fi

echo
echo "installed:"
ls -la "$HOOKS"
echo
echo "done. repos with a committed lefthook.yml now run their gates on push;"
echo "everything else behaves exactly as before (LFS + commit-msg checks only)."
FTR5
} > "$ROOT/scripts/install-global-hooks.sh"
chmod +x "$ROOT/scripts/install-global-hooks.sh"

# ---- checksum manifest (bare filenames, checked from inside the hooks dir).
# Normalized to text mode (no leading `*` marker): sha256sum's binary marker
# is platform-dependent, and the manifest must verify identically everywhere.
(
  cd "$HOOKS" &&
    { sha256sum commit-msg pre-commit prepare-commit-msg pre-push \
                post-checkout post-commit post-merge \
        | sed 's/ \*\{0,1\}[[:space:]]\{0,1\}\([^[:space:]]*\)$/ \1/'; } \
      > "$ROOT/scripts/hooks-manifest.sha256"
)

echo "regenerated:"
echo "  scripts/install-global-hooks.sh"
echo "  scripts/hooks-manifest.sha256"
echo
echo "commit the pair together, then run scripts/verify-hooks.sh on any"
echo "machine to detect drift."
