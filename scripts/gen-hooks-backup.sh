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
#
# RETIREMENT PLAN for the pre-push hand-patch (2026-09-18) -------------------
# The not-found guard in ~/.config/git/hooks/pre-push is a hand-patch for
# lefthook 1.13.6's fail-open shim; upstream PR evilmartians/lefthook#1549
# (open as of this writing) renders the guard natively. The patch must
# retire — not fight — the native render:
#
#   TRIGGER (both must hold):
#     a. PR #1549 is merged AND the installed lefthook version includes the
#        fix (currently 1.13.6 locally, which predates it).
#     b. A lefthook pass re-rendered the shim (manifest drift on pre-push)
#        and the NEW shim passes scripts/test-pre-push-failclosed.sh.
#   Until both hold, pre-push drift means a REGRESSION, not progress:
#   restore the embedded body from install-global-hooks.sh, never regenerate.
#
#   STEPS (in order):
#     1. Confirm trigger (a); after the next re-render, run
#        sh scripts/test-pre-push-failclosed.sh against the new shim.
#        All behavioral scenarios must pass. The battery's
#        LEFTHOOK_CLAUDE_SHIM_ASSERT self-check going quiet ("assertion not
#        claimed") is EXPECTED here — it is the hand-patch being gone.
#     2. Re-run this script (it refuses to regenerate from a shim that
#        fails the battery, below) and commit the pair together.
#     3. Set RETIREMENT_DONE=1 in scripts/test-pre-push-failclosed.sh so
#        the battery stops expecting the self-assertion, and commit that
#        in the same change.
#   ROLLBACK: restore the guarded body from install-global-hooks.sh's
#   "pre-push (verbatim)" section, re-run the battery, regenerate.
#   NEVER hand-edit a native render to keep the patch alive — that restarts
#   the patch/fight cycle this plan exists to end.
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

# ---- fail-closed guard: refuse to embed a regression -----------------------
# The pre-push shim's not-found branch MUST fail closed. A lefthook pass
# from a pre-#1549 version re-renders the fail-open original; regenerating
# from that would embed the regression into the installer and bless it in
# the manifest. The battery doubles as this script's precondition and as
# the retirement plan's verification gate (see header above).
if ! sh "$ROOT/scripts/test-pre-push-failclosed.sh" "$HOOKS/pre-push" >/dev/null 2>&1; then
  echo "REFUSING to regenerate: the live pre-push fails the fail-closed battery." >&2
  echo "A lefthook pass probably re-rendered the fail-open shim (pre-#1549" >&2
  echo "render), or the guard was otherwise lost. Restore the guarded body from" >&2
  echo "install-global-hooks.sh (pre-push verbatim section), re-run" >&2
  echo "scripts/test-pre-push-failclosed.sh, then regenerate." >&2
  exit 1
fi

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
# MACHINE SETUP NOTE — remote URLs vs the global insteadOf rule: git config
# on this machine rewrites scp-style SSH remotes back to HTTPS
# (url.https://github.com/.insteadof git@github.com:), so a remote set as
# git@github.com:owner/repo.git silently pushes over HTTPS and can fail
# with "refusing to allow an OAuth App to create or update workflow" when
# the gh credential lacks the workflow scope. Use the explicit ssh:// form,
# which the rewrite rule does not match:
#   git remote set-url origin ssh://git@github.com/owner/repo.git
# Pass --push too if a separate pushurl was already set (plain set-url
# then only changes fetch). Real case: liqdmetal/spore, 2026-09-18.
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
