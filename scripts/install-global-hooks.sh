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

# ----- commit-msg (verbatim) -----
cat > "$HOOKS/commit-msg" <<'HOOK_EOF_9x'
#!/usr/bin/env bash
# ------------------------------------------------------------------
# Global commit-msg hook — enforces on EVERY repo:
#   * Conventional Commits 1.0.0  (conventionalcommits.org)
#   * Conventional Branch 1.1.0   (conventionalbranch.org)
# Installed once via:  git config --global core.hooksPath
# Escape hatch:  git commit --no-verify
# ------------------------------------------------------------------

MSG_FILE="$1"
[ -z "$MSG_FILE" ] && exit 0

subject="$(sed -n '1p' "$MSG_FILE")"

# --- Allow git-generated messages that are not developer-authored ---
case "$subject" in
  Merge\ *|Merge:\ *|Revert\ \"*|Revert\ *|Initial\ commit|Apply\ patch\ *) exit 0 ;;
esac

if [ -z "$subject" ]; then
  echo "commit-msg: REJECTED — empty commit subject."
  echo "Expected: <type>(<scope>): <description>   e.g. 'feat(cli): add retry to sync'"
  exit 1
fi

# --- Conventional Commits 1.0.0: <type>[optional scope][!]: <description> ---
if ! printf '%s' "$subject" | grep -Eq '^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9][a-z0-9-]*\))?!?: .+'; then
  echo "commit-msg: REJECTED — not a Conventional Commit (conventionalcommits.org v1.0.0)."
  echo "Expected: <type>(<scope>): <description>   e.g. 'feat(cli): add retry to sync'"
  echo "Got:      $subject"
  echo ""
  echo "Allowed types: feat fix docs chore ci test refactor perf build style revert"
  exit 1
fi

# --- Conventional Branch 1.1.0: <type>/<description> or a trunk branch ---
BRANCH="$(git symbolic-ref --short -q HEAD 2>/dev/null || echo DETACHED)"
case "$BRANCH" in
  DETACHED|main|master|develop) exit 0 ;;
esac
if ! printf '%s' "$BRANCH" | grep -Eq '^(feature|feat|bugfix|fix|hotfix|release|chore|ai|copilot|cursor|claude|codex)/[a-z0-9]+([.-][a-z0-9]+)*$'; then
  echo "commit-msg: REJECTED — branch name does not follow Conventional Branch (conventionalbranch.org v1.1.0)."
  echo "Expected: <type>/<lowercase-hyphen-desc>   e.g. 'feature/add-login-page', 'fix/k0-min-ring4'"
  echo "Got:      $BRANCH"
  echo ""
  echo "Allowed prefixes: feature feat bugfix fix hotfix release chore ai copilot cursor claude codex"
  echo "Trunk branches (no prefix): main master develop"
  exit 1
fi

exit 0
HOOK_EOF_9x
chmod +x "$HOOKS/commit-msg"

# ----- pre-commit (verbatim) -----
cat > "$HOOKS/pre-commit" <<'HOOK_EOF_9x'
#!/bin/sh

if [ "$LEFTHOOK_VERBOSE" = "1" -o "$LEFTHOOK_VERBOSE" = "true" ]; then
  set -x
fi

if [ "$LEFTHOOK" = "0" ]; then
  exit 0
fi

call_lefthook()
{
  if test -n "$LEFTHOOK_BIN"
  then
    "$LEFTHOOK_BIN" "$@"
  elif lefthook.exe -h >/dev/null 2>&1
  then
    lefthook.exe "$@"
  elif lefthook.bat -h >/dev/null 2>&1
  then
    lefthook.bat "$@"
  else
    dir="$(git rev-parse --show-toplevel)"
    osArch=$(uname | tr '[:upper:]' '[:lower:]')
    cpuArch=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x64/')
    if test -f "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe"
    then
      "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/lefthook/bin/index.js"
    then
      "$dir/node_modules/lefthook/bin/index.js" "$@"
    
    elif go tool lefthook -h >/dev/null 2>&1
    then
      go tool lefthook "$@"
    elif bundle exec lefthook -h >/dev/null 2>&1
    then
      bundle exec lefthook "$@"
    elif yarn lefthook -h >/dev/null 2>&1
    then
      yarn lefthook "$@"
    elif pnpm lefthook -h >/dev/null 2>&1
    then
      pnpm lefthook "$@"
    elif swift package lefthook >/dev/null 2>&1
    then
      swift package --build-path .build/lefthook --disable-sandbox lefthook "$@"
    elif command -v mint >/dev/null 2>&1
    then
      mint run csjones/lefthook-plugin "$@"
    elif uv run lefthook -h >/dev/null 2>&1
    then
      uv run lefthook "$@"
    elif mise exec -- lefthook -h >/dev/null 2>&1
    then
      mise exec -- lefthook "$@"
    elif devbox run lefthook -h >/dev/null 2>&1
    then
      devbox run lefthook "$@"
    else
      echo "Can't find lefthook in PATH"
      echo "ERROR: Operation is aborted due to lefthook settings."
      echo "Make sure lefthook is available in your environment and re-try."
      echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
      exit 1
    fi
  fi
}

call_lefthook run "pre-commit" "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/pre-commit"

# ----- prepare-commit-msg (verbatim) -----
cat > "$HOOKS/prepare-commit-msg" <<'HOOK_EOF_9x'
#!/bin/sh

if [ "$LEFTHOOK_VERBOSE" = "1" -o "$LEFTHOOK_VERBOSE" = "true" ]; then
  set -x
fi

if [ "$LEFTHOOK" = "0" ]; then
  exit 0
fi

call_lefthook()
{
  if test -n "$LEFTHOOK_BIN"
  then
    "$LEFTHOOK_BIN" "$@"
  elif lefthook.exe -h >/dev/null 2>&1
  then
    lefthook.exe "$@"
  elif lefthook.bat -h >/dev/null 2>&1
  then
    lefthook.bat "$@"
  else
    dir="$(git rev-parse --show-toplevel)"
    osArch=$(uname | tr '[:upper:]' '[:lower:]')
    cpuArch=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x64/')
    if test -f "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe"
    then
      "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/lefthook/bin/index.js"
    then
      "$dir/node_modules/lefthook/bin/index.js" "$@"
    
    elif go tool lefthook -h >/dev/null 2>&1
    then
      go tool lefthook "$@"
    elif bundle exec lefthook -h >/dev/null 2>&1
    then
      bundle exec lefthook "$@"
    elif yarn lefthook -h >/dev/null 2>&1
    then
      yarn lefthook "$@"
    elif pnpm lefthook -h >/dev/null 2>&1
    then
      pnpm lefthook "$@"
    elif swift package lefthook >/dev/null 2>&1
    then
      swift package --build-path .build/lefthook --disable-sandbox lefthook "$@"
    elif command -v mint >/dev/null 2>&1
    then
      mint run csjones/lefthook-plugin "$@"
    elif uv run lefthook -h >/dev/null 2>&1
    then
      uv run lefthook "$@"
    elif mise exec -- lefthook -h >/dev/null 2>&1
    then
      mise exec -- lefthook "$@"
    elif devbox run lefthook -h >/dev/null 2>&1
    then
      devbox run lefthook "$@"
    else
      echo "Can't find lefthook in PATH"
      echo "ERROR: Operation is aborted due to lefthook settings."
      echo "Make sure lefthook is available in your environment and re-try."
      echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
      exit 1
    fi
  fi
}

call_lefthook run "prepare-commit-msg" "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/prepare-commit-msg"

# ----- pre-push (verbatim) -----
cat > "$HOOKS/pre-push" <<'HOOK_EOF_9x'
#!/bin/sh

if [ "$LEFTHOOK_VERBOSE" = "1" -o "$LEFTHOOK_VERBOSE" = "true" ]; then
  set -x
fi

if [ "$LEFTHOOK" = "0" ]; then
  exit 0
fi

call_lefthook()
{
  if test -n "$LEFTHOOK_BIN"
  then
    "$LEFTHOOK_BIN" "$@"
  elif lefthook.exe -h >/dev/null 2>&1
  then
    lefthook.exe "$@"
  elif lefthook.bat -h >/dev/null 2>&1
  then
    lefthook.bat "$@"
  else
    dir="$(git rev-parse --show-toplevel)"
    osArch=$(uname | tr '[:upper:]' '[:lower:]')
    cpuArch=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x64/')
    if test -f "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe"
    then
      "$dir/node_modules/lefthook-${osArch}-${cpuArch}/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook/bin/lefthook-${osArch}-${cpuArch}/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe"
    then
      "$dir/node_modules/@evilmartians/lefthook-installer/bin/lefthook.exe" "$@"
    elif test -f "$dir/node_modules/lefthook/bin/index.js"
    then
      "$dir/node_modules/lefthook/bin/index.js" "$@"
    
    elif go tool lefthook -h >/dev/null 2>&1
    then
      go tool lefthook "$@"
    elif bundle exec lefthook -h >/dev/null 2>&1
    then
      bundle exec lefthook "$@"
    elif yarn lefthook -h >/dev/null 2>&1
    then
      yarn lefthook "$@"
    elif pnpm lefthook -h >/dev/null 2>&1
    then
      pnpm lefthook "$@"
    elif swift package lefthook >/dev/null 2>&1
    then
      swift package --build-path .build/lefthook --disable-sandbox lefthook "$@"
    elif command -v mint >/dev/null 2>&1
    then
      mint run csjones/lefthook-plugin "$@"
    elif uv run lefthook -h >/dev/null 2>&1
    then
      uv run lefthook "$@"
    elif mise exec -- lefthook -h >/dev/null 2>&1
    then
      mise exec -- lefthook "$@"
    elif devbox run lefthook -h >/dev/null 2>&1
    then
      devbox run lefthook "$@"
    else
      echo "Can't find lefthook in PATH"
      dir="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
      # Fail CLOSED when this repo actually uses lefthook but no binary was
      # found: exiting 0 would silently skip the pre-push gate. Repos that
      # do not use lefthook stay a silent no-op (exit 0).
      if test -f "$dir/lefthook.yml" || test -f "$dir/.lefthook.yml" || \
         test -f "$dir/lefthook.yaml" || test -f "$dir/.config/lefthook.yml"
      then
        echo "ERROR: Operation is aborted due to lefthook settings."
        echo "Make sure lefthook is available in your environment and re-try."
        echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
        exit 1
      fi
    fi
  fi
}

call_lefthook run "pre-push" "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/pre-push"

# ----- pristine LFS-only pre-push (fallback backup) -----
if [ ! -f "$HOME/.config/git/pre-push.lfs.orig" ]; then
  cat > "$HOME/.config/git/pre-push.lfs.orig" <<'HOOK_EOF_9x'
#!/bin/sh
command -v git-lfs >/dev/null 2>&1 || { printf >&2 "\n%s\n\n" "This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'pre-push' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks')."; exit 2; }
git lfs pre-push "$@"
HOOK_EOF_9x
  chmod +x "$HOME/.config/git/pre-push.lfs.orig"
fi

# ----- Git LFS post hooks (git-lfs's own standard shims) -----
cat > "$HOOKS/post-checkout" <<'HOOK_EOF_9x'
#!/bin/sh
command -v git-lfs >/dev/null 2>&1 || { printf >&2 "\n%s\n\n" "This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'post-checkout' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks')."; exit 2; }
git lfs post-checkout "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/post-checkout"
cat > "$HOOKS/post-commit" <<'HOOK_EOF_9x'
#!/bin/sh
command -v git-lfs >/dev/null 2>&1 || { printf >&2 "\n%s\n\n" "This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'post-commit' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks')."; exit 2; }
git lfs post-commit "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/post-commit"
cat > "$HOOKS/post-merge" <<'HOOK_EOF_9x'
#!/bin/sh
command -v git-lfs >/dev/null 2>&1 || { printf >&2 "\n%s\n\n" "This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'post-merge' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks')."; exit 2; }
git lfs post-merge "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/post-merge"

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
