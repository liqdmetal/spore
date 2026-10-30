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
# git@github.com:owner/repo.git silently pushes over HTTPS and — when the
# gh credential lacks the workflow scope — fails with "refusing to allow
# an OAuth App to create or update workflow". Status 2026-09-18: that
# scope has since been granted (gh auth refresh -s workflow, device flow)
# and a live HTTPS push of workflow-file content was accepted, so HTTPS
# works repo-wide — but it hinges on one OAuth credential staying scoped.
# SSH is immune to both the rewrite rule and credential scopes; prefer the
# explicit ssh:// form, which the rewrite rule does not match:
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
    # `go install github.com/evilmartians/lefthook@latest` — what
    # install-global-hooks.sh itself uses — lands in $HOME/go/bin, which is
    # not on PATH in every shell (git on Windows, cron, IDE git clients).
    # Without these the not-found guard below would abort every commit/push
    # in a gated repo on a machine that is in fact correctly set up.
    elif test -x "$HOME/go/bin/lefthook.exe"
    then
      "$HOME/go/bin/lefthook.exe" "$@"
    elif test -x "$HOME/go/bin/lefthook"
    then
      "$HOME/go/bin/lefthook" "$@"
    else
      echo "Can't find lefthook in PATH"
      echo "ERROR: Operation is aborted due to lefthook settings."
      echo "Make sure lefthook is available in your environment and re-try."
      echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
      exit 1
    fi
  fi
}

call_lefthook run "pre-commit" --no-auto-install "$@"
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
    # `go install github.com/evilmartians/lefthook@latest` — what
    # install-global-hooks.sh itself uses — lands in $HOME/go/bin, which is
    # not on PATH in every shell (git on Windows, cron, IDE git clients).
    # Without these the not-found guard below would abort every commit/push
    # in a gated repo on a machine that is in fact correctly set up.
    elif test -x "$HOME/go/bin/lefthook.exe"
    then
      "$HOME/go/bin/lefthook.exe" "$@"
    elif test -x "$HOME/go/bin/lefthook"
    then
      "$HOME/go/bin/lefthook" "$@"
    else
      echo "Can't find lefthook in PATH"
      echo "ERROR: Operation is aborted due to lefthook settings."
      echo "Make sure lefthook is available in your environment and re-try."
      echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
      exit 1
    fi
  fi
}

call_lefthook run "prepare-commit-msg" --no-auto-install "$@"
HOOK_EOF_9x
chmod +x "$HOOKS/prepare-commit-msg"

# ----- pre-push (verbatim) -----
cat > "$HOOKS/pre-push" <<'HOOK_EOF_9x'
#!/bin/sh
# Global pre-push shim (machine-wide, installed by scripts/install-global-hooks.sh).
#
# Runs the repo's lefthook pre-push commands — for spore that is the full gate
# suite in scripts/gates.sh. Beyond the upstream render it carries two
# fail-closed guards, because lefthook's own "nothing matched, skip" path exits
# 0 and a gate-bypassing push then looks exactly like a passing one:
#
#   1. NO REF LINES. git writes the push's refs to the hook on stdin; if that
#      list is empty the push range is unknown and lefthook has nothing to
#      compute a diff from. Upstream also exits 0 here. We abort — unless the
#      emptiness is provably a no-op push (`git push` on a tree already at its
#      upstream), which is allowed with a note. The proof is that every branch
#      sits exactly on its upstream and the current branch has one: a branch
#      ahead of its upstream is the shape a stdin-eating consumer leaves
#      behind, since git would have written a ref line for it.
#      (Real case, 2026-10-30: a plain `git push` with nothing to send aborted
#      with a bypass warning instead of saying "Everything up-to-date".)
#   2. SKIPPED GATES ON A REAL PUSH. lefthook prints
#        gates (skip) no matching push files
#      and exits 0 when the diff range comes back empty (dropped/consumed refs,
#      an unfetchable remote sha, a path filter that matches nothing). When the
#      push carries new commits — or carries none because every ref already
#      points at what the remote has — that is a bypass, so it aborts. Two
#      skips are legitimate and are allowed with a note: a deletion-only push
#      (nothing arrives), and a message-only rewrite, where every arriving ref
#      REPLACES a commit the remote already has with an identical tree — an
#      amended message, the only way to fix a published one. The old commit is
#      still in the object db, so the two trees are compared rather than
#      assumed: an empty commit added on top is not a rewrite, and a remote
#      sha this clone cannot resolve is treated as a real push. Anything
#      unproven stays a refusal. (Real case, 2026-10-28: a reworded message
#      was refused as a gate bypass because its diff was empty.)
#
# The refs are buffered once and replayed to lefthook, so no downstream
# consumer (git-lfs, a wrapper) can eat them on the way.
#
# lefthook is invoked with --no-auto-install on purpose: its hook-sync step
# re-renders every hook in core.hooksPath, and a re-render REPLACES this file
# with the upstream shim — guards and all. (Real case, 2026-10-26: one push
# from a repo with an unfamiliar lefthook.yml rewrote all three shims and the
# manifest drifted mid-session.) With the flag, our own runs cannot undo
# themselves; scripts/verify-hooks.sh still catches a re-render from anything
# else.
#
# Escape hatches: LEFTHOOK=0 git push ...  |  git push --no-verify
# Battery: spore scripts/test-pre-push-failclosed.sh (also run by
# gen-hooks-backup.sh before it regenerates the installer).

if [ "$LEFTHOOK_VERBOSE" = "1" -o "$LEFTHOOK_VERBOSE" = "true" ]; then
  set -x
fi

if [ "$LEFTHOOK" = "0" ]; then
  exit 0
fi

# repo_uses_lefthook — true when lefthook would load a config for this repo.
# The set is lefthook's own search list (internal/config/loader.go:
# MainConfigNames + LocalConfigNames, x Extensions), plus LEFTHOOK_CONFIG when
# it names an existing file. Repos without a config keep the silent no-op
# contract: nothing to gate, nothing to guard.
repo_uses_lefthook()
{
  dir="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  if test -n "$LEFTHOOK_CONFIG"
  then
    test -f "$LEFTHOOK_CONFIG" && return 0
    test -f "$dir/$LEFTHOOK_CONFIG" && return 0
  fi
  for base in lefthook .lefthook .config/lefthook \
              lefthook-local .lefthook-local .config/lefthook-local
  do
    for ext in .yml .yaml .json .jsonc .toml
    do
      if test -f "$dir/$base$ext"
      then
        return 0
      fi
    done
  done
  return 1
}

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
    # `go install github.com/evilmartians/lefthook@latest` — what
    # install-global-hooks.sh itself uses — lands in $HOME/go/bin, which is
    # not on PATH in every shell (git on Windows, cron, IDE git clients).
    # Without these the not-found guard below would abort every push in a
    # gated repo on a machine that is in fact correctly set up.
    elif test -x "$HOME/go/bin/lefthook.exe"
    then
      "$HOME/go/bin/lefthook.exe" "$@"
    elif test -x "$HOME/go/bin/lefthook"
    then
      "$HOME/go/bin/lefthook" "$@"
    else
      echo "Can't find lefthook in PATH"
      dir="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
      # Self-identify for scripts/test-pre-push-failclosed.sh (retirement
      # plan in gen-hooks-backup.sh): lets the battery tell this hand-patch
      # from a native render. Remove when a passing native render retires it.
      if [ "$LEFTHOOK_CLAUDE_SHIM_ASSERT" = "1" ]; then
        echo "LEFTHOOK_CLAUDE_SHIM_ASSERT: hand-patched fail-closed shim (spore f016bab)"
        exit 1
      fi
      # Fail CLOSED when this repo actually uses lefthook but no binary was
      # found: exiting 0 would silently skip the pre-push gate. Repos that
      # do not use lefthook stay a silent no-op (exit 0).
      # Retirement runbook: gen-hooks-backup.sh header in the spore repo
      # (battery: scripts/test-pre-push-failclosed.sh).
      if repo_uses_lefthook
      then
        echo "ERROR: Operation is aborted due to lefthook settings."
        echo "Make sure lefthook is available in your environment and re-try."
        echo "To skip these checks use --no-verify git argument or set LEFTHOOK=0 env variable."
        exit 1
      fi
    fi
  fi
}

# ---- guard: the push range must be knowable --------------------------------
REFS_FILE="$(mktemp)" || {
  echo "pre-push: cannot create a temp file for the push refs — refusing to run blind." >&2
  exit 1
}
OUT_FILE="$(mktemp)" || {
  rm -f "$REFS_FILE"
  echo "pre-push: cannot create a temp file for the lefthook output — refusing to run blind." >&2
  exit 1
}
trap 'rm -f "$REFS_FILE" "$OUT_FILE"' EXIT
trap 'exit 1' INT TERM

# git hands the hook: <local ref> <local sha> <remote ref> <remote sha>.
# Buffer once; the replay below is the only consumer, so a chained tool
# cannot eat the lines the way git-lfs did before this was buffered.
cat >"$REFS_FILE"

ref_lines=$(grep -c . "$REFS_FILE" 2>/dev/null || true)
[ -n "$ref_lines" ] || ref_lines=0

# A push "arrives" when at least one ref carries commits: local sha present,
# not the all-zero null sha (deletion), and different from the remote side.
# Deletion-only pushes are the one legitimate no-files push.
#
# same_tree_all marks the other one: EVERY arriving ref replaces a commit the
# remote side already has, with the tree that commit already carried. That is
# a message-only rewrite (git commit --amend -m), and the gates have nothing to
# look at — they would diff an empty range. The proof is three-way and any ref
# that fails a leg clears the flag: the remote commit must exist in this clone
# (a reword leaves it in the object db; an unfetched one is unknowable, so it
# keeps its gates), it must NOT be an ancestor of what is being pushed (an
# empty commit stacked on top is a new commit, not a rewrite), and the two
# trees must be identical.
ZERO_SHA=0000000000000000000000000000000000000000
arriving=""
deleting=""
same_tree_all=""
while read -r _lref lsha _rref rsha
do
  [ -n "$lsha" ] || continue
  if [ "$lsha" = "$ZERO_SHA" ]; then
    deleting=1
    continue
  fi
  [ "$lsha" = "$rsha" ] && continue
  arriving=1
  if git cat-file -e "$rsha^{commit}" 2>/dev/null \
     && ! git merge-base --is-ancestor "$rsha" "$lsha" 2>/dev/null \
     && git diff --quiet "$rsha" "$lsha" 2>/dev/null
  then
    same_tree_all=1
  else
    same_tree_all=""
    break
  fi
done <"$REFS_FILE"

refuse_skip()
{
  echo "" >&2
  echo "pre-push: REFUSING TO SKIP THE GATES — $1" >&2
  echo "  lefthook reports a pass in that situation, so a push that ran no gates" >&2
  echo "  would be indistinguishable from one that ran them all. This push is" >&2
  echo "  aborted instead. Nothing was verified." >&2
  echo "  If this push genuinely has nothing to gate, use the documented escape" >&2
  echo "  hatches for this one push:" >&2
  echo "    git push --no-verify ...        (per-invocation)" >&2
  echo "    LEFTHOOK=0 git push ...         (env-scoped)" >&2
  echo "  Otherwise fix the refs or the lefthook config and push again." >&2
  exit 1
}

# Empty stdin means git had zero refs to update — `git push` on a synced tree.
# It is also what a consumer upstream of this file would leave after eating the
# lines, so prove the clone has nothing in flight instead of taking it on
# faith: every branch that tracks an upstream must sit exactly on it, and the
# current branch must have an upstream at all (a detached HEAD or an unpushed
# branch cannot be proven empty). A branch ahead of its upstream is precisely
# the eaten-lines shape — git would have written a ref line for it — so that
# stays a refusal. Without this, a plain `git push` on an up-to-date tree
# aborted with a gate-bypass warning for a push that carried nothing.
if repo_uses_lefthook && [ "$ref_lines" -eq 0 ]; then
  noop_proven=""
  if git symbolic-ref --quiet HEAD >/dev/null 2>&1 \
     && git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' >/dev/null 2>&1
  then
    noop_proven=1
    while read -r _b _u
    do
      [ -n "$_u" ] || continue
      if [ "$(git rev-parse --verify "$_b" 2>/dev/null)" != "$(git rev-parse --verify "$_u" 2>/dev/null)" ]; then
        noop_proven=""
        break
      fi
    done <<NOOP_EOF
$(git for-each-ref --format='%(refname:short) %(upstream:short)' refs/heads 2>/dev/null)
NOOP_EOF
  fi
  if [ -n "$noop_proven" ]; then
    echo "pre-push: note: gates skipped — git reported nothing to push and every" >&2
    echo "  branch sits on its upstream, so no commit is arriving." >&2
    exit 0
  fi
  refuse_skip "stdin carried no ref lines, so the push range is unknown"
fi

call_lefthook run "pre-push" --no-auto-install "$@" <"$REFS_FILE" >"$OUT_FILE" 2>&1
rc=$?
cat "$OUT_FILE" >&2

[ "$rc" -eq 0 ] || exit "$rc"

# lefthook's skip path: the summary shows the command as skipped for "no
# matching push files" and the exit code is still 0. Treat that as a failure
# whenever commits are actually arriving with content the gates have not seen.
if grep -q "no matching push files" "$OUT_FILE"; then
  if [ -n "$arriving" ] && [ -z "$same_tree_all" ]; then
    refuse_skip "lefthook skipped the gates ('no matching push files') for a push that carries new commits"
  fi
  if [ -n "$same_tree_all" ]; then
    echo "pre-push: note: gates skipped — message-only rewrite (every arriving ref" >&2
    echo "  carries a tree the remote already has; no file content to verify)." >&2
  elif [ -z "$deleting" ]; then
    refuse_skip "the push range came back empty — no ref carries a commit the remote does not already have"
  else
    echo "pre-push: note: gates skipped for a deletion-only push (no commits arriving)." >&2
  fi
fi

exit 0
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
