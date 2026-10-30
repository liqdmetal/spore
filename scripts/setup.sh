#!/bin/sh
# setup.sh — one command to arm this clone so a push cannot skip its gates.
#
# A fresh clone is unprotected by default, and nothing in .git/config is
# versioned:
#
#   * core.hooksPath is unset, so git uses .git/hooks, which holds only
#     *.sample files — no pre-push hook runs, and the lefthook gates in
#     scripts/gates.sh never execute.
#   * credential.helper inherits a bare `manager`, so a credential-store
#     ambiguity hangs the push on an account picker no terminal can answer.
#
# Both are one-command fixes that nobody runs because nothing asks them to.
# This script runs both, verifies both, and exits non-zero naming the exact
# command to run when one is still wrong. It also reports a credential store
# holding two GitHub accounts: the guard can only refuse a push then, so the
# duplicate is caught here, at arm-time, rather than at push-time.
#
#   scripts/setup.sh          install anything missing, then verify
#   scripts/setup.sh --check  verify only — changes nothing, safe in CI
#
# Idempotent: re-running on a set-up machine reports and changes nothing.
# Escape hatches are unchanged (LEFTHOOK=0 git push, git push --no-verify,
# GIT_CRED_GUARD=0) — this arms the guards, it does not remove them.
set -eu

SELF_DIR=$(cd "$(dirname "$0")" && pwd) || exit 2
cd "$SELF_DIR/.."

MODE=install
case "${1:-}" in
  ""|--install) ;;
  --check) MODE=check ;;
  -h|--help)
    # Print the header block only: strip the shebang, drop the leading "# "
    # from each comment, and stop at the first line of code — so growing the
    # header can never spill the script body into --help.
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$SELF_DIR/setup.sh"
    exit 0
    ;;
  *)
    echo "setup: unknown argument: $1 (try --check or --help)" >&2
    exit 2
    ;;
esac

fail=0
say() { printf '%s\n' "$*"; }
warn() { printf 'setup: %s\n' "$*" >&2; fail=1; }

# ---- 1. git hooks ----------------------------------------------------------
# hooks_path_is_ours — the effective core.hooksPath resolves somewhere with a
# committed manifest inside it, i.e. this machine already runs the backed-up
# hook set. Reading the configured value alone is not enough: a dangling path
# looks configured while git silently runs no hooks at all.
hooks_armed() {
  p="$(git config --get core.hooksPath 2>/dev/null || true)"
  [ -n "$p" ] || return 1
  case "$p" in
    /*|[A-Za-z]:*) ;;
    *) p="$HOME/$p" ;;
  esac
  [ -d "$p" ] && [ -f "$p/pre-push" ] && [ -x "$p/pre-push" ]
}

if [ "$MODE" = install ]; then
  say "== hooks =="
  # Sets core.hooksPath, installs lefthook via `go install` when absent, writes
  # every shim, and self-checks against scripts/hooks-manifest.sha256.
  sh "$SELF_DIR/install-global-hooks.sh" || { warn "hook install failed"; exit 1; }
else
  say "== hooks =="
  if hooks_armed; then
    say "hooks: armed ($(git config --get core.hooksPath))"
  else
    warn "hooks NOT armed — no pre-push hook will run here, so a push goes ungated.
  fix: scripts/setup.sh   (or scripts/install-global-hooks.sh)"
  fi
fi

# Drift check: the manifest is versioned, the installed shims are not, so a
# re-render or a hand edit is invisible without it. Only meaningful once hooks
# are armed — comparing against an absent install would report "DRIFT" for the
# one thing that is not drift (nothing installed yet, already reported above).
if hooks_armed && [ -f "$SELF_DIR/hooks-manifest.sha256" ]; then
  if sh "$SELF_DIR/verify-hooks.sh" >/dev/null 2>&1; then
    say "hooks: match scripts/hooks-manifest.sha256"
  else
    warn "hooks DRIFT from the committed manifest — inspect with:
  scripts/verify-hooks.sh"
  fi
fi

# ---- 2. credential guard ---------------------------------------------------
say ""
say "== credential guard =="
guard_armed() {
  helper="$({ git config --get-all credential.helper 2>/dev/null || true; } | grep -F 'git-credential-guard.sh' | tail -1 || true)"
  [ -n "$helper" ] || return 1
  path="${helper#!}"
  path="${path%\"}"
  path="${path#\"}"
  [ -f "$path" ] && [ -x "$path" ]
}

if [ "$MODE" = install ]; then
  sh "$SELF_DIR/git-credential-guard.sh" --install || { warn "credential guard install failed"; exit 1; }
elif guard_armed; then
  say "credential guard: armed"
else
  warn "credential guard NOT armed — a credential-store ambiguity will hang this
  clone's pushes instead of failing them.
  fix: scripts/git-credential-guard.sh --install"
fi

# ---- 2b. credential store: one account per host ----------------------------
# Arming the guard does not make the store unambiguous. GCM keys its store by
# username, not identity, so a second entry — often the same token stored under
# a different name — makes every username-less query (every `git push`) raise
# an account picker, which the guard then refuses. Reporting it here means the
# duplicate is found while arming a clone instead of on a push. GCM is optional
# on a given machine (CI has none), so an absent, silent or unreadable store is
# skipped rather than failed; a bounded call keeps a slow keychain from hanging
# setup the way it used to hang pushes.
if command -v git-credential-manager >/dev/null 2>&1; then
  if command -v timeout >/dev/null 2>&1; then
    gh_accounts="$(timeout 10 git-credential-manager github list 2>/dev/null || true)"
  else
    gh_accounts="$(git-credential-manager github list 2>/dev/null || true)"
  fi
  gh_count=$(printf '%s\n' "$gh_accounts" | grep -c . || true)
  [ -n "$gh_count" ] || gh_count=0
  if [ "$gh_count" -gt 1 ]; then
    warn "credential store holds $gh_count GitHub accounts: $(printf '%s' "$gh_accounts" | tr '\n' ' ' || true)
  Every username-less push asks for a credential with no username, GCM answers
  with an account picker no terminal can answer, and the guard above refuses.
  Two names are usually one identity — drop the duplicate and keep the one you
  authenticate as. See README 'Keep exactly one account per host'.
  fix: git-credential-manager github logout <account-to-drop>"
  elif [ "$gh_count" -eq 1 ]; then
    say "credential store: 1 GitHub account ($gh_accounts)"
  fi
fi

# ---- 3. verdict ------------------------------------------------------------
say ""
if [ "$fail" -ne 0 ]; then
  echo "setup: NOT ready — fix the items above, then re-run scripts/setup.sh" >&2
  exit 1
fi

if [ "$MODE" = check ]; then
  say "ready: hooks and credential guard are armed."
else
  say "ready. pushes from this clone now run the full gate suite"
  say "(scripts/gates.sh) and cannot silently skip it; a broken gate blocks the push."
fi
say ""
say "  scripts/gates.sh --quick   fast inner loop"
say "  scripts/gates.sh           the full suite, exactly what a push runs"
