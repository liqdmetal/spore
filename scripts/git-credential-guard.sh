#!/bin/sh
# git-credential-guard.sh — bounded, fail-closed wrapper around Git Credential
# Manager, so a credential-store ambiguity fails a push in seconds instead of
# hanging it with no output.
#
# WHY THIS EXISTS (real case, 2026-10-25): GCM 2.9.1 held TWO accounts for
# github.com — `liqdmetal` and `x-access-token`, both valid `gho_` tokens for
# the same login. `git push` asks its helper for a credential WITHOUT a
# username, so GCM's GitHub provider found multiple accounts and went to
# "Multiple accounts available - prompting user to select one...". In a shell
# with no terminal that prompt is never answered and git waits forever: a
# 120 s timeout, no error, no hint what is stuck. Passing `username=liqdmetal`
# filters to one account, which is why the identical push worked when the
# username was supplied explicitly. The duplicate is gone now, but the failure
# mode returns the moment a second account exists again (another
# `gcm github login`, or a PAT pushed under the `x-access-token` username).
#
# So this helper sits in front of GCM and makes both failure modes loud:
#
#   * more than one account stored for the host, and no username in the query
#     (exactly the query `git push`/`git pull` make) → refuse immediately,
#     naming the accounts and the one command that clears it;
#   * GCM itself stalls for any other reason → killed after
#     GIT_CRED_GUARD_TIMEOUT seconds (default 10) and reported, instead of
#     sitting on a prompt nobody can answer.
#
# A refusal is fail-CLOSED: the helper exits non-zero, git finds no credential
# and aborts the push with an error. It never silently proceeds, and it never
# waits.
#
# Usage:
#   scripts/git-credential-guard.sh --install [--global]
#       Put the guard in front of GCM for this clone (default) or for every
#       repo (--global), then self-check it. The inherited helper list is
#       RESET first: without that, global `manager` is queried before the
#       guard and hangs before the guard is ever reached.
#   scripts/git-credential-guard.sh --uninstall [--global]
#       Drop the guard's helper entries again (plain GCM behavior returns).
#   scripts/git-credential-guard.sh get|store|erase
#       The helper protocol itself; reached via the config --install writes.
#
# Escape hatches, for a one-off when the store really is ambiguous and you
# want the picker back: GIT_CRED_GUARD=0 (passes straight through to GCM) or
# --uninstall. Tuning: GIT_CRED_GUARD_TIMEOUT (seconds, default 10),
# GIT_CRED_GUARD_GCM (helper binary, default git-credential-manager).
#
# Exit codes: 0 credential returned / installed, 1 ambiguity or stall (the
# push aborts), 2 usage or install error.
set -u

SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SELF_DIR="."
SELF="$SELF_DIR/$(basename "$0")"
TIMEOUT=${GIT_CRED_GUARD_TIMEOUT:-10}
GCM=${GIT_CRED_GUARD_GCM:-git-credential-manager}

say() { printf '%s\n' "$*" >&2; }
refuse() { say "git-credential-guard: $*"; exit 1; }

# bounded CMD... — run CMD under a hard wall-clock limit. `timeout` is coreutils
# and present in Git for Windows' sh; if it is missing we still run, because
# losing the guard entirely is worse than losing its kill switch (and the
# ambiguity check below, which is the actual hang, happens before this).
bounded() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "$TIMEOUT" "$@"
  else
    "$@"
  fi
}

usage() {
  sed -n '/^# Usage:/,/^# Exit codes:/p' "$0" | sed '1d;$d' | sed 's/^# \{0,1\}//'
}

# host_of FILE — the host from either the legacy `host=` line or a newer
# `url=` line (git 2.40+ may hand a helper a URL instead of split fields).
host_of() {
  h=$(sed -n 's/^host=//p' "$1" | head -1)
  if [ -z "$h" ]; then
    h=$(sed -n 's/^url=//p' "$1" | head -1 |
        sed -e 's|^[^:/]*://||' -e 's|^[^@/]*@||' -e 's|[:/].*$||')
  fi
  printf '%s' "$h"
}

guard_get() {
  q=$(mktemp) || refuse "cannot create a temp file for the credential query"
  cat >"$q"

  host=$(host_of "$q")
  user=$(sed -n 's/^username=//p' "$q" | head -1)

  if [ -z "$user" ] && [ "$host" = "github.com" ]; then
    accounts=$(bounded "$GCM" github list 2>/dev/null)
    rc=$?
    if [ "$rc" -ne 0 ] || [ -z "$accounts" ]; then
      rm -f "$q"
      refuse "cannot read the credential-store account list (exit $rc) — not handing git a credential that could stall"
    fi
    count=$(printf '%s\n' "$accounts" | grep -c .)
    if [ "$count" -gt 1 ]; then
      rm -f "$q"
      say "git-credential-guard: REFUSING to query GCM — $count GitHub accounts are stored and the request carries no username."
      say "  This is the exact query 'git push' makes. GCM answers it with an interactive account picker;"
      say "  with no terminal that prompt never resolves, so the push hangs instead of failing."
      say "  Accounts: $(printf '%s' "$accounts" | tr '\n' ' ')"
      say "  Fix:  git-credential-manager github list"
      say "        git-credential-manager github logout <account-to-drop>   # keep ONE"
      say "  Or bypass once:  GIT_CRED_GUARD=0 git push ..."
      exit 1
    fi
  fi

  bounded "$GCM" get <"$q"
  rc=$?
  rm -f "$q"
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    refuse "GCM did not answer within ${TIMEOUT}s (killed) — aborting the push instead of waiting on it"
  fi
  return "$rc"
}

install_guard() {
  scope=$1
  if [ "$scope" = "--global" ]; then set_scope=--global; where="every repo"; else set_scope=--local; where="this clone"; fi

  git config "$set_scope" --replace-all credential.helper "" || exit 2
  git config "$set_scope" --add credential.helper "!\"$SELF\"" || exit 2

  echo "guard installed for $where ($set_scope):"
  git config "$set_scope" --get-all credential.helper | sed 's/^/  credential.helper = /'

  echo
  echo "self-check (bounded to $((TIMEOUT + 5))s):"
  out=$(printf 'protocol=https\nhost=github.com\n\n' | timeout $((TIMEOUT + 5)) "$SELF" get)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAILED (exit $rc) — the guard would refuse pushes right now; see the message above." >&2
    exit 1
  fi
  got_user=$(printf '%s\n' "$out" | sed -n 's/^username=//p' | head -1)
  if printf '%s\n' "$out" | grep -q '^password='; then
    echo "  ok: credential returned for '$got_user' without a prompt"
  else
    echo "  FAILED: no password in the helper output" >&2
    exit 1
  fi
}

uninstall_guard() {
  scope=$1
  if [ "$scope" = "--global" ]; then set_scope=--global; else set_scope=--local; fi
  git config "$set_scope" --unset-all credential.helper 2>/dev/null || true
  echo "guard removed ($set_scope); credential.helper entries now:"
  git config "$set_scope" --get-all credential.helper | sed 's/^/  /' || echo "  (none — inherited helpers apply again)"
}

op=${1:-}
case "$op" in
  --install)   install_guard "${2:-}" ;;
  --uninstall) uninstall_guard "${2:-}" ;;
  -h|--help)   usage; exit 0 ;;
  get)
    if [ "${GIT_CRED_GUARD:-1}" = "0" ]; then exec "$GCM" get; fi
    guard_get
    ;;
  store|erase)
    if [ "${GIT_CRED_GUARD:-1}" = "0" ]; then exec "$GCM" "$op"; fi
    exec "$GCM" "$op"
    ;;
  ""|--*) usage >&2; exit 2 ;;
  *) exec "$GCM" "$@" ;;
esac
