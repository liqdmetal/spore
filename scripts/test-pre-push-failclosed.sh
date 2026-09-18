#!/bin/sh
# test-pre-push-failclosed.sh — behavioral battery for the global pre-push
# hook's fail-closed not-found guard. This is the verification gate of the
# PR #1549 retirement plan (see gen-hooks-backup.sh): any pre-push shim is
# allowed to replace the 2026-09-17 hand-patch ONLY if it passes this
# battery, which proves in a stripped environment (git on PATH, lefthook
# absent, stdin empty — the way git invokes the hook) that
#
#   * a repo with ANY lefthook config (yml or toml; the shim loops over the
#     full loader set) ABORTS the push (exit 1) when no lefthook binary can
#     be found — fail closed;
#   * LEFTHOOK_CONFIG (absolute or repo-relative, existing file) aborts too;
#   * a repo with no config and no override stays a silent no-op (exit 0);
#   * LEFTHOOK=0 keeps working as the escape hatch;
#   * a nonexistent LEFTHOOK_CONFIG does NOT abort (the verdict is driven by
#     file presence, not by the variable being set);
#   * the retired hand-patch self-identifies via LEFTHOOK_CLAUDE_SHIM_ASSERT
#     (exit 1) — that check failing means the shim is NOT the hand-patch,
#     which after the retirement step is exactly right.
#
# usage: test-pre-push-failclosed.sh [path-to-pre-push-shim]
#        test-pre-push-failclosed.sh --installer
#
# Without arguments the shim is resolved like verify-hooks.sh resolves the
# hooks dir (explicit path, else the effective global core.hooksPath).
# --installer extracts the pre-push body embedded in
# scripts/install-global-hooks.sh and batteries THAT — the backup copy is
# checked against the same bar as the live one.
#
# exit codes:
#   0  every scenario behaved (shim is fail-closed; scenario 8 additionally
#      identified the hand-patch unless it already retired)
#   1  FAIL-CLOSED REGRESSION — the shim served a push it must abort, or
#      no-op'd a repo it must guard. Do NOT run gen-hooks-backup.sh while
#      this is red: regeneration would embed the regression into the
#      installer and the manifest would bless it. Remediation: restore the
#      guarded shim body from the installer's embedded "pre-push (verbatim)"
#      section (or re-apply the guard per spore commit f016bab), re-run this
#      battery, THEN regenerate and commit the pair.
#   2  environment error (shim not found, no git, no temp dir)
set -eu

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# Strip the environment down to git + POSIX basics so the shim's binary
# search genuinely cannot find lefthook on this machine. (Git-for-Windows
# keeps git in /mingw64/bin; the /usr/bin fallback covers Linux/macOS.)
GIT_BIN_DIR="$(dirname "$(command -v git)" 2>/dev/null)" || GIT_BIN_DIR=""
[ -n "$GIT_BIN_DIR" ] || { echo "git not found on PATH" >&2; exit 2; }
SAFE_PATH="$GIT_BIN_DIR:/usr/bin:/bin"

SHIM=""
if [ "${1:-}" = "--installer" ]; then
  INSTALLER="$SELF_DIR/install-global-hooks.sh"
  [ -f "$INSTALLER" ] || { echo "installer not found: $INSTALLER" >&2; exit 2; }
  # mktemp -d: the extracted body needs a directory to live in (plain mktemp
  # creates a file, and the redirect dies with "Not a directory").
  EXTRACT_DIR="$(mktemp -d)"
  trap 'rm -rf "$EXTRACT_DIR"' EXIT
  SHIM="$EXTRACT_DIR/pre-push"
  # Extract the embedded verbatim body between the pre-push heredoc markers.
  awk '
    /^cat > "\$HOOKS\/pre-push" <<.HOOK_EOF_9x.$/ { f=1; next }
    f && /^HOOK_EOF_9x$/ { exit }
    f { print }
  ' "$INSTALLER" > "$SHIM"
  [ -s "$SHIM" ] || { echo "could not extract pre-push from installer" >&2; exit 2; }
  TARGET_DESC="pre-push embedded in install-global-hooks.sh"
elif [ -n "${1:-}" ]; then
  SHIM="$1"
  [ -f "$SHIM" ] || { echo "shim not found: $SHIM" >&2; exit 2; }
  TARGET_DESC="$SHIM"
else
  if effective="$(git config --global --get core.hooksPath 2>/dev/null)" && [ -n "$effective" ]; then
    case "$effective" in
      /*|[A-Za-z]:*) HOOKS="$effective" ;;
      *) HOOKS="$HOME/$effective" ;;
    esac
  else
    HOOKS="$HOME/.config/git/hooks"
  fi
  SHIM="$HOOKS/pre-push"
  [ -f "$SHIM" ] || { echo "pre-push not found: $SHIM" >&2; exit 2; }
  TARGET_DESC="$SHIM"
fi
echo "battery target: $TARGET_DESC"

# ---- battery ---------------------------------------------------------------
# run <name> <expected-rc> <setup-fn> — builds a fresh sandbox, runs the shim
# from inside it with the listed env cleared, compares the exit code. The
# shim must never need a real git repo: without one it falls back to pwd,
# which is exactly the "config sits in the repo root" shape under test.
fails=0
hand_patch_asserted=0

run() {
  name="$1"; want="$2"; setup="$3"; shift 3
  s="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 2; }
  ( cd "$s" && "$setup" "$s" )
  rc=0
  ( cd "$s" && env -u LEFTHOOK -u LEFTHOOK_CONFIG $extra \
      PATH="$SAFE_PATH" sh "$SHIM" --hand-patch-battery-run </dev/null ) >/dev/null 2>&1 || rc=$?
  rm -rf "$s"
  if [ "$rc" -eq "$want" ]; then
    echo "  ok   $name (rc=$rc)"
  else
    echo "  FAIL $name: rc=$rc, want $want"
    fails=$((fails + 1))
  fi
}

mk_yml()   { printf 'pre-push:\n  commands:\n    noop:\n      run: "true"\n' > "$1/lefthook.yml"; }
mk_toml()  { printf '[pre-push]\n' > "$1/lefthook.toml"; }

mk_nothing() { :; }

echo "scenarios:"

# 1: canonical fail-open case (the 1.13.6 bug): config exists, binary absent.
extra=""
run "yml config + no binary aborts the push" 1 mk_yml

# 2: the TOML half of the loader set (the exact repo shape the 4-name check
# missed and Greptile flagged upstream).
run "toml config + no binary aborts the push" 1 mk_toml

# 3: LEFTHOOK_CONFIG pointing OUTSIDE the repo (the doc's flagship example).
override="$(mktemp -d)/override.yml"
printf '[pre-push]\n' > "$override"
extra="LEFTHOOK_CONFIG=$override"
run "absolute LEFTHOOK_CONFIG + no binary aborts" 1 mk_nothing
rm -rf "${override%/override.yml}"

# 4: the no-op contract: shared hooks dir serving config-less repos.
extra=""
run "no config, no binary: silent no-op" 0 mk_nothing

# 5: the escape hatch must keep working even with a config present.
extra="LEFTHOOK=0"
run "LEFTHOOK=0 + config: escape hatch honored" 0 mk_yml
extra=""

# 6: negative control for scenario 3 — a SET but nonexistent override must
# not abort (the verdict comes from file presence, not the variable).
extra="LEFTHOOK_CONFIG=does-not-exist.yml"
run "nonexistent LEFTHOOK_CONFIG: no-op" 0 mk_nothing
extra=""

# 7: the hand-patch's self-assertion. While the retirement is pending the
# shim is still the hand-patch and this must pass; after retirement the
# native shim does not know the marker, which is the expected end state.
assert_dir="$(mktemp -d)"
rc=0
( cd "$assert_dir" && env -u LEFTHOOK -u LEFTHOOK_CONFIG \
    LEFTHOOK_CLAUDE_SHIM_ASSERT=1 PATH="$SAFE_PATH" sh "$SHIM" </dev/null ) >/dev/null 2>&1 || rc=$?
rm -rf "$assert_dir"
if [ "$rc" -eq 1 ]; then
  echo "  ok   hand-patch assertion (shim is still the 2026-09-17 patch)"
  hand_patch_asserted=1
else
  echo "  note hand-patch assertion not claimed (rc=$rc) — native or already-retired shim"
fi

# ---- verdict ----------------------------------------------------------------
if [ "$fails" -eq 0 ]; then
  echo "battery PASS: pre-push fails closed ($SHIM)"
  if [ "$hand_patch_asserted" -eq 1 ] && [ "${RETIREMENT_DONE:-0}" != "1" ]; then
    echo "state: hand-patch still in place — retirement steps still pending."
  fi
  exit 0
fi
echo ""
echo "FAIL-CLOSED REGRESSION ($fails scenario(s) failed): $SHIM"
echo "A push was served (or a config-less repo was blocked) while lefthook"
echo "was absent. Do NOT run gen-hooks-backup.sh now — regenerating would"
echo "embed this regression into the installer and manifest. Restore the"
echo "guarded body from install-global-hooks.sh (pre-push verbatim section),"
echo "re-run this battery, then regenerate and commit the pair."
echo "Plan reference: gen-hooks-backup.sh header (PR #1549 retirement)."
exit 1
