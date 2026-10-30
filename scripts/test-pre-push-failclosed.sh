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
# Empty-range guards (added after a gate-bypassing push on 2026-10-26):
#   * a GATED repo whose stdin carries no ref lines ABORTS — the push range is
#     unknown, and upstream lefthook exits 0 there without running anything;
#   * a gated repo where lefthook reports "no matching push files" while
#     commits are arriving ABORTS — the skip can never read as a pass again;
#   * the same skip on a deletion-only push (all-zero local sha) is allowed —
#     nothing arrives, so there is nothing to gate;
#   * a clean run still exits 0, and a failing gate still propagates its own
#     exit code (the guards add no false blocks and swallow nothing).
#
# Message-only rewrites (added after a reword was refused as a bypass on
# 2026-10-28): git commit --amend -m produces an empty diff range, so lefthook
# skips and the guard above called a legitimate reword a bypass. The last three
# scenarios pin the boundary with real repositories — the rewrite shape is
# allowed, while an empty commit stacked on top and a rewrite that changes file
# content are both still refused.
#
# The stub lefthook binaries used by those scenarios exercise the exact
# summary line lefthook 1.12.4 prints on its skip path, without needing a
# real index, remote or network.
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
extra=""
refs_in=""
STUB_DIR="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 2; }
# Keep the --installer extraction dir cleanup working: replacing the earlier
# EXIT trap here would otherwise leak it every run.
trap 'rm -rf "$STUB_DIR"; [ -z "${EXTRACT_DIR:-}" ] || rm -rf "$EXTRACT_DIR"' EXIT

# stdin comes from $refs_in: empty means /dev/null (the "no refs at all"
# shape git never produces but a chained tool or a dropped pipe does).
# HOME is pointed at the sandbox: the shim also probes $HOME/go/bin for the
# `go install` lefthook that install-global-hooks.sh creates, and on a machine
# that has one the "binary absent" scenarios would otherwise be untestable.
run() {
  name="$1"; want="$2"; setup="$3"; shift 3
  s="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 2; }
  mkdir -p "$s/home"
  ( cd "$s" && "$setup" "$s" )
  rc=0
  if [ -n "$refs_in" ]; then
    ( cd "$s" && printf '%s\n' "$refs_in" | env -u LEFTHOOK -u LEFTHOOK_CONFIG $extra \
        HOME="$s/home" PATH="$SAFE_PATH" sh "$SHIM" --hand-patch-battery-run ) >/dev/null 2>&1 || rc=$?
  else
    ( cd "$s" && env -u LEFTHOOK -u LEFTHOOK_CONFIG $extra \
        HOME="$s/home" PATH="$SAFE_PATH" sh "$SHIM" --hand-patch-battery-run </dev/null ) >/dev/null 2>&1 || rc=$?
  fi
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

# A push that carries commits: local sha differs from the remote sha, so a
# gate run is mandatory. A deletion sends the all-zero local sha instead.
ARRIVING="refs/heads/main aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DELETION="(delete) 0000000000000000000000000000000000000000 refs/heads/gone cccccccccccccccccccccccccccccccccccccccc"

echo "scenarios:"

refs_in="$ARRIVING"
extra=""

# 1: canonical fail-open case (the 1.13.6 bug): config exists, binary absent.
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
# No config means nothing to gate, so an empty ref list is not an error here.
extra=""
refs_in=""
run "no config, no binary: silent no-op" 0 mk_nothing

# 5: the escape hatch must keep working even with a config present.
extra="LEFTHOOK=0"
refs_in="$ARRIVING"
run "LEFTHOOK=0 + config: escape hatch honored" 0 mk_yml
extra=""
refs_in=""

# 6: negative control for scenario 3 — a SET but nonexistent override must
# not abort (the verdict comes from file presence, not the variable).
extra="LEFTHOOK_CONFIG=does-not-exist.yml"
run "nonexistent LEFTHOOK_CONFIG: no-op" 0 mk_nothing
extra=""

# 7: the hand-patch's self-assertion. While the retirement is pending the
# shim is still the hand-patch and this must pass; after retirement the
# native shim does not know the marker, which is the expected end state.
assert_dir="$(mktemp -d)"
mkdir -p "$assert_dir/home"
assert_rc=0
( cd "$assert_dir" && env -u LEFTHOOK -u LEFTHOOK_CONFIG \
    LEFTHOOK_CLAUDE_SHIM_ASSERT=1 HOME="$assert_dir/home" PATH="$SAFE_PATH" sh "$SHIM" </dev/null ) >/dev/null 2>&1 || assert_rc=$?
rm -rf "$assert_dir"

# 8: a gated repo whose stdin is empty. The push range is unknowable, so the
# gates cannot run and upstream lefthook would exit 0 having checked nothing.
extra=""
refs_in=""
run "gated repo + empty stdin aborts" 1 mk_yml

# 9: lefthook's own skip path on a push that carries commits — the gate
# bypass this battery exists to prevent. rc must be 1, not lefthook's 0.
STUB_SKIP="$STUB_DIR/lefthook-skip"
printf '#!/bin/sh\necho "gates (skip) no matching push files"\nexit 0\n' > "$STUB_SKIP"
chmod +x "$STUB_SKIP"
refs_in="$ARRIVING"
extra="LEFTHOOK_BIN=$STUB_SKIP"
run "skip on an arriving push aborts" 1 mk_yml

# 10: the one legitimate skip — deleting a remote ref arrives with no commits.
refs_in="$DELETION"
run "skip on a deletion-only push is allowed" 0 mk_yml

# 10b: refs that already point at what the remote has. The range is empty and
# nothing is being deleted, so there is no reason for the gates to have been
# skipped — the same loud abort applies.
refs_in="refs/heads/main aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
run "empty push range (refs already at the remote) aborts" 1 mk_yml

# 11: a clean run still passes; the guards must not block healthy pushes.
STUB_OK="$STUB_DIR/lefthook-ok"
printf '#!/bin/sh\necho "gates (0.1 seconds)"\nexit 0\n' > "$STUB_OK"
chmod +x "$STUB_OK"
refs_in="$ARRIVING"
extra="LEFTHOOK_BIN=$STUB_OK"
run "clean run passes" 0 mk_yml

# 12: a failing gate still propagates its exit code (nothing is swallowed).
STUB_FAIL="$STUB_DIR/lefthook-fail"
printf '#!/bin/sh\nexit 3\n' > "$STUB_FAIL"
chmod +x "$STUB_FAIL"
extra="LEFTHOOK_BIN=$STUB_FAIL"
run "failing gate still fails" 3 mk_yml

# 13-15: the message-only rewrite boundary. These need real objects, because
# the shim proves the shape (remote commit present, not an ancestor, identical
# tree) rather than taking the ref lines at their word — the fake shas above
# resolve to nothing and therefore stay on the refusing side of the line.
run_repo() {
  name="$1"; want="$2"; mode="$3"
  s="$(mktemp -d)" || { echo "mktemp failed" >&2; exit 2; }
  mkdir -p "$s/home"
  if ! ( cd "$s" || exit 1
    git init -q . 2>/dev/null
    git config user.email battery@example.invalid
    git config user.name battery
    printf 'body\n' > f.txt
    git add f.txt
    git commit -qm "chore: base"
    old="$(git rev-parse HEAD)"
    case "$mode" in
      rewrite) git commit -q --amend -m "fix(scope): message-only rewrite" ;;
      stacked) git commit -q --allow-empty -m "chore: empty commit on top" ;;
      content) printf 'more\n' >> f.txt && git add f.txt && git commit -qm "feat(scope): real change" ;;
    esac
    new="$(git rev-parse HEAD)"
    printf 'refs/heads/main %s refs/heads/main %s\n' "$new" "$old" > refs.txt
    mk_yml "$s"
  ) >/dev/null 2>&1; then
    echo "  FAIL $name: sandbox repo setup failed"
    fails=$((fails + 1)); rm -rf "$s"; return
  fi
  refs="$(cat "$s/refs.txt")"
  rc=0
  ( cd "$s" && printf '%s\n' "$refs" | env -u LEFTHOOK -u LEFTHOOK_CONFIG LEFTHOOK_BIN="$STUB_SKIP" \
      HOME="$s/home" PATH="$SAFE_PATH" sh "$SHIM" --hand-patch-battery-run ) >/dev/null 2>&1 || rc=$?
  rm -rf "$s"
  if [ "$rc" -eq "$want" ]; then
    echo "  ok   $name (rc=$rc)"
  else
    echo "  FAIL $name: rc=$rc, want $want"
    fails=$((fails + 1))
  fi
}

run_repo "message-only rewrite (same tree, replaced commit) is allowed" 0 rewrite
run_repo "empty commit stacked on top still aborts" 1 stacked
run_repo "rewrite that changes file content still aborts" 1 content
extra=""
refs_in=""
if [ "$assert_rc" -eq 1 ]; then
  echo "  ok   hand-patch assertion (shim is still the 2026-09-17 patch)"
  hand_patch_asserted=1
else
  echo "  note hand-patch assertion not claimed (rc=$assert_rc) — native or already-retired shim"
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
