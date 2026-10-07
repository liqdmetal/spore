#!/usr/bin/env bash
# scripts/fuzz-soak.sh — the unattended fuzz soak.
#
# The repository has no GitHub Actions workflows, so nothing fuzzes on its own
# any more: the deep pre-flight (scripts/fuzz-smoke.sh --deep) happens only when
# a human remembers before a release, and what it finds is only kept if someone
# then runs scripts/fuzz-corpus.sh --save. This script is what a scheduler calls
# instead. One pass:
#
#   1. fuzz every target for --time seconds each (default 60: the deep pass)
#   2. harvest and minimize what that pass found (scripts/fuzz-corpus.sh --save)
#   3. count the corpus and the code it covers, and report what changed since
#      the previous pass
#
# It is safe to run unattended. It takes a lock so two passes cannot overlap, it
# never prompts, it keeps the raw fuzz log next to the report, and it exits
# non-zero when a target crashed so a scheduler's mail carries the failure. A
# crash reproducer is never minimized away: fuzz-corpus.sh keeps any entry that
# fails on its own run. A *stalled* coverage trend is reported but is not a
# failure: the passes succeeded, the fuzzer has just stopped finding new code.
#
# It is minutes long, so — like --deep — nothing in scripts/gates.sh runs it.
#
#   usage: scripts/fuzz-soak.sh [--time SECONDS] [--status] [--print-schedule]
#                                [--doctor] [--pr] [--propose]
#     --time SECONDS    fuzz seconds per target (default 60, the deep pass)
#     --status          print the last report and recent ledger rows; run nothing
#     --print-schedule  print the scheduler incantation for this host. Nothing is
#                       installed by it: paste it yourself, or ask for it to be.
#     --doctor          check that the installed schedule can still run: the
#                       launcher is current, the task is registered and points at
#                       it, and go resolves in a scheduler's minimal environment.
#                       Runs nothing and installs nothing. Non-zero on a problem,
#                       so a broken install is caught the day it breaks rather
#                       than after a week of passes that never started.
#     --pr              after the pass, hand what it found to a reviewer: the
#                       corpus, and nothing else, on one rolling fuzz-soak/corpus
#                       branch whose pull request is updated in place. Nothing to
#                       hand over is not an error. A failure here never fails the
#                       pass.
#     --propose         do just that, for the corpus as it stands, and stop.
#
# Env: FUZZ_SOAK_DIR   state directory (default <repo>/.fuzz-soak, gitignored).
#      FUZZ_SOAK_TASK  the registered task's name (default spore-fuzz-soak). Set
#                      it empty to run --doctor with no task to inspect.
#
# State under FUZZ_SOAK_DIR:
#   log.tsv            append-only ledger, one row per pass
#   last.state         the last pass's numbers, which the next pass diffs against
#   last-report.md     the human report for the last pass
#   last-fuzz.log      raw output of the last fuzz pass
#   last-corpus.log    output of the last harvest/minimize
#   last-coverage.log  the replay behind the coverage count, kept because it is
#                      the evidence a pass that could not measure points at
#   corpus-names.txt   the corpus the last pass left behind
#   last-haul.state    the haul already proposed (fingerprint, branch, url)
#
# The ledger is also what scripts/fuzz-soak-trends.sh reads: it flags the things
# a single pass cannot see (coverage that has stopped setting new bests, passes
# that did not end GREEN), and each pass quotes those flags in its report.
#
# A pass that cannot measure coverage records *why* in the ledger's last column,
# as "<kind>: <detail>". A reproducer sitting in the corpus and a failing test in
# the package are opposite things — the corpus working as intended, and the
# measurement itself broken — and they look identical in a coverage cell holding
# only "n/a", which is exactly long enough for the reader to blame the wrong one.
#
# What a pass finds is otherwise left in the working tree, waiting for somebody
# to notice it. --pr is the other half: it takes the corpus directories and
# nothing else, commits them, pushes them, and makes sure review has a pull
# request for them. It is one rolling branch, fuzz-soak/corpus, that each haul
# adds a commit to, with its pull request updated in place — so review has one
# place to look, showing the corpus the soak proposes now, instead of a fresh
# request every night the corpus moves ahead of a haul nobody has merged yet. The
# commits are built in a throwaway git worktree, so an unrelated edit in the tree
# you are sitting in is never swept in and your checkout is never switched out
# from under you. The push is always a fast-forward: the branch is appended to,
# never rewritten — a rewrite would be refused anyway, because this repository's
# protect-all-branches ruleset forbids non-fast-forward pushes on every branch —
# so nothing anybody put on that branch is ever lost. The pull request goes
# through the GitHub API with the credential git already pushes with (set
# GITHUB_TOKEN or GH_TOKEN to choose one explicitly); with no usable token, or on
# a non-GitHub remote, the branch is still pushed and its compare URL is reported
# instead.
#
# Once a haul has been pushed the corpus has a second home, and the checkout does
# not have to keep showing it: the tree is restored to HEAD, so a finding stops
# sitting in git status the moment it has a pull request, instead of every pass
# leaving the checkout dirtier than the last. Only a push that succeeded restores
# anything — a hand-off that failed leaves the corpus exactly where it was, which
# is the only place it exists. Nothing is lost by the restore: the branch carries
# what the tree carried, and the entries come back on their own, because the fuzz
# cache keeps compounding and fuzz-corpus.sh --save harvests every cached input
# the repo lacks into testdata before a pass hauls anything — so the next haul
# still starts from a superset of the branch.
#
# Exit codes: 0 every target ran clean (or --doctor found nothing wrong), 1 a
# target crashed, a step failed, or --doctor found a problem, 2 usage error (or
# --status with nothing to show).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIME=60
SHOW_STATUS=0
PRINT_SCHEDULE=0
SHOW_DOCTOR=0
PROPOSE_PR=0
PROPOSE_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -t | --time)
      [ $# -ge 2 ] || { echo "fuzz-soak: --time needs SECONDS" >&2; exit 2; }
      TIME="$2"
      shift 2
      ;;
    --status) SHOW_STATUS=1; shift ;;
    --print-schedule) PRINT_SCHEDULE=1; shift ;;
    --doctor) SHOW_DOCTOR=1; shift ;;
    --pr) PROPOSE_PR=1; shift ;;
    --propose) PROPOSE_ONLY=1; shift ;;
    -h | --help)
      cat <<'USAGE'
usage: scripts/fuzz-soak.sh [--time SECONDS] [--status] [--print-schedule] [--doctor]
                             [--pr] [--propose]
  --time SECONDS    fuzz seconds per target (default 60, the deep pass)
  --status          print the last report, then stop
  --print-schedule  print the scheduler incantation for this host, then stop
  --doctor          check the installed schedule can still run, then stop
  --pr              run a pass, then update the haul's rolling branch + PR, then stop
  --propose         branch + pull request the corpus as it stands; run no pass
USAGE
      exit 0
      ;;
    *)
      echo "fuzz-soak: unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
done

case "$TIME" in
  '' | *[!0-9]*)
    echo "fuzz-soak: --time must be a whole number of seconds, got '$TIME'" >&2
    exit 2
    ;;
esac
[ "$TIME" -ge 1 ] || { echo "fuzz-soak: --time must be at least 1" >&2; exit 2; }

SOAK_DIR="${FUZZ_SOAK_DIR:-$REPO_ROOT/.fuzz-soak}"
LEDGER="$SOAK_DIR/log.tsv"
STATE="$SOAK_DIR/last.state"
REPORT="$SOAK_DIR/last-report.md"
RAWLOG="$SOAK_DIR/last-fuzz.log"
CORPUSLOG="$SOAK_DIR/last-corpus.log"
NAMES="$SOAK_DIR/corpus-names.txt"
COVER_TMP="$SOAK_DIR/.coverage.out"
COVERLOG="$SOAK_DIR/last-coverage.log"
LOCK="$SOAK_DIR/lock"
HAUL_STATE="$SOAK_DIR/last-haul.state"
# One rolling branch rather than one per firing. The soak rewrites this branch
# from the base each time and the pull request under it is updated in place, so
# review has a single place to look and it always shows the corpus as the soak
# currently proposes it — instead of a fresh request every night the corpus
# moves ahead of a haul nobody has merged yet.
HAUL_BRANCH_NAME='fuzz-soak/corpus'

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
human() { # human SECONDS
  local s="$1"
  if [ "$s" -ge 3600 ]; then printf '%dh%dm' "$((s / 3600))" "$((s % 3600 / 60))"
  elif [ "$s" -ge 60 ]; then printf '%dm%ds' "$((s / 60))" "$((s % 60))"
  else printf '%ds' "$s"; fi
}

# How a pass describes its coverage, wherever it is quoted — the report, the
# commit that carries a haul, the pull request body. One place decides it, so the
# count, the reason it is missing and the log behind it cannot drift apart, and
# nothing can quietly go back to reporting a missing number as a number. The note
# is the same string the ledger carries, so it never has to be re-derived.
coverage_phrase() { # coverage_phrase VALUE NOTE
  case "${1:-?}" in
    n/a) printf 'not measured — %s' "${2:-the pass did not record why}" ;;
    *) printf '%s covered block(s) across ./...' "${1:-?}" ;;
  esac
}

# The last pass's numbers, as the pass wrote them. --propose reads them too, so
# a haul made without a pass still describes the pass that produced the corpus.
state_get() { # state_get KEY
  [ -f "$STATE" ] || return 0
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$STATE"
}

# ---- status, schedule and doctor are read-only, and never touch the lock ----

# The task's name. Unset takes the default; empty means "there is no task to
# inspect", which lets --doctor run against a state directory no scheduler knows
# about — including the one a test builds.
TASK_NAME="${FUZZ_SOAK_TASK-spore-fuzz-soak}"

# The fields the launcher and --doctor both need, derived once from this machine
# so "the launcher matches the config" has a single meaning and cannot drift
# between the printer and the checker.
scheduler_env() {
  if command -v cygpath >/dev/null 2>&1; then
    BASHEXE_WIN="$(cygpath -w "$(command -v bash)" 2>/dev/null || echo 'C:\Program Files\Git\bin\bash.exe')"
    SOAK_WIN="$(cygpath -w "$SOAK_DIR" 2>/dev/null || echo "$SOAK_DIR")"
  else
    BASHEXE_WIN='C:\Program Files\Git\bin\bash.exe'
    SOAK_WIN="$SOAK_DIR"
  fi

  # A scheduler hands the task a minimal environment, not this shell's. Where
  # the only go on the box is a toolchain inside the module cache — which is
  # what a box without a system Go install looks like — a launcher that just
  # calls the script dies with "go not found on PATH" a second in, and the task
  # reports that as a failure nobody reads. Set PATH in both worlds: cmd needs
  # the Windows form, and the login shell below would otherwise start clean.
  GO_BIN="$(command -v go 2>/dev/null || true)"
  if [ -n "$GO_BIN" ]; then
    GO_DIR="$(dirname "$GO_BIN")"
    if command -v cygpath >/dev/null 2>&1; then
      GO_DIR_WIN="$(cygpath -w "$GO_DIR")"
    else
      GO_DIR_WIN="$GO_DIR"
    fi
    GO_PRELUDE="set PATH=$GO_DIR_WIN;%PATH%"
    GO_EXPORT="export PATH=$GO_DIR:\$PATH && "
  else
    GO_DIR=""
    GO_DIR_WIN=""
    GO_PRELUDE="rem no go on PATH here; the launcher inherits the scheduler's"
    GO_EXPORT=""
  fi
}

# The launcher file, byte for byte. --print-schedule embeds this text and
# --doctor diffs the installed file against it, so the two cannot disagree about
# what the launcher is supposed to hold.
launcher_cmd() {
  scheduler_env
  printf '@echo off\n'
  printf 'rem spore nightly fuzz soak; regenerate this file with scripts/fuzz-soak.sh --print-schedule\n'
  printf '%s\n' "$GO_PRELUDE"
  printf '"%s" -lc "cd %s && %sbash scripts/fuzz-soak.sh --pr >> %s/soak.log 2>&1"\n' \
    "$BASHEXE_WIN" "$REPO_ROOT" "$GO_EXPORT" "$SOAK_DIR"
  printf 'exit /b %%ERRORLEVEL%%\n'
}

print_schedule() {
  scheduler_env

  case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN* | Windows*)
      # schtasks mangles nested quotes in /tr, so the scheduled command is a
      # launcher file and /tr stays a single path.
      cat <<EOF
This host looks like Windows. To soak daily at 03:30 as the current user - no
administrator rights, and printing this installs nothing:

1. write the launcher the scheduler will call:

  cat > "$SOAK_DIR/run-soak.cmd" <<'CMD'
$(launcher_cmd | sed 's/^/  /')
  CMD

2. schedule it:

  schtasks /create /tn $TASK_NAME /sc daily /st 03:30 /f /tr "$SOAK_WIN\\run-soak.cmd"

Then prove it can still run, and read the last pass:

  bash scripts/fuzz-soak.sh --doctor
  schtasks /query /tn $TASK_NAME /v /fo LIST
  bash scripts/fuzz-soak.sh --status

Undo it:

  schtasks /delete /tn $TASK_NAME /f
EOF
      ;;
    *)
      cat <<EOF
This host looks POSIX. cron, daily at 03:30:

  30 3 * * * cd $REPO_ROOT && scripts/fuzz-soak.sh >> $SOAK_DIR/soak.log 2>&1

or a systemd user timer, which logs to the journal, catches up on a missed run,
and survives a reboot once \`loginctl enable-linger \$USER\` is set:

  mkdir -p ~/.config/systemd/user
  cat > ~/.config/systemd/user/spore-fuzz-soak.service <<'UNIT'
  [Unit]
  Description=spore fuzz soak
  [Service]
  Type=oneshot
  WorkingDirectory=$REPO_ROOT
  ExecStart=$REPO_ROOT/scripts/fuzz-soak.sh
  UNIT
  cat > ~/.config/systemd/user/spore-fuzz-soak.timer <<'UNIT'
  [Unit]
  Description=daily spore fuzz soak
  [Timer]
  OnCalendar=daily
  Persistent=true
  [Install]
  WantedBy=timers.target
  UNIT
  systemctl --user daemon-reload && systemctl --user enable --now spore-fuzz-soak.timer
EOF
      ;;
  esac
}

# ---- doctor: can the installed schedule still run? --------------------------

# A scheduled soak fails the quiet way. The task stays registered and the ledger
# keeps its last row, so nothing looks wrong until somebody reads a timestamp —
# and by then it has been days. Three things have to hold, and each breaks on its
# own: a moved checkout or a moved toolchain leaves the launcher stale, the task
# can be lost or left pointing somewhere else, and go has to resolve in the
# minimal environment a scheduler hands a task, which is the failure that started
# all this. Each check is instant, and none of them runs a pass.
doctor() {
  local problems=0 passed=0
  local q runs status next shell_exe
  local launcher="$SOAK_DIR/run-soak.cmd"

  ok() { printf '  ok:   %s\n' "$*"; passed=$((passed + 1)); }
  bad() { printf '  FAIL: %s\n' "$*" >&2; problems=$((problems + 1)); }
  note() { printf '  note: %s\n' "$*"; }

  scheduler_env
  echo "fuzz-soak: doctor — can the installed schedule still run? (state: $SOAK_DIR)"

  case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN* | Windows*)
      # --- the launcher the task starts ---------------------------------------
      if [ ! -f "$launcher" ]; then
        bad "no launcher at $launcher — the task has nothing to start"
        note "regenerate it: bash scripts/fuzz-soak.sh --print-schedule"
      elif cmp -s <(launcher_cmd) <(tr -d '\r' < "$launcher"); then
        ok "launcher is current: byte for byte what --print-schedule prints"
      else
        bad "launcher is stale — it is not what --print-schedule prints now"
        diff <(launcher_cmd) <(tr -d '\r' < "$launcher") 2>/dev/null | head -8 | sed 's/^/        /' >&2 || true
      fi

      # --- the task that starts it --------------------------------------------
      if [ -z "$TASK_NAME" ]; then
        note "FUZZ_SOAK_TASK is empty: no task was named, so none was checked"
      elif ! command -v schtasks >/dev/null 2>&1; then
        note "no schtasks on this host: the registration is not checkable from here"
      elif ! q="$(MSYS_NO_PATHCONV=1 schtasks /query /tn "$TASK_NAME" /v /fo LIST 2>&1)"; then
        bad "task $TASK_NAME is not registered — nothing will fire"
      else
        runs="$(printf '%s\n' "$q" | sed -n 's/^Task To Run:[[:space:]]*//p' | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//')"
        status="$(printf '%s\n' "$q" | sed -n 's/^Status:[[:space:]]*//p' | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//')"
        next="$(printf '%s\n' "$q" | sed -n 's/^Next Run Time:[[:space:]]*//p' | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//')"
        if [ -z "$runs" ]; then
          bad "task $TASK_NAME is registered but names no command to run"
        elif [ "$(printf '%s' "$runs" | tr 'A-Z' 'a-z')" != "$(printf '%s' "$SOAK_WIN\\run-soak.cmd" | tr 'A-Z' 'a-z')" ]; then
          bad "task $TASK_NAME runs $runs, not $SOAK_WIN\\run-soak.cmd"
        else
          ok "task $TASK_NAME runs the launcher (status ${status:-?}, next run ${next:-?})"
        fi
      fi
      ;;
    *)
      note "this host is POSIX: the schedule is a cron line or a systemd timer, which --print-schedule prints and this script cannot read back"
      ;;
  esac

  # --- go, in the environment a scheduler actually hands the task -------------
  # The launcher works by putting one directory on PATH, and nothing else. If go
  # does not resolve with only that directory, the task starts and dies about a
  # second in — which is exactly how the first install here failed.
  if [ -z "$GO_DIR" ]; then
    bad "go is not on PATH here, so the launcher --print-schedule would write could not run"
  else
    shell_exe=""
    if command -v bash >/dev/null 2>&1; then shell_exe="$(command -v bash)"
    elif command -v sh >/dev/null 2>&1; then shell_exe="$(command -v sh)"
    fi
    if [ -z "$shell_exe" ]; then
      note "no shell available to probe go with"
    elif PATH="$GO_DIR" "$shell_exe" -c 'go version' >/dev/null 2>&1; then
      ok "go runs with only the launcher's directory on PATH ($GO_DIR)"
    else
      bad "go does not run with PATH=$GO_DIR alone — the launcher's PATH line cannot save it"
    fi
  fi

  echo "fuzz-soak: doctor: $passed ok, $problems problem(s)"
  [ "$problems" -eq 0 ]
}

# ---- the haul: hand what a pass found to a reviewer -------------------------

# A pass used to end by leaving its findings in the working tree, where they wait
# for somebody to notice. This is the other half: the corpus directories, and
# nothing else, on a branch of their own, with a pull request attached.
#
# Nothing here fails a pass. No git, no remote, no credential, nothing new — each
# of those is a sentence in the report and a haul still sitting in the working
# tree, exactly as before.

# The git pathspecs that are the corpus: the fuzz data directory of every package
# that has one. Named per package rather than handed to git as a glob, so the
# pathspec cannot reach anything else that happens to be called testdata/fuzz.
corpus_pathspecs() {
  local d
  for d in internal/*/testdata/fuzz; do
    [ -d "$d" ] || continue
    printf '%s\n' "$d"
  done
}

# A token for the GitHub API, preferring one set for us. Otherwise ask git for
# the credential it already pushes with — same store, same login, nothing new to
# configure. Never printed and never written down; only ever handed to curl.
github_token() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then printf '%s' "$GITHUB_TOKEN"; return 0; fi
  if [ -n "${GH_TOKEN:-}" ]; then printf '%s' "$GH_TOKEN"; return 0; fi
  local fill=(git credential fill)
  if command -v timeout >/dev/null 2>&1; then fill=(timeout 15 git credential fill); fi
  printf 'protocol=https\nhost=github.com\n\n' \
    | GIT_TERMINAL_PROMPT=0 "${fill[@]}" 2>/dev/null \
    | sed -n 's/^password=//p'
}

# owner/repo for a github.com remote, left in $owner/$repo; false for anything
# else, so a local path or an internal mirror degrades to a pushed branch.
github_slug() { # github_slug URL
  local slug
  case "$1" in
    https://github.com/* | http://github.com/* | git@github.com:* | ssh://git@github.com/*) ;;
    *) return 1 ;;
  esac
  slug="${1#*github.com}"
  slug="${slug#[:/]}"
  slug="${slug%.git}"
  owner="${slug%%/*}"
  repo="${slug#*/}"
  [ -n "$owner" ] && [ -n "$repo" ] && [ "$repo" != "$slug" ]
}

# A JSON string literal for arbitrary text, without jq. The pull request body is
# the only field that needs it.
json_string() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' \
    | awk 'BEGIN { ORS="" } { if (NR > 1) printf "\\n"; printf "%s", $0 }'
}

HAUL_STATUS="skipped"
HAUL_BRANCH=""
HAUL_URL=""
HAUL_NOTE=""
# What became of the working tree once the haul was pushed: restoring it is the
# tidy half of the hand-off, never a condition of it.
HAUL_RESTORE=""
# Handed to curl as a bearer header and to nothing else: never printed, never
# written into the state directory.
HAUL_TOKEN=""

haul_skip() { HAUL_STATUS="skipped"; HAUL_NOTE="$*"; }
haul_fail() { HAUL_STATUS="failed"; HAUL_NOTE="$*"; }

# A fact from the pass that produced this corpus, with a fallback for the case
# where --propose runs against a tree no pass has touched yet.
haul_fact() { # haul_fact KEY DEFAULT
  local v
  v="$(state_get "$1")"
  if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "$2"; fi
}

# What the last haul carried. Without it a nightly would re-propose the same
# corpus every night until somebody merged it — the pileup that makes an
# automated pull request worth ignoring.
haul_state_get() { # haul_state_get KEY
  [ -f "$HAUL_STATE" ] || return 0
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$HAUL_STATE"
}

# The delta's identity. Corpus entries are named after their contents, so the
# set of names *is* the contents: two hauls with the same fingerprint are the
# same entries, whatever changed in between. git hash-object rather than
# sha256sum, because git is already required here.
haul_fingerprint() {
  git status --porcelain -- "$@" | LC_ALL=C sort | git hash-object --stdin
}

# A rolling pull request keeps one title: the pass that produced the current
# contents is named in the body, which is refreshed with each haul.
haul_title() {
  printf 'test(fuzz): the soak corpus haul'
}

haul_body() { # haul_body BASE_SHA BASE_BRANCH
  # The heredoc is unquoted so the haul_fact calls expand — which also means every
  # backtick in it is a command substitution. They are escaped, not decorative:
  # the first firing of this shipped a body that had run `go test` and substituted
  # its output, and an empty base, because they were not.
  cat <<EOF
The scheduled fuzz soak found corpus entries and minimized them. This branch is
where each pass hands them over: one commit per pass that changed anything, so
the newest seed out of the fuzzer is the newest commit here, and a seed a later
pass minimized away is a deletion in the commit after it. The corpus directories
are all it carries. Every entry is named after the sha256 of its own contents, so
a file name here is exact, and \`go test\` replays the whole corpus, so these are
pinned against the code that found them.

- newest pass: $(haul_fact timestamp '(no pass recorded on this machine)')
- corpus: $(haul_fact corpus '?') file(s)
- coverage: $(coverage_phrase "$(haul_fact coverage '')" "$(haul_fact coverage_note '')")
- built on: \`$1\` on \`$2\`

A shrinking corpus with flat coverage is normal: minimization keeps a covering
subset, so entries leave as well as arrive.
EOF
}

haul_commit_message() {
  local stamp corpus coverage
  stamp="$(haul_fact timestamp '')"
  corpus="$(haul_fact corpus '')"
  coverage="$(haul_fact coverage '')"
  printf 'test(fuzz): the soak corpus haul'
  if [ -n "$stamp" ]; then printf ' from %s' "$stamp"; fi
  printf '\n\n'
  printf 'Automated by scripts/fuzz-soak.sh --pr: the corpus directories, and nothing\n'
  printf 'else, as one pass left them. A corpus entry is a regression seed, and every\n'
  printf 'entry is named after the sha256 of its own contents, so a name here is exact.\n'
  if [ -n "$corpus" ] || [ -n "$coverage" ]; then
    printf '\ncorpus %s file(s), coverage %s\n' \
      "${corpus:-?}" "$(coverage_phrase "$coverage" "$(haul_fact coverage_note '')")"
  fi
}

# The branch belongs on the remote, not in this checkout: a nightly soak that
# left a local branch per firing would bury the branches the user works on. The
# commit stays reachable through the pushed ref.
haul_cleanup() { # haul_cleanup BRANCH
  git -C "$REPO_ROOT" worktree remove --force "$SOAK_DIR/pr-worktree" >/dev/null 2>&1 || true
  rm -rf "$SOAK_DIR/pr-worktree"
  git -C "$REPO_ROOT" branch -D "$1" >/dev/null 2>&1 || true
}

# One GitHub API call. Prints the response body and then, on its own last line,
# the HTTP status code. The two have to travel together: the callers capture this
# in a command substitution, which runs in a subshell, and nothing a function
# assigns there survives to be read afterwards. Split an answer with
# haul_api_body and haul_api_status. The token is never printed and never written
# down.
haul_api() { # haul_api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" data="${3:-}"
  local args=(-sS -X "$method"
    -H "Authorization: Bearer $HAUL_TOKEN"
    -H 'Accept: application/vnd.github+json')
  if [ -n "$data" ]; then
    args+=(-H 'Content-Type: application/json' --data "$data")
  fi
  local resp
  resp="$(curl "${args[@]}" -w '\n%{http_code}' "https://api.github.com$path" 2>&1)" || resp='
000'
  printf '%s' "$resp"
}

haul_api_body() { printf '%s' "${1%$'\n'*}"; }
haul_api_status() { printf '%s' "${1##*$'\n'}"; }

# The pull request's own html_url. The API puts it before any other url in the
# document, so the first one on the wire is the request itself.
pr_url() { # pr_url JSON
  printf '%s\n' "$1" \
    | sed -n 's/.*"html_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# The hand-off, once the branch is on the remote. One rolling branch means one
# rolling pull request: when review already has one for this branch it is updated
# in place rather than a second request being opened beside it, which is what a
# nightly used to do every time the corpus moved ahead of a haul nobody had
# merged. The title is fixed and the body is regenerated each haul, so the request
# always describes the pass whose corpus it currently carries.
#
# Nothing here turns a pushed branch into a failed haul. No curl, no github.com, no
# credential, an API that answers a code it should not: each of those leaves the
# branch pushed and reports the compare URL instead.
propose_pull_request() { # propose_pull_request BASE_SHA BASE_BRANCH BRANCH URL
  local base_sha="$1" base_branch="$2" branch="$3" url="$4"
  local number existing_json body payload resp code attempt

  HAUL_STATUS='proposed'
  HAUL_URL=""

  if ! command -v curl >/dev/null 2>&1 || ! github_slug "$url"; then
    HAUL_NOTE="pushed $branch (not a github.com remote, so no pull request was opened)"
    return 0
  fi
  HAUL_URL="https://github.com/$owner/$repo/compare/$base_branch...$branch?expand=1"
  HAUL_NOTE="pushed $branch; no GitHub credential was available, so the compare URL is the hand-off"

  HAUL_TOKEN="$(github_token)"
  [ -n "$HAUL_TOKEN" ] || return 0

  # Is there already an open request for this branch? Asking first is the whole
  # difference between one rolling request and a pile of them.
  number=""
  existing_json="$(haul_api GET "/repos/$owner/$repo/pulls?head=$owner:$branch&state=open")"
  if [ "$(haul_api_status "$existing_json")" = "200" ]; then
    number="$(haul_api_body "$existing_json" \
      | sed -n 's/^[[:space:]]*"number":[[:space:]]*\([0-9][0-9]*\).*$/\1/p' | head -1)"
  fi

  body="$(haul_body "$base_sha" "$base_branch")"
  if [ -n "$number" ]; then
    # head is not updatable, and does not need to be: the branch was already
    # rewritten under the request by the push above.
    payload="$(printf '{"title":"%s","body":"%s"}' \
      "$(printf '%s' "$(haul_title)" | json_string)" \
      "$(printf '%s' "$body" | json_string)")"
    resp="$(haul_api PATCH "/repos/$owner/$repo/pulls/$number" "$payload")"
    code="$(haul_api_status "$resp")"
    if [ "$code" = "200" ]; then
      HAUL_URL="$(pr_url "$(haul_api_body "$resp")")"
      [ -n "$HAUL_URL" ] || HAUL_URL="https://github.com/$owner/$repo/compare/$base_branch...$branch?expand=1"
      HAUL_NOTE="pushed $branch and updated pull request #$number"
    else
      HAUL_NOTE="pushed $branch, but updating pull request #$number answered $code, so the compare URL is the hand-off"
    fi
    return 0
  fi

  payload="$(printf '{"title":"%s","head":"%s","base":"%s","body":"%s"}' \
    "$(printf '%s' "$(haul_title)" | json_string)" \
    "$branch" "$base_branch" \
    "$(printf '%s' "$body" | json_string)")"
  # A creation is retried once. A request for a branch that was pushed seconds
  # ago is refused while the API still sees the ref as it was — seen once here: a
  # 400 for a brand-new branch, with the same request answering 201 minutes
  # later. Anything that fails twice is reported and the compare URL is the
  # hand-off, exactly as before.
  code=""
  for attempt in 1 2; do
    resp="$(haul_api POST "/repos/$owner/$repo/pulls" "$payload")"
    code="$(haul_api_status "$resp")"
    if [ "$code" = "201" ]; then break; fi
    if [ "$attempt" = 1 ]; then sleep 2; fi
  done
  if [ "$code" = "201" ]; then
    HAUL_URL="$(pr_url "$(haul_api_body "$resp")")"
    [ -n "$HAUL_URL" ] || HAUL_URL="https://github.com/$owner/$repo/compare/$base_branch...$branch?expand=1"
    HAUL_NOTE="pushed $branch and opened a pull request"
  else
    HAUL_NOTE="pushed $branch, but the pull request API answered $code, so the compare URL is the hand-off"
  fi
  return 0
}

# Restore the corpus to HEAD in this checkout, now that the branch carries it.
#
# Called from exactly one place — after a push that succeeded. An unhanded-over
# haul is never restored, because the working tree is then the only place it
# exists, and a failed hand-off has to stay harmless.
#
# The pathspec is the corpus directories and nothing else, the same one the haul
# stages, so an unrelated edit somebody has open is untouched. git clean does not
# reach an ignored file (that would take -x), and the entries it does remove are
# the corpus files the branch has just taken.
restore_hauled_corpus() {
  local paths=() p left
  while IFS= read -r p; do paths+=("$p"); done < <(corpus_pathspecs)
  HAUL_RESTORE=""
  [ "${#paths[@]}" -gt 0 ] || return 0

  # Tracked entries come back from HEAD (a minimized-away seed is a deletion);
  # untracked ones are the pass's findings, and the branch has them now.
  git -C "$REPO_ROOT" checkout -- "${paths[@]}" >/dev/null 2>&1 || true
  git -C "$REPO_ROOT" clean -fdq -- "${paths[@]}" >/dev/null 2>&1 || true

  left="$(git -C "$REPO_ROOT" status --porcelain -- "${paths[@]}" 2>/dev/null | wc -l)"
  if [ "$left" -eq 0 ]; then
    HAUL_RESTORE="the corpus is restored to HEAD here: it is on $HAUL_BRANCH now, so it stops sitting in git status"
  else
    HAUL_RESTORE="could not restore the corpus here: $left path(s) still differ from HEAD"
  fi
  return 0
}

propose_haul() {
  local remote url base_branch base_sha branch wt p msg fingerprint parent
  local paths=()

  command -v git >/dev/null 2>&1 || { haul_skip 'git is not on PATH'; return 0; }
  git rev-parse --git-dir >/dev/null 2>&1 || { haul_skip 'this is not a git checkout'; return 0; }

  while IFS= read -r p; do paths+=("$p"); done < <(corpus_pathspecs)
  [ "${#paths[@]}" -gt 0 ] || { haul_skip 'this tree carries no corpus'; return 0; }

  [ -n "$(git status --porcelain -- "${paths[@]}")" ] \
    || { haul_skip 'the corpus matches HEAD: nothing new to hand over'; return 0; }

  local fingerprint
  fingerprint="$(haul_fingerprint "${paths[@]}")"
  if [ -n "$(haul_state_get fingerprint)" ] && [ "$fingerprint" = "$(haul_state_get fingerprint)" ]; then
    haul_skip "already proposed on $(haul_state_get branch); these entries have not changed since"
    return 0
  fi

  remote="$(git remote | head -1)"
  [ -n "$remote" ] || { haul_skip 'no git remote to push a branch to'; return 0; }
  url="$(git config --get "remote.$remote.url" || true)"

  base_branch="$(git rev-parse --abbrev-ref HEAD)"
  base_sha="$(git rev-parse HEAD)"
  branch="$HAUL_BRANCH_NAME"
  wt="$SOAK_DIR/pr-worktree"

  # Where this haul's commit goes. The branch accumulates: each haul adds one
  # commit to what is already on it and the pull request is updated in place. It
  # cannot be rewritten, and should not be — the repository's protect-all-branches
  # ruleset forbids a non-fast-forward push and a deletion on every branch, so a
  # rewrite is refused by the remote, and an automated writer has no business
  # rewriting history anyway. Appending is also the more useful shape for review:
  # the branch is a record of what each firing found, the newest seed the fuzzer
  # produced is the newest commit, and a seed a later pass minimized away is a
  # deletion in the commit after it.
  #
  # One fetch says what the branch holds now without moving any ref. Nothing
  # there yet — the first haul, or a branch the last merge cleaned up — means this
  # haul starts from the commit the pass ran against.
  parent="$base_sha"
  if GIT_TERMINAL_PROMPT=0 git -C "$REPO_ROOT" fetch --quiet "$remote" "refs/heads/$branch" >/dev/null 2>&1; then
    parent="$(git -C "$REPO_ROOT" rev-parse FETCH_HEAD 2>/dev/null || true)"
    [ -n "$parent" ] || parent="$base_sha"
  fi

  # A worktree, not this checkout. Staging here would sweep up whatever else the
  # tree holds, and committing here would move the branch the user is on.
  git worktree remove --force "$wt" >/dev/null 2>&1 || true
  rm -rf "$wt"
  git worktree prune >/dev/null 2>&1 || true
  mkdir -p "$(dirname "$wt")"
  if ! git worktree add -B "$branch" "$wt" "$parent" >/dev/null 2>&1; then
    haul_fail "could not make a worktree at $wt for the haul"
    return 0
  fi

  for p in "${paths[@]}"; do
    rm -rf "$wt/$p"
    mkdir -p "$(dirname "$wt/$p")"
    cp -R "$REPO_ROOT/$p" "$wt/$p"
  done

  git -C "$wt" add -A -- "${paths[@]}" >/dev/null 2>&1 || true
  if git -C "$wt" diff --cached --quiet; then
    haul_cleanup "$branch"
    haul_skip "$branch already carries this corpus: nothing to hand over"
    return 0
  fi

  msg="$(haul_commit_message)"
  if ! git -C "$wt" commit -q -m "$msg" >/dev/null 2>&1; then
    haul_cleanup "$branch"
    haul_fail 'could not commit the corpus in the worktree'
    return 0
  fi

  # GIT_TERMINAL_PROMPT=0: an unattended pass must fail rather than wait at a
  # prompt nobody is there to answer. A plain push, never a force: the commit sits
  # on top of what the branch already holds, so it is a fast-forward, and if
  # somebody pushed in the meantime the remote refuses it rather than losing
  # either side — the next pass picks the branch up where it now stands.
  if ! GIT_TERMINAL_PROMPT=0 git -C "$wt" push --quiet "$remote" "$branch" >/dev/null 2>&1; then
    haul_cleanup "$branch"
    haul_fail "could not push $branch to $remote: the haul is still in the working tree"
    return 0
  fi
  HAUL_BRANCH="$branch"

  # Past the push the hand-off has happened; only how loud it is remains.
  propose_pull_request "$base_sha" "$base_branch" "$branch" "$url"

  { printf 'fingerprint=%s\n' "$fingerprint"
    printf 'branch=%s\n' "$HAUL_BRANCH"
    printf 'url=%s\n' "$HAUL_URL"
    printf 'timestamp=%s\n' "$(now_iso)"
  } > "$HAUL_STATE"

  # Past the push, so the corpus has another home now and this one can go back to
  # the way it was. A push that failed returned above, leaving the tree alone.
  restore_hauled_corpus

  haul_cleanup "$branch"
  return 0
}

if [ "$PRINT_SCHEDULE" -eq 1 ]; then print_schedule; exit 0; fi

if [ "$SHOW_DOCTOR" -eq 1 ]; then
  if doctor; then exit 0; else exit 1; fi
fi

if [ "$PROPOSE_ONLY" -eq 1 ]; then
  # Refuse while a pass is in flight: the corpus it is still minimizing is not
  # the corpus to propose.
  if [ -d "$LOCK" ]; then
    echo "fuzz-soak: a pass holds $LOCK — the corpus is still moving; propose once it finishes" >&2
    exit 2
  fi
  propose_haul
  case "$HAUL_STATUS" in
    proposed)
      echo "fuzz-soak: haul — $HAUL_NOTE"
      echo "fuzz-soak: haul — branch $HAUL_BRANCH"
      if [ -n "$HAUL_URL" ]; then echo "fuzz-soak: haul — $HAUL_URL"; fi
      if [ -n "$HAUL_RESTORE" ]; then echo "fuzz-soak: haul — $HAUL_RESTORE"; fi
      exit 0
      ;;
    failed)
      echo "fuzz-soak: haul — $HAUL_NOTE" >&2
      exit 1
      ;;
    *)
      echo "fuzz-soak: haul — nothing to propose: $HAUL_NOTE"
      exit 0
      ;;
  esac
fi

if [ "$SHOW_STATUS" -eq 1 ]; then
  if [ ! -f "$REPORT" ]; then
    echo "fuzz-soak: no pass has run here yet (looked for $REPORT)" >&2
    echo "           run one: bash scripts/fuzz-soak.sh" >&2
    exit 2
  fi
  cat "$REPORT"
  if [ -s "$LEDGER" ]; then
    echo
    echo "recent passes ($LEDGER):"
    printf '  %-20s %-6s %8s %8s %9s %9s %8s\n' "timestamp" "status" "corpus" "found" "minimized" "coverage" "secs"
    tail -n +2 "$LEDGER" | tail -n 5 | awk -F'\t' '{ printf "  %-20s %-6s %8s %8s %9s %9s %8s\n", $1, $4, $6, $7, $8, $9, $11 }'
    echo
    echo "multi-pass view: scripts/fuzz-soak-trends.sh"
  fi
  exit 0
fi

# ---- one pass ---------------------------------------------------------------

acquire_lock() {
  if mkdir "$LOCK" 2>/dev/null; then
    trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
    return 0
  fi
  # A pass is about ten minutes. Anything much older is a corpse (a killed run,
  # a reboot mid-soak), not a live pass, and must not block the soak forever.
  if find "$LOCK" -maxdepth 0 -mmin +360 2>/dev/null | grep -q .; then
    rmdir "$LOCK" 2>/dev/null || true
    if mkdir "$LOCK" 2>/dev/null; then
      trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT
      return 0
    fi
  fi
  echo "fuzz-soak: another pass holds $LOCK — not starting a second one" >&2
  return 1
}

# The packages carrying a corpus, derived from the tree rather than typed, so
# this cannot drift from the target list the runner and the harvester share.
corpus_packages() {
  local d p
  for d in internal/*/testdata/fuzz/Fuzz*/; do
    [ -d "$d" ] || continue
    p="$(dirname "$(dirname "$(dirname "$d")")")"
    printf '%s\n' "./$p"
  done | sort -u
}

# One line per corpus entry, "<Target>/<name>", so two snapshots diff per target
# without this script knowing anything about the corpus contents.
corpus_names() {
  local d f
  for d in internal/*/testdata/fuzz/Fuzz*/; do
    [ -d "$d" ] || continue
    for f in "$d"*; do
      [ -f "$f" ] || continue
      printf '%s/%s\n' "$(basename "$d")" "$(basename "$f")"
    done
  done | sort
}

# What this box knew before a pass: the tree, plus what the last pass left. On a
# quiet night those are the same set. They part company when the last pass handed
# its corpus over, because a successful haul restores the tree to HEAD and the
# entries it took are then only in that snapshot (and in the fuzz cache, which the
# harvest copies back). Taking the union is what keeps a pass's delta about what it
# found rather than about what the last haul took away: without it, every night
# would report the same unmerged entries as found again, for as long as the request
# stayed open.
corpus_known_before() { # corpus_known_before PREV_NAMES_FILE
  { corpus_names; if [ -f "$1" ]; then cat "$1"; fi; } | sort -u
}

count_files() { find internal/*/testdata/fuzz/Fuzz*/ -maxdepth 1 -type f 2>/dev/null | wc -l; }
count_targets() { find internal/*/testdata/fuzz/Fuzz*/ -maxdepth 0 -type d 2>/dev/null | wc -l; }

# The targets the report tabulates. Named from what the pass found ($NAMES) and
# only then from what the tree holds now, because a successful haul restores the
# corpus: the report is about the pass that ran, not about the checkout it left
# behind, and a target whose entries all went away is still worth naming.
corpus_targets() {
  { for d in internal/*/testdata/fuzz/Fuzz*/; do
      [ -d "$d" ] || continue
      basename "$d"
    done
    if [ -f "$NAMES" ]; then cut -d/ -f1 "$NAMES"; fi
  } | sort -u
}

# Covered statement blocks across the module, as the corpus replays them, and —
# when it cannot — why not: one TSV line, the value then the reason, exactly like
# the API helper's status code riding on its own last line. It has to travel that
# way because the pass reads this through a command substitution, which runs in a
# subshell: nothing a function assigns in one survives to be read afterwards. The
# tab is always printed, empty reason included, and that is what makes the split
# in the pass total.
measure_coverage() {
  local pkgs=() p note
  while IFS= read -r p; do pkgs+=("$p"); done < <(corpus_packages)
  if [ "${#pkgs[@]}" -eq 0 ]; then
    printf '%s\t%s' 'n/a' 'no-corpus: no package carries a corpus to measure'
    return 0
  fi
  # The replay's output is kept rather than discarded: it is the only place the
  # reason lives, and the report points at it as the evidence behind the summary.
  if ! go test -coverpkg=./... -covermode=set -coverprofile="$COVER_TMP" "${pkgs[@]}" > "$COVERLOG" 2>&1; then
    note="$(coverage_note "$COVERLOG" | tr -d '\r' | tr '\t' ' ')"
    printf '%s\t%s' 'n/a' "$note"
    return 0
  fi
  printf '%s\t%s' "$(awk 'NR > 1 && $NF + 0 > 0' "$COVER_TMP" | wc -l)" ''
}

# The failing test names in a go test log, joined for a ledger cell: at most
# three, then "...", so one bad run cannot make the column enormous.
coverage_names() {
  awk 'NR > 3 { more = 1; next } { printf "%s%s", (seen++ ? ", " : ""), $0 } END { if (more) printf ", ..." }'
}

# Why a coverage measurement could not be taken, as one "<kind>: <detail>" line.
# The kind is what the trend reader matches on, and it is the whole point: "n/a"
# hides two opposite things. The shapes below are what go test really prints.
#
#   --- FAIL: FuzzFrameParse (0.00s)        the target, then the entry under it
#       --- FAIL: FuzzFrameParse/seed#2 (0.00s)
#   --- FAIL: TestFuzzSoakHaul... (0.00s)   an ordinary test, nothing to do with
#                                           the corpus
#   FAIL  ./internal/wirefuzz [build failed]  nothing was replayed at all
coverage_note() { # coverage_note LOGFILE
  local log="$1" fails tests corpus detail
  if grep -q 'panic: test timed out' "$log"; then
    printf 'timeout: go test did not finish'
    return 0
  fi
  if grep -q '\[build failed\]\|cannot find package\|no required module' "$log"; then
    printf 'build-error: the package did not build, so nothing was replayed'
    return 0
  fi
  fails="$(grep -E '^[[:space:]]*--- FAIL: ' "$log" 2>/dev/null | sed 's/^[[:space:]]*--- FAIL: //; s/ (.*//' || true)"
  if [ -n "$fails" ]; then
    # A fuzz target name, or an entry under one: a corpus file or a seed.
    tests="$(printf '%s\n' "$fails" | grep -vE '^Fuzz[A-Za-z0-9_]+(/.*)?$' | coverage_names || true)"
    corpus="$(printf '%s\n' "$fails" | grep -E '^Fuzz[A-Za-z0-9_]+/' | coverage_names || true)"
    if [ -n "$tests" ]; then
      detail="$tests fails, which is not a corpus entry"
      if [ -n "$corpus" ]; then detail="$detail; the replay also failed on $corpus"; fi
      printf 'test-failure: %s' "$detail"
      return 0
    fi
    if [ -z "$corpus" ]; then corpus="$(printf '%s\n' "$fails" | coverage_names)"; fi
    printf 'reproducer: %s fails on its own, so the replay it would be measured against cannot finish' "$corpus"
    return 0
  fi
  detail="$(grep -m1 -v '^[[:space:]]*$' "$log" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//' | cut -c1-160 || true)"
  printf 'other: go test failed — %s' "${detail:-see the log}"
}

command -v go >/dev/null 2>&1 || { echo "fuzz-soak: go not found on PATH" >&2; exit 1; }
mkdir -p "$SOAK_DIR"
acquire_lock || exit 1

START_EPOCH="$(date +%s)"
START_ISO="$(now_iso)"
if [ "$TIME" -ge 60 ]; then MODE="deep"; else MODE="short"; fi
echo "fuzz-soak: pass starting $START_ISO — ${TIME}s per target, then save + minimize"

# The previous pass left the corpus this pass starts from, so the two snapshots
# around the pass are all the delta reporting needs.
PREV_NAMES="$SOAK_DIR/corpus-names.prev.txt"
if [ -f "$NAMES" ]; then cp "$NAMES" "$PREV_NAMES"; else : > "$PREV_NAMES"; fi
NAMES_BEFORE="$SOAK_DIR/corpus-names.before.txt"
corpus_known_before "$PREV_NAMES" > "$NAMES_BEFORE"
COUNT_BEFORE="$(wc -l < "$NAMES_BEFORE")"
TARGETS_N="$(count_targets)"

# --- 1. the deep pass --------------------------------------------------------
FUZZ_RC=0
bash "$REPO_ROOT/scripts/fuzz-smoke.sh" -t "$TIME" > "$RAWLOG" 2>&1 || FUZZ_RC=$?
CRASHES="$(grep -oE 'FUZZ SMOKE FAILED: Fuzz[A-Za-z0-9_]+' "$RAWLOG" 2>/dev/null | sed 's/.*: //' | sort -u | tr '\n' ' ' || true)"
case "$FUZZ_RC" in
  0) STATUS="GREEN"; echo "fuzz-soak: $TARGETS_N target(s) clean" ;;
  1) STATUS="CRASH"; echo "fuzz-soak: TARGET CRASHED — ${CRASHES:-see $RAWLOG}" >&2 ;;
  *) STATUS="ERROR"; echo "fuzz-soak: the fuzz pass exited $FUZZ_RC (see $RAWLOG)" >&2 ;;
esac

# --- 2. keep what it found ---------------------------------------------------
CORPUS_RC=0
bash "$REPO_ROOT/scripts/fuzz-corpus.sh" --save > "$CORPUSLOG" 2>&1 || CORPUS_RC=$?
if [ "$CORPUS_RC" -ne 0 ]; then
  echo "fuzz-soak: harvest/minimize exited $CORPUS_RC (see $CORPUSLOG)" >&2
  [ "$STATUS" = "GREEN" ] && STATUS="ERROR"
fi

corpus_names > "$NAMES"
COUNT_AFTER="$(count_files)"

# --- 3. what changed ---------------------------------------------------------
ADDED="$(comm -13 "$NAMES_BEFORE" "$NAMES" | wc -l)"
DROPPED="$(comm -23 "$NAMES_BEFORE" "$NAMES" | wc -l)"
SINCE_FOUND="$(comm -13 "$PREV_NAMES" "$NAMES" | wc -l)"
SINCE_GONE="$(comm -23 "$PREV_NAMES" "$NAMES" | wc -l)"
PREV_CORPUS="$(wc -l < "$PREV_NAMES")"

# One line out, two halves in: the value, then the reason there is not one. A
# missing tab would otherwise put the whole line in the value and leave the note
# silently empty, which is the bug this shape exists to make impossible.
COVERAGE_OUT="$(measure_coverage)"
case "$COVERAGE_OUT" in
  *$'\t'*)
    COVERAGE="${COVERAGE_OUT%%$'\t'*}"
    COVERAGE_NOTE="${COVERAGE_OUT#*$'\t'}"
    ;;
  *)
    COVERAGE="$COVERAGE_OUT"
    COVERAGE_NOTE=""
    ;;
esac
PREV_COVERAGE="$(state_get coverage)"
PREV_ISO="$(state_get timestamp)"
PREV_EPOCH="$(state_get epoch)"
[ -n "$PREV_EPOCH" ] || PREV_EPOCH="$START_EPOCH"
if [ "$COVERAGE" != "n/a" ] && [ -n "$PREV_COVERAGE" ] && [ "$PREV_COVERAGE" != "n/a" ]; then
  COVER_DELTA="$(printf '%+d' "$((COVERAGE - PREV_COVERAGE))")"
else
  COVER_DELTA="n/a"
fi

END_EPOCH="$(date +%s)"
DURATION="$((END_EPOCH - START_EPOCH))"

# The ledger row and the state are written first, so the trend reader sees this
# pass; the report is then allowed to quote the reader's verdict on it.
if [ ! -s "$LEDGER" ]; then
  printf 'timestamp\tmode\tfuzz_seconds\tstatus\tcorpus_before\tcorpus_after\tfound\tminimized\tcoverage\tcoverage_delta\tduration_s\tcoverage_note\n' > "$LEDGER"
fi
# The last column is the reason a coverage cell says n/a, in the pass's own
# words. Rows written before it existed leave it empty, which the reader reads as
# "did not record why" rather than guessing.
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$START_ISO" "$MODE" "$TIME" "$STATUS" "$COUNT_BEFORE" "$COUNT_AFTER" \
  "$ADDED" "$DROPPED" "$COVERAGE" "$COVER_DELTA" "$DURATION" "$COVERAGE_NOTE" >> "$LEDGER"

{
  printf 'timestamp=%s\n' "$START_ISO"
  printf 'epoch=%s\n' "$END_EPOCH"
  printf 'status=%s\n' "$STATUS"
  printf 'corpus=%s\n' "$COUNT_AFTER"
  printf 'coverage=%s\n' "$COVERAGE"
  printf 'coverage_note=%s\n' "$COVERAGE_NOTE"
  printf 'fuzz_seconds=%s\n' "$TIME"
  printf 'targets=%s\n' "$TARGETS_N"
  printf 'crashes=%s\n' "${CRASHES:-none}"
} > "$STATE"

# What no single pass can see: whether the corpus is still moving at all. A
# quiet week and a quietly broken harness look identical in one pass; they do
# not in the ledger, so the pass quotes the reader rather than guessing.
TRENDS=""
TREND_SHELL=""
if [ -f "$REPO_ROOT/scripts/fuzz-soak-trends.sh" ]; then
  if command -v sh >/dev/null 2>&1; then TREND_SHELL="sh"
  elif command -v bash >/dev/null 2>&1; then TREND_SHELL="bash"
  fi
  if [ -n "$TREND_SHELL" ]; then
    TRENDS="$(FUZZ_SOAK_LEDGER="$LEDGER" "$TREND_SHELL" \
      "$REPO_ROOT/scripts/fuzz-soak-trends.sh" --flags-only 2>/dev/null || true)"
  fi
fi

# --- 4. hand it over ---------------------------------------------------------
# The pass has said what it found; this is where that stops waiting for somebody
# to notice the working tree. A failure here is reported and never fatal: the
# haul is still in the tree, and the pass itself succeeded.
if [ "$PROPOSE_PR" -eq 1 ]; then
  propose_haul
  case "$HAUL_STATUS" in
    proposed)
      echo "fuzz-soak: haul — $HAUL_NOTE"
      if [ -n "$HAUL_RESTORE" ]; then echo "fuzz-soak: haul — $HAUL_RESTORE"; fi
      ;;
    failed) echo "fuzz-soak: haul — $HAUL_NOTE" >&2 ;;
    *) echo "fuzz-soak: haul — not proposed: $HAUL_NOTE" ;;
  esac
fi

# --- the report --------------------------------------------------------------
{
  printf '# fuzz soak — %s\n\n' "$START_ISO"
  printf -- '- **status:** %s\n' "$STATUS"
  printf -- '- fuzz: %ss per target, %s target(s)\n' "$TIME" "$TARGETS_N"
  printf -- '- took: %s (fuzz, then save + minimize + coverage)\n' "$(human "$DURATION")"
  printf -- '- raw log: %s\n' "$(basename "$RAWLOG")"
  printf -- '- corpus: %s -> %s file(s) (+%s found, -%s minimized)\n' \
    "$COUNT_BEFORE" "$COUNT_AFTER" "$ADDED" "$DROPPED"
  printf -- '- coverage: %s\n' "$(coverage_phrase "$COVERAGE" "$COVERAGE_NOTE")"
  if [ -n "$COVERAGE_NOTE" ]; then
    printf -- '- replay log: %s\n' "$(basename "$COVERLOG")"
  fi
  if [ -n "$CRASHES" ]; then
    printf -- '- **crash:** %s — the reproducer is in the corpus and was kept\n' "$CRASHES"
  fi

  printf '\n## What changed\n\n'
  if [ -z "$PREV_ISO" ]; then
    printf -- '- no earlier pass on this machine: nothing to compare against yet\n'
    printf -- '- corpus: %s file(s)\n' "$COUNT_AFTER"
    printf -- '- coverage: %s\n' "$(coverage_phrase "$COVERAGE" "$COVERAGE_NOTE")"
  else
    printf -- '- since: %s (%s ago)\n' "$PREV_ISO" "$(human "$((START_EPOCH - PREV_EPOCH))")"
    printf -- '- corpus: %s -> %s file(s) (+%s, -%s)\n' \
      "$PREV_CORPUS" "$COUNT_AFTER" "$SINCE_FOUND" "$SINCE_GONE"
    if [ "$COVERAGE" = "n/a" ]; then
      # The reason, not an arrow to nowhere: a pass that could not measure has
      # nothing to compare, and "1210 -> n/a covered block(s)" says neither why
      # nor what it means.
      printf -- '- coverage: not measured this pass — %s\n' "${COVERAGE_NOTE:-the pass did not record why}"
    else
      printf -- '- coverage: %s -> %s covered block(s) (%s)\n' \
        "$PREV_COVERAGE" "$COVERAGE" "$COVER_DELTA"
    fi
  fi
  printf -- '- crashes: %s\n' "${CRASHES:-none}"

  printf '\n## Per target\n\n| target | corpus | found | minimized |\n|---|---|---|---|\n'
  for t in $(corpus_targets); do
    printf '| %s | %s | %s | %s |\n' "$t" \
      "$(grep -c "^$t/" "$NAMES" || true)" \
      "$(comm -13 <(grep "^$t/" "$NAMES_BEFORE" || true) <(grep "^$t/" "$NAMES" || true) | wc -l)" \
      "$(comm -23 <(grep "^$t/" "$NAMES_BEFORE" || true) <(grep "^$t/" "$NAMES" || true) | wc -l)"
  done

  printf '\n## Trends across passes\n\n'
  if [ -n "$TRENDS" ]; then
    printf '```\n%s\n```\n' "$TRENDS"
  else
    # An empty flag set means exactly three things — nothing else. In particular
    # it does NOT mean coverage is still climbing: a pass can repeat the last
    # best and stay unflagged for the first FUZZ_STALL_PASSES passes.
    printf 'nothing flagged — no stall, no coverage loss, and every pass ended GREEN.\n'
  fi

  if [ "$PROPOSE_PR" -eq 1 ]; then
    printf '\n## Haul\n\n'
    case "$HAUL_STATUS" in
      proposed)
        printf -- '- branch: `%s`\n' "$HAUL_BRANCH"
        if [ -n "$HAUL_URL" ]; then printf -- '- %s\n' "$HAUL_URL"; fi
        printf -- '- %s\n' "$HAUL_NOTE"
        if [ -n "$HAUL_RESTORE" ]; then printf -- '- %s\n' "$HAUL_RESTORE"; fi
        ;;
      failed)
        printf -- '- **could not hand it over:** %s\n' "$HAUL_NOTE"
        ;;
      *)
        printf -- '- not proposed: %s\n' "$HAUL_NOTE"
        ;;
    esac
  fi

  printf '\n## Reproduce this pass\n\n```\nscripts/fuzz-smoke.sh -t %s\nscripts/fuzz-corpus.sh --save\nscripts/fuzz-soak-trends.sh\n```\n' "$TIME"
} > "$REPORT"

# The coverage harness is instrumented separately, so the profile is scratch.
rm -f "$COVER_TMP"

cat "$REPORT"
echo
if [ -n "$TRENDS" ]; then
  echo "fuzz-soak: trends (scripts/fuzz-soak-trends.sh)"
  printf '%s\n' "$TRENDS"
fi
echo "fuzz-soak: report $REPORT"
echo "fuzz-soak: ledger $LEDGER (row appended for $START_ISO)"
if [ "$STATUS" != "GREEN" ]; then
  echo "fuzz-soak: pass ended $STATUS" >&2
  exit 1
fi
exit 0
