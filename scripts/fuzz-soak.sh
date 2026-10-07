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
#                                [--doctor]
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
#   corpus-names.txt   the corpus the last pass left behind
#
# The ledger is also what scripts/fuzz-soak-trends.sh reads: it flags the things
# a single pass cannot see (coverage that has stopped setting new bests, passes
# that did not end GREEN), and each pass quotes those flags in its report.
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
    -h | --help)
      cat <<'USAGE'
usage: scripts/fuzz-soak.sh [--time SECONDS] [--status] [--print-schedule] [--doctor]
  --time SECONDS    fuzz seconds per target (default 60, the deep pass)
  --status          print the last report, then stop
  --print-schedule  print the scheduler incantation for this host, then stop
  --doctor          check the installed schedule can still run, then stop
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
LOCK="$SOAK_DIR/lock"

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
human() { # human SECONDS
  local s="$1"
  if [ "$s" -ge 3600 ]; then printf '%dh%dm' "$((s / 3600))" "$((s % 3600 / 60))"
  elif [ "$s" -ge 60 ]; then printf '%dm%ds' "$((s / 60))" "$((s % 60))"
  else printf '%ds' "$s"; fi
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
  printf '"%s" -lc "cd %s && %sbash scripts/fuzz-soak.sh >> %s/soak.log 2>&1"\n' \
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

if [ "$PRINT_SCHEDULE" -eq 1 ]; then print_schedule; exit 0; fi

if [ "$SHOW_DOCTOR" -eq 1 ]; then
  if doctor; then exit 0; else exit 1; fi
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

count_files() { find internal/*/testdata/fuzz/Fuzz*/ -maxdepth 1 -type f 2>/dev/null | wc -l; }
count_targets() { find internal/*/testdata/fuzz/Fuzz*/ -maxdepth 0 -type d 2>/dev/null | wc -l; }

# Covered statement blocks across the module, as the corpus replays them.
# "n/a" when the measurement cannot be taken — most often because the corpus now
# holds a reproducer, which fails the very replay being measured.
measure_coverage() {
  local pkgs=() p
  while IFS= read -r p; do pkgs+=("$p"); done < <(corpus_packages)
  if [ "${#pkgs[@]}" -eq 0 ]; then printf 'n/a'; return 0; fi
  if ! go test -coverpkg=./... -covermode=set -coverprofile="$COVER_TMP" "${pkgs[@]}" >/dev/null 2>&1; then
    printf 'n/a'
    return 0
  fi
  awk 'NR > 1 && $NF + 0 > 0' "$COVER_TMP" | wc -l
}

state_get() { # state_get KEY
  [ -f "$STATE" ] || return 0
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$STATE"
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
corpus_names > "$NAMES_BEFORE"
COUNT_BEFORE="$(count_files)"
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

COVERAGE="$(measure_coverage)"
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
  printf 'timestamp\tmode\tfuzz_seconds\tstatus\tcorpus_before\tcorpus_after\tfound\tminimized\tcoverage\tcoverage_delta\tduration_s\n' > "$LEDGER"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$START_ISO" "$MODE" "$TIME" "$STATUS" "$COUNT_BEFORE" "$COUNT_AFTER" \
  "$ADDED" "$DROPPED" "$COVERAGE" "$COVER_DELTA" "$DURATION" >> "$LEDGER"

{
  printf 'timestamp=%s\n' "$START_ISO"
  printf 'epoch=%s\n' "$END_EPOCH"
  printf 'status=%s\n' "$STATUS"
  printf 'corpus=%s\n' "$COUNT_AFTER"
  printf 'coverage=%s\n' "$COVERAGE"
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

# --- the report --------------------------------------------------------------
{
  printf '# fuzz soak — %s\n\n' "$START_ISO"
  printf -- '- **status:** %s\n' "$STATUS"
  printf -- '- fuzz: %ss per target, %s target(s)\n' "$TIME" "$TARGETS_N"
  printf -- '- took: %s (fuzz, then save + minimize + coverage)\n' "$(human "$DURATION")"
  printf -- '- raw log: %s\n' "$(basename "$RAWLOG")"
  printf -- '- corpus: %s -> %s file(s) (+%s found, -%s minimized)\n' \
    "$COUNT_BEFORE" "$COUNT_AFTER" "$ADDED" "$DROPPED"
  printf -- '- coverage: %s covered block(s) across ./...\n' "$COVERAGE"
  if [ -n "$CRASHES" ]; then
    printf -- '- **crash:** %s — the reproducer is in the corpus and was kept\n' "$CRASHES"
  fi

  printf '\n## What changed\n\n'
  if [ -z "$PREV_ISO" ]; then
    printf -- '- no earlier pass on this machine: nothing to compare against yet\n'
    printf -- '- corpus: %s file(s)\n' "$COUNT_AFTER"
    printf -- '- coverage: %s covered block(s)\n' "$COVERAGE"
  else
    printf -- '- since: %s (%s ago)\n' "$PREV_ISO" "$(human "$((START_EPOCH - PREV_EPOCH))")"
    printf -- '- corpus: %s -> %s file(s) (+%s, -%s)\n' \
      "$PREV_CORPUS" "$COUNT_AFTER" "$SINCE_FOUND" "$SINCE_GONE"
    printf -- '- coverage: %s -> %s covered block(s) (%s)\n' \
      "$PREV_COVERAGE" "$COVERAGE" "$COVER_DELTA"
  fi
  printf -- '- crashes: %s\n' "${CRASHES:-none}"

  printf '\n## Per target\n\n| target | corpus | found | minimized |\n|---|---|---|---|\n'
  for d in internal/*/testdata/fuzz/Fuzz*/; do
    [ -d "$d" ] || continue
    t="$(basename "$d")"
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
