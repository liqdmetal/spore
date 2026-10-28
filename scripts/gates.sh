#!/bin/bash -eu
# Run the full pre-push gate suite locally: everything CI checks, without CI.
#
#   usage: scripts/gates.sh [--quick] [spore-checkout] [spore-peer-checkout]
#
# Both arguments are optional. The spore checkout defaults to the repo this
# script lives in. The spore-peer checkout defaults to SPORE_PEER_DIR, then a
# sibling `spore-peer` directory, then `_review_tmp/spore-peer`; if none
# exists the spore-peer gates are skipped with a loud note. (The layout
# assumption: a checkout root containing the `spore` repo and — optionally —
# a `spore-peer` checkout either as a sibling or under `_review_tmp/`.)
#
# --quick skips the spore-peer (Rust) gates, the -race + cross-binary interop
# run, and the fuzz-smoke timing itself for fast inner-loop feedback;
# everything else (the credential-guard check, gofmt/goimports,
# build+vet+test, doc-refs, the fuzz-smoke target list) still runs. It
# complements the full suite — a push is still gated by the full run, never
# by --quick.
#
# Every gate prints its duration when it finishes, and a slowest-first
# timing table prints before the final banner — slow gates are visible at
# a glance, not buried in total runtime.
#
# Timings are also appended to a CSV so gate latency can be tracked over
# time: one row per gate per run (including failed gates), long format:
#
#   timestamp,mode,spore_sha,peer_sha,gate,duration_ms,status
#
# Default location: .gate-timings.csv in the spore repo root (gitignored).
# Override with GATE_TIMINGS_CSV=<path>, or disable with GATE_TIMINGS_CSV=off.
#
# The summary also flags any gate slower than GATE_SLOW_RATIO (default 2)
# times its historical median from prior rows of the CSV — this machine's
# own baseline, never the run being judged. Informational only: a slow-but-
# green run still exits 0. A gate needs >= 3 prior samples before its
# median is trusted; gate labels are compared across quick and full modes.
#
# Only one run may be in flight per checkout: the script takes an exclusive
# lock (a directory, .gate-run.lock, gitignored) and a second run waits its
# turn, saying who it is waiting for. Two suites at once is not hypothetical —
# the timing log shows one starting at 04:30:35 while an earlier run was still
# fuzzing — and it is what makes `go build ./...` / `go vet ./...` read as
# 4-5x slow, because both are CPU-bound and both run first, so they absorb
# whatever else the box is doing: a warm `go build ./...` takes 1.5s on an
# idle machine and 15.4s with every core busy (measured 2026-10-28). The lock
# cannot help against load from outside spore; it stops spore from being that
# load for itself. A run that dies uncleanly leaves the lock behind, so each
# gate touches a beat file and a beat older than GATE_LOCK_STALE_MIN (default
# 15 minutes; the longest single gate is ~6) is taken over rather than
# wedging pushes. GATE_LOCK=off skips the wait entirely.
#
# The -race gate needs cgo, and cgo needs a C compiler. Where PATH has none the
# gate looks for a Windows mingw-w64 install itself (MSYS2 ucrt64/mingw64,
# scoop, TDM-GCC, MinGW) instead of dying with go's "requires cgo" line, which
# names the wrong cause and suggests no fix. Finding nothing is a FAILURE, not
# a skip. Exit code is 0 only if every gate that ran passed; skips are printed,
# not hidden.
#
# NOTE: the flags are set explicitly below rather than trusted to the
# shebang — shebang flags are silently dropped when the script is invoked as
# `bash scripts/gates.sh`, and an -e-less gate script would report success
# after a failed gate.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

QUICK=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    *) ARGS+=("$a") ;;
  esac
done

SPORE_DIR="${ARGS[0]:-$SELF_DIR/..}"
SPORE_DIR="$(cd "$SPORE_DIR" && pwd)"
MODE_CSV=full
[ "$QUICK" -eq 1 ] && MODE_CSV=quick

if [ "$QUICK" -eq 1 ]; then PEER_DIR=""   # quick mode never enters the Rust gates
elif [ -n "${ARGS[1]:-}" ]; then PEER_DIR="${ARGS[1]}"
elif [ -n "${SPORE_PEER_DIR:-}" ]; then PEER_DIR="$SPORE_PEER_DIR"
elif [ -d "$SPORE_DIR/../spore-peer" ]; then PEER_DIR="$SPORE_DIR/../spore-peer"
elif [ -d "$SPORE_DIR/../_review_tmp/spore-peer" ]; then PEER_DIR="$SPORE_DIR/../_review_tmp/spore-peer"
else PEER_DIR=""; fi

# ---- timing helpers --------------------------------------------------------
# Millisecond clock with a fallback for `date` implementations that lack %N
# (they emit a literal 'N', which fails the all-digits test below).
now_ms() {
  t=$(date +%s%N 2>/dev/null)
  case "$t" in
    ''|*[!0-9]*) echo $(( $(date +%s) * 1000 )) ;;
    *) echo "${t:0:13}" ;;
  esac
}

fmt_ms() {
  ms=$1
  if [ "$ms" -ge 60000 ]; then
    printf '%dm%ds' $(( ms / 60000 )) $(( (ms % 60000) / 1000 ))
  elif [ "$ms" -ge 1000 ]; then
    printf '%d.%ds' $(( ms / 1000 )) $(( (ms % 1000) / 100 ))
  else
    printf '%dms' "$ms"
  fi
}

# ---- CSV latency log -------------------------------------------------------
# Long format, one row per gate per run, appended as each gate finishes (so
# even a run that fails mid-way records the gates that completed). Raw
# integer duration_ms keeps the file analysis-friendly.
if [ "${GATE_TIMINGS_CSV:-}" = "off" ] || [ "${GATE_TIMINGS_CSV:-}" = "0" ]; then
  CSV_PATH=""
elif [ -n "${GATE_TIMINGS_CSV:-}" ]; then
  CSV_PATH="$GATE_TIMINGS_CSV"
else
  CSV_PATH="$SPORE_DIR/.gate-timings.csv"
fi
GATE_SLOW_RATIO="${GATE_SLOW_RATIO:-2.0}"

# ---- one run at a time -----------------------------------------------------
# mkdir is atomic on NTFS and POSIX alike, which makes a directory a lock that
# needs no flock(1). The stale-beat rule exists because a hard-killed run (a
# scheduled task stopped mid-flight, a closed window) would otherwise block
# every later push until somebody found the directory.
LOCK_DIR="$SPORE_DIR/.gate-run.lock"
GATE_LOCK_STALE_MIN="${GATE_LOCK_STALE_MIN:-15}"
LOCK_HELD=0

# lock_beat stamps the CURRENT time into the beat file. It must be a timestamp,
# not an empty touch: an empty file reads as age 0 from the epoch, which looks
# like a lock abandoned 30 million minutes ago — the first version of this did
# exactly that and a waiting run "took over" a live lock (caught by test,
# 2026-10-28).
lock_beat() {
  [ "$LOCK_HELD" -eq 1 ] || return 0
  date +%s > "$LOCK_DIR/beat" 2>/dev/null || true
  return 0
}

release_lock() {
  [ "$LOCK_HELD" -eq 1 ] || return 0
  # Only remove the lock while it still names this process: a run that had its
  # lock taken over as stale must not delete the new owner's directory on exit.
  if [ "$(cat "$LOCK_DIR/pid" 2>/dev/null || echo '')" = "$$" ]; then
    rm -rf "$LOCK_DIR" 2>/dev/null || true
  fi
  LOCK_HELD=0
}

acquire_lock() {
  [ "${GATE_LOCK:-on}" = "off" ] && return 0
  local waited=0 last_beat beat_age v f
  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    last_beat=0
    for f in beat started; do
      v=$(cat "$LOCK_DIR/$f" 2>/dev/null || true)
      case "$v" in ''|*[!0-9]*) continue ;; esac
      last_beat=$v
      break
    done
    # No stamp yet: either the owner is between mkdir and its first write (the
    # window is microseconds) or the directory was never finished. The
    # directory's own mtime covers both — mkdir sets it — so a fresh one waits
    # and an abandoned empty one still ages out instead of wedging pushes.
    if [ "$last_beat" -eq 0 ]; then
      last_beat=$(stat -c %Y "$LOCK_DIR" 2>/dev/null || echo 0)
      case "$last_beat" in ''|*[!0-9]*) last_beat=0 ;; esac
    fi
    beat_age=$(( $(date +%s) - last_beat ))
    if [ "$beat_age" -gt $(( GATE_LOCK_STALE_MIN * 60 )) ]; then
      echo "gates: taking over a stale run lock ($(( beat_age / 60 ))m since its last gate finished)"
      rm -rf "$LOCK_DIR" 2>/dev/null || true
      continue
    fi
    if [ "$waited" -eq 0 ]; then
      echo "gates: another run is in progress (pid $(cat "$LOCK_DIR/pid" 2>/dev/null || echo '?'), started $(cat "$LOCK_DIR/started_at" 2>/dev/null || echo '?'))"
      echo "gates: waiting — two suites at once is what makes build/vet read as 4-5x slow"
    fi
    sleep 5
    waited=$((waited + 5))
  done
  # started goes first: it is the stamp a waiter falls back to when beat is
  # still empty, so writing it last would leave a window of "no stamp at all".
  printf '%s\n' "$(date +%s)" > "$LOCK_DIR/started"
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$LOCK_DIR/started_at"
  : > "$LOCK_DIR/beat"
  LOCK_HELD=1
  trap release_lock EXIT
  trap 'release_lock; exit 130' INT
  trap 'release_lock; exit 143' TERM
}

csv_init() {
  [ -n "$CSV_PATH" ] || return 0
  # Header when the file is missing OR empty (a zero-byte file is not a log).
  [ -s "$CSV_PATH" ] || printf 'timestamp,mode,spore_sha,peer_sha,gate,duration_ms,status\n' > "$CSV_PATH"
}

csv_row() {  # csv_row GATE DURATION_MS STATUS
  [ -n "$CSV_PATH" ] || return 0
  printf '%s,%s,%s,%s,"%s",%s,%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MODE_CSV" "${SPORE_SHA:--}" "${PEER_SHA:--}" \
    "$1" "$2" "$3" >> "$CSV_PATH"
}

TIMINGS=""

# run_gate LABEL CMD... — run CMD, print its duration, remember it for the
# end-of-run table, and exit with CMD's status on failure (so a failing gate
# still reports how long it ran before it died).
run_gate() {
  label=$1; shift
  printf -- '-- %s ...\n' "$label"
  lock_beat
  t0=$(now_ms)
  rc=0
  "$@" || rc=$?
  dt=$(( $(now_ms) - t0 ))
  lock_beat
  TIMINGS="${TIMINGS}${dt} ${label}
"
  printf -- '-- %s — %s\n' "$label" "$(fmt_ms "$dt")"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL $label (exit $rc)"
    csv_row "$label" "$dt" fail
    exit "$rc"
  fi
  csv_row "$label" "$dt" ok
}

check_gofmt() {
  UNFMT="$(gofmt -l .)"
  if [ -n "$UNFMT" ]; then
    echo "unformatted files:"
    echo "$UNFMT"
    return 1
  fi
}

check_goimports() {
  UNIMP="$(goimports -l .)"
  if [ -n "$UNIMP" ]; then
    echo "files needing import fixes:"
    echo "$UNIMP"
    return 1
  fi
}

# cmd/spore is included for the F2 cross-binary fabric test
# (TestFabricSubscribeCrossBinary): real Rust relay + real `spore fabric
# subscribe` binary; it self-skips when SPORE_PEER_BIN is absent, so the
# plain -race pass on a machine without the spore-peer checkout stays green.
RACE_PKGS="./internal/store ./internal/peerstore ./cmd/spore"

# ---- C toolchain for -race -------------------------------------------------
# `go test -race` needs cgo, and cgo needs a C compiler. Windows is where this
# bites: git hands a hook the environment of whatever launched the push — an
# IDE client, a task runner, a bare bash — so a machine with a perfectly good
# mingw-w64 installed still fails in 68 ms with
#   go: -race requires cgo; enable cgo by setting CGO_ENABLED=1
# which names the wrong thing (cgo is on; the compiler is merely not on PATH)
# and suggests no fix. Real case 2026-10-26: the first push whose gates
# actually ran on this machine died exactly there, with mingw present at
# /c/msys64/mingw64/bin the whole time.
#
# So the gate looks for a compiler itself and prints the one it used. A
# missing compiler is still a FAILURE, never a skip: a gate that cannot run
# has verified nothing.
CC_USED=""

# _cc_candidates — Windows keeps a mingw-w64 gcc outside PATH by default.
# MSYS2 first (what Go's own Windows docs use), current ucrt64 prefix before
# the older mingw64 one; D: is included because MSYS2 is often installed there.
_cc_candidates() {
  cat <<EOF
${MINGW_PREFIX:-}
${MSYS2_ROOT:-/c/msys64}/ucrt64/bin
${MSYS2_ROOT:-/c/msys64}/mingw64/bin
${MSYS2_ROOT:-/d/msys64}/ucrt64/bin
${MSYS2_ROOT:-/d/msys64}/mingw64/bin
$HOME/scoop/apps/gcc/current/bin
/c/TDM-GCC-64/bin
/c/mingw64/bin
/c/MinGW/bin
/c/ProgramData/mingw64/mingw64/bin
/c/Program Files/mingw64/bin
EOF
}

# find_c_toolchain — true when a C compiler is reachable, adding its directory
# to PATH when it was found off-PATH. Sets CC_USED.
find_c_toolchain() {
  # An explicit CC is a decision, not a hint: keep it, and fail loudly rather
  # than quietly compiling with something the user did not choose.
  if [ -n "${CC:-}" ]; then
    if command -v "$CC" >/dev/null 2>&1; then
      CC_USED="$(command -v "$CC")"
      return 0
    fi
    echo "CC=$CC is set but not on PATH — refusing to pick a different compiler." >&2
    return 1
  fi
  if command -v gcc >/dev/null 2>&1; then
    CC_USED="$(command -v gcc)"
    return 0
  fi
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) ;;
    *) return 1 ;;   # elsewhere a missing compiler is what PATH says it is
  esac
  local d
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    if [ -x "$d/gcc.exe" ]; then
      PATH="$d:$PATH"
      export PATH
      CC_USED="$d/gcc.exe"
      return 0
    fi
  done < <(_cc_candidates)
  return 1
}

check_race() {
  if ! find_c_toolchain; then
    cat >&2 <<'EOF'
-race needs cgo, and cgo needs a C compiler — none was found.
  Windows (MSYS2, what Go's docs use):
      pacman -S mingw-w64-ucrt-x86_64-gcc     # installs into C:\msys64\ucrt64\bin
    this gate checks there, mingw64, scoop, TDM-GCC and MinGW with no PATH
    edit; if yours is elsewhere, set CC to its gcc.
  Debian/Ubuntu:  sudo apt install gcc
  Fedora:         sudo dnf install gcc
  macOS:          xcode-select --install
A gate that cannot run has verified nothing, so this fails the push. For a
single push the documented escape hatches still apply (--no-verify,
LEFTHOOK=0).
EOF
    return 1
  fi
  # cgo disabled explicitly makes the detector impossible to build; the gate's
  # purpose is the detector, so turn it on for this run and say so.
  if [ "$(go env CGO_ENABLED)" = "0" ]; then
    echo "-race: CGO_ENABLED=0 in the environment — enabling cgo for this gate"
    export CGO_ENABLED=1
  fi
  echo "-race: cgo via $CC_USED"
  if [ -n "$PEER_BIN" ]; then
    SPORE_PEER_BIN="$PEER_BIN" go test -race -count=1 $RACE_PKGS
  else
    go test -race -count=1 $RACE_PKGS
  fi
}

# ---- credential guard ------------------------------------------------------
# scripts/git-credential-guard.sh wraps GCM so a credential-store ambiguity
# fails a push in a second instead of hanging it on an account picker no
# terminal can answer. It protects only a clone whose helper list routes
# through it — .git/config is not versioned, so a fresh clone inherits plain
# `manager` — which is why this gate runs FIRST: a push from a clone that
# never armed the guard is refused before the expensive gates spend their
# minutes, and the fix is one command.
#
# Skipped, loudly, where the guard cannot matter: no git-credential-manager on
# PATH (SSH-key and other-helper machines never make the GCM query the guard
# exists for), or an origin that is not https (git never consults the helper
# at all). Both are printed, never silent.
check_cred_guard() {
  gcm="${GIT_CRED_GUARD_GCM:-git-credential-manager}"
  if ! command -v "$gcm" >/dev/null 2>&1; then
    echo "credential guard: $gcm not on PATH — nothing to wrap, skipped"
    return 0
  fi

  # The URL a push ACTUALLY uses — `git remote get-url --push` applies the
  # url.<base>.insteadOf / pushInsteadOf rewrites, which on this machine (and
  # any box with the global rule) turn a stored `git@github.com:` remote into
  # https. Reading raw remote.origin.url here called this clone "ssh" while
  # its pushes were going through GCM.
  url="$(git remote get-url --push origin 2>/dev/null || true)"
  case "$url" in
    https://*) ;;
    *)
      echo "credential guard: push URL is not https (${url:-none}) — helper unused, skipped"
      return 0
      ;;
  esac

  # Effective helper list under git's own rule: an empty value RESETS the
  # list, which is exactly how --install discards an inherited global
  # `manager` before adding the guard. Reading the raw values without
  # applying that rule would call an unarmed clone armed.
  effective="$( { git config --get-all credential.helper 2>/dev/null || true; } | awk '
    { if ($0 == "") { n = 0; delete l; next } l[++n] = $0 }
    END { for (i = 1; i <= n; i++) print l[i] }')"

  helper="$(printf '%s\n' "$effective" | grep -F 'git-credential-guard.sh' | tail -1 || true)"
  if [ -z "$helper" ]; then
    cat >&2 <<EOF
credential guard NOT armed for this clone — a push here would hand GCM a
username-less query, the exact call that hangs forever once two GitHub
accounts are stored. Arm it once (nothing is stored outside .git/config):

  scripts/git-credential-guard.sh --install            # this clone
  scripts/git-credential-guard.sh --install --global   # every repo

or arm this clone's hooks and its guard together with one command:

  scripts/setup.sh

If the guard is unwanted here, remove GCM from PATH or push over ssh — this
gate skips where the helper cannot be consulted (see scripts/gates.sh).
EOF
    return 1
  fi

  # The configured path must still exist: a moved or deleted script leaves
  # every push failing at auth time with git's own "cannot run" and no hint.
  path="${helper#!}"
  path="${path%\"}"
  path="${path#\"}"
  if [ ! -f "$path" ]; then
    echo "credential guard: configured helper no longer exists: $path" >&2
    echo "  re-run scripts/git-credential-guard.sh --install" >&2
    return 1
  fi

  # Git runs a `!` helper as a shell command, so the script must carry the
  # executable bit where that exists: on POSIX a 100644 checkout made every
  # push die with "Permission denied" while the config still looked armed.
  # (On Windows this is always true — MSYS reports every file executable.)
  if [ ! -x "$path" ]; then
    echo "credential guard: helper is not executable: $path" >&2
    echo "  chmod +x \"$path\"   (the mode is versioned: commit it)" >&2
    return 1
  fi

  echo "credential guard: armed ($helper)"
}

# ---- gates -----------------------------------------------------------------
echo "== pre-push gates =="
echo "spore: $SPORE_DIR"

cd "$SPORE_DIR"

SPORE_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo -)"
csv_init
# Snapshot of the log BEFORE this run appends anything: the slow-gate check
# must judge this run against history, not against itself.
PRE_ROWS=0
if [ -n "$CSV_PATH" ] && [ -f "$CSV_PATH" ]; then
  PRE_ROWS=$(( $(wc -l < "$CSV_PATH") ))
fi

acquire_lock

run_gate 'credential guard' check_cred_guard

run_gate gofmt check_gofmt

if command -v goimports >/dev/null 2>&1; then
  run_gate goimports check_goimports
else
  echo "goimports: not installed — skipped (gofmt covers formatting)"
fi

run_gate 'go build ./...' go build ./...

run_gate 'go vet ./...' go vet ./...

run_gate 'go test ./...' go test ./...

PEER_BIN=""
if [ "$QUICK" -eq 1 ]; then
  echo
  echo "== quick mode: spore-peer gates skipped (--quick) =="
elif [ -n "$PEER_DIR" ] && [ -d "$PEER_DIR" ]; then
  PEER_DIR="$(cd "$PEER_DIR" && pwd)"
  cd "$PEER_DIR"
  PEER_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo -)"
  echo
  echo "== spore-peer gates ($PEER_DIR) =="

  run_gate 'cargo build' cargo build --locked
  run_gate 'cargo fmt --check' cargo fmt --check
  run_gate 'cargo clippy -D warnings' cargo clippy --locked --all-targets -- -D warnings
  run_gate 'cargo test' cargo test --locked

  # Real-binary fabric smoke: tests/fabric_smoke.rs drives the ACTUAL
  # `spore-peer serve -fabric` binary over a live socket (freg/fput/fpop +
  # hard-kill restart). The Rust unit tests call handle_client in-process,
  # so a broken main() flag path or serve loop passes them all — this smoke
  # is what fails pre-push instead of shipping.
  if [ -x target/debug/spore-peer ]; then
    PEER_BIN="$PEER_DIR/target/debug/spore-peer"
    run_gate 'fabric serve smoke' cargo test --locked --test fabric_smoke
  fi
else
  echo
  echo "== spore-peer: checkout not found (${PEER_DIR:-none}) — spore-peer gates skipped =="
fi

cd "$SPORE_DIR"

if [ "$QUICK" -eq 1 ]; then
  echo
  echo "== quick mode: -race + cross-binary interop skipped (--quick) =="
elif [ -n "$PEER_BIN" ]; then
  echo
  echo "== go test -race + cross-binary interop (SPORE_PEER_BIN=$PEER_BIN) =="
  run_gate '-race + cross-binary interop' check_race
else
  echo
  echo "== go test -race (no spore-peer binary — interop tests will skip) =="
  run_gate '-race' check_race
fi

echo
echo "== local fuzz smoke: the wirefuzz + ratchetwire targets, short -fuzztime =="
# The fuzz targets lost their runner when the workflows (and ClusterFuzzLite)
# were deleted, so the pre-push gate is the only place they run now. Full mode
# fuzzes each target for a few seconds; --quick only proves the target list
# still resolves, keeping the inner loop fast while a renamed target still
# fails a push. TestFuzzSmokeListsEveryTarget checks the list against the code
# in `go test ./...`, which both modes run.
if [ "$QUICK" -eq 1 ]; then
  run_gate 'fuzz smoke (target list)' bash scripts/fuzz-smoke.sh --check
else
  run_gate 'fuzz smoke' bash scripts/fuzz-smoke.sh
fi

echo
echo "== doc-refs checker =="
run_gate 'doc-refs checker' bash .github/actions/doc-refs/verify_doc_refs.sh

echo
echo "== release-designs release-prep set (in-tree; every pointer resolves) =="
run_gate 'release-designs check' bash scripts/release-designs-check.sh

echo
echo "== release surfaces carry no rehearsal marker (synthetic values must never ship) =="
run_gate 'release placeholder sweep' bash scripts/release-placeholders.sh --quiet

echo
echo "== tag-message draft: strip marker intact, no stale scratch copy =="
run_gate 'release tag-message check' bash scripts/release-tag-message.sh

echo
echo "== tag-message rehearsal: fill nine fields from a receipt, strip, sign, verify =="
# The tag is the one release artifact nothing else reads — the receipt gate reads
# the docs, the sweep reads the release surfaces, this reads the tag body — and a
# tag is immutable once pushed. --self-check fills the REAL draft from a
# deliberately synthetic receipt, strips it with the shipped pass, checks the body
# independently, signs a throwaway tag, and requires git verify-tag to accept it.
# No toolchain beyond git+ssh-keygen (~2s), so it runs on every push: a draft edit
# between now and release day must fail a push, not the only run that matters.
run_gate 'release tag-message rehearsal' bash scripts/release-tag-rehearsal.sh --self-check -s

echo
echo "== release-day rehearsal (frozen passes applied to a scratch tree) =="
# --quick only confirms the patch still applies; the full rehearsal also runs
# the referee twice (flipped -> green, registry removed -> red), ~1m, which is
# exactly the kind of gate --quick exists to keep out of the inner loop.
if [ "$QUICK" -eq 1 ]; then
  run_gate 'release-day rehearsal (apply check)' bash scripts/release-day-rehearsal.sh --check
else
  run_gate 'release-day rehearsal' bash scripts/release-day-rehearsal.sh
fi

echo
echo "== local Anvil two-party EVM proof (self-skips when foundry is absent) =="
# -r makes the proof write the receipt release day consumes (and have it checked
# against release-fill.sh's own rules), so the artifact is produced — not typed —
# on every push. Nothing is written inside the repo: it is a scratch file whose
# values are anvil's, which release-fill.sh refuses without --local-proof.
run_gate 'anvil E2E proof' bash scripts/anvil_e2e.sh -s -r "${TMPDIR:-/tmp}/spore-anvil-receipt.txt"

echo
echo "== Base Sepolia rehearsal: its burn-recovery wiring, on a throwaway local anvil =="
# The rehearsal itself needs two faucet-funded keys, so the step that reads the
# burn txid back off the chain — and the receipt line that carries it — would
# otherwise never be executed by anything but release day. --self-check starts
# its own anvil, puts a burn and its near misses on a real chain, and requires
# the recovery step to name exactly that burn and refuse every variant. Foundry
# only, ~10s, and -s turns a missing anvil into a skip rather than a silent pass.
run_gate 'sepolia rehearsal self-check' bash scripts/sepolia_rehearsal.sh --self-check -s

echo
echo "== release fill: every marker anchor still resolves (no values needed) =="
# The frozen patches ship markers, and release day replaces them from a receipt
# values file. Cheap half of the pair below: this only proves each marker's
# anchor still resolves, so a doc edit that moves a line out from under the
# patches fails here in milliseconds instead of on deployment day.
run_gate 'release fill anchors' bash scripts/release-fill.sh --check

echo
echo "== release fill rehearsal (real anvil deployment; self-skips without foundry) =="
# The fill is the one release step nothing else exercises. Both frozen patches
# are markers-only, and until now nothing had shown that filling every marker
# actually CLEARS the sweep and keeps the referee green — only that the sweep
# still flags the unfilled tree. This one deploys the pinned bytecode to a local
# anvil, measures with the runbook's own `spore contract estimate`, fills a
# scratch tree from those real values, and requires both. It needs foundry, so
# -s turns a missing tool into a skip — never a silent pass. --quick keeps it
# out of the inner loop (it deploys, then runs the referee twice, ~40s) and
# leans on the anchor check above for the cheap half.
if [ "$QUICK" -eq 1 ]; then
  echo "-- release fill rehearsal — skipped (--quick)"
else
  run_gate 'release fill rehearsal' bash scripts/release-fill-rehearsal.sh -s
fi

# ---- summary ---------------------------------------------------------------
if [ -n "$TIMINGS" ]; then
  echo
  echo "== gate timings (slowest first) =="
  printf '%s' "$TIMINGS" | sort -rn | while IFS=' ' read -r ms label; do
    printf '  %8s  %s\n' "$(fmt_ms "$ms")" "$label"
  done
fi

# ---- slow-gate check: this run vs this machine's own history ---------------
if [ -n "$CSV_PATH" ] && [ "$PRE_ROWS" -ge 2 ]; then
  HIST=$(head -n "$PRE_ROWS" "$CSV_PATH" | awk -F',' '
    NR > 1 {
      g = $5; gsub(/^"|"$/, "", g)
      c[g]++
      v[g "," c[g]] = $6 + 0
    }
    END {
      for (g in c) {
        if (c[g] < 3) continue            # a median needs >= 3 samples
        k = 0
        for (i = 1; i <= c[g]; i++) buf[k++] = v[g "," i]
        for (i = 0; i < k - 1; i++)       # insertion sort; k is small
          for (j = i + 1; j < k; j++)
            if (buf[j] < buf[i]) { t = buf[i]; buf[i] = buf[j]; buf[j] = t }
        m = (k % 2) ? buf[int(k / 2)] : int((buf[k / 2 - 1] + buf[k / 2]) / 2)
        printf "%d\t%s\n", m, g
      }
    }')

  checked=0; flagged=0; MIN_RATIO=""; MIN_GATE=""
  while read -r dt label; do
    [ -n "$label" ] || continue
    med=$(printf '%s\n' "$HIST" | awk -F'\t' -v g="$label" '$2 == g {print $1; exit}')
    [ -n "$med" ] || continue
    checked=$((checked + 1))
    ratio=$(awk -v d="$dt" -v m="$med" 'BEGIN { printf "%.2f", d / m }')
    # The least-inflated gate is the run's floor: contention pads every gate,
    # a real regression pads one. Keep the floor so the summary can tell the
    # two apart instead of blaming the gate that happened to be CPU-bound.
    if [ -z "$MIN_RATIO" ] || awk -v a="$ratio" -v b="$MIN_RATIO" 'BEGIN { exit !(a < b) }'; then
      MIN_RATIO=$ratio; MIN_GATE=$label
    fi
    if awk -v d="$dt" -v m="$med" -v r="$GATE_SLOW_RATIO" 'BEGIN { exit !(d > m * r) }'; then
      flagged=$((flagged + 1))
      printf '  SLOW: %s — %s vs median %s (%.2fx baseline)\n' \
        "$label" "$(fmt_ms "$dt")" "$(fmt_ms "$med")" "$ratio"
    fi
  done <<TIMINGS
$TIMINGS
TIMINGS

  if [ "$flagged" -gt 0 ]; then
    echo "slow-gate check: $flagged gate(s) anomalously slow for this machine (see SLOW above)"
    # A busy box is not a regression. When even the cheapest gate — the one no
    # source change can touch — ran well over its median (measured 2026-10-28:
    # a warm `go build ./...` is 1.5s idle and 15.4s with every core busy),
    # every gate in the run is padded and SLOW says nothing about the code.
    if awk -v m="$MIN_RATIO" 'BEGIN { exit !(m >= 1.5) }'; then
      echo "  above: the whole run was inflated ($MIN_GATE, the least affected gate, was ${MIN_RATIO}x its median) — this reads as a busy machine, not a slower gate"
    fi
  elif [ "$checked" -gt 0 ]; then
    echo "slow-gate check: no anomalies ($checked gate(s) vs history)"
  else
    echo "slow-gate check: skipped (insufficient history — a median needs >= 3 prior runs)"
  fi
fi

MODE=""
if [ "$QUICK" -eq 1 ]; then MODE=" (quick)"; fi

echo
echo "ALL GATES GREEN${MODE} — spore@$SPORE_SHA"
if [ -n "$PEER_BIN" ]; then
  echo "              spore-peer@$PEER_SHA"
fi

if [ -n "$CSV_PATH" ]; then
  rows=$(( $(wc -l < "$CSV_PATH") - 1 ))
  echo "gate latency log: $CSV_PATH ($rows rows)"
fi
