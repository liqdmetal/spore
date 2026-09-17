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
# --quick skips the spore-peer (Rust) gates and the -race + cross-binary
# interop run for fast inner-loop feedback; everything else (gofmt/
# goimports, build+vet+test, doc-refs) still runs. It complements the full
# suite — a push is still gated by the full run, never by --quick.
#
# Gates, in order:
#   spore       gofmt / goimports, go build ./..., go vet ./..., go test ./...
#   spore-peer  cargo build --locked, cargo fmt --check,
#               cargo clippy --locked -D warnings, cargo test --locked
#   spore       go test -race on store + peerstore — with SPORE_PEER_BIN set
#               to the freshly built Rust binary when available, so the
#               cross-binary interop tests run for real instead of skipping —
#               then the doc-refs checker over the audit pins.
#
# The -race gate needs cgo enabled (the default on most dev boxes). Exit code
# is 0 only if every gate that ran passed; skips are printed, not hidden.
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

if [ "$QUICK" -eq 1 ]; then PEER_DIR=""   # quick mode never enters the Rust gates
elif [ -n "${ARGS[1]:-}" ]; then PEER_DIR="${ARGS[1]}"
elif [ -n "${SPORE_PEER_DIR:-}" ]; then PEER_DIR="$SPORE_PEER_DIR"
elif [ -d "$SPORE_DIR/../spore-peer" ]; then PEER_DIR="$SPORE_DIR/../spore-peer"
elif [ -d "$SPORE_DIR/../_review_tmp/spore-peer" ]; then PEER_DIR="$SPORE_DIR/../_review_tmp/spore-peer"
else PEER_DIR=""; fi

echo "== pre-push gates =="
echo "spore: $SPORE_DIR"

cd "$SPORE_DIR"

UNFMT="$(gofmt -l .)"
if [ -n "$UNFMT" ]; then
  echo "FAIL gofmt — unformatted files:"
  echo "$UNFMT"
  exit 1
fi
echo "gofmt: clean"

if command -v goimports >/dev/null 2>&1; then
  UNIMP="$(goimports -l .)"
  if [ -n "$UNIMP" ]; then
    echo "FAIL goimports — files needing import fixes:"
    echo "$UNIMP"
    exit 1
  fi
  echo "goimports: clean"
else
  echo "goimports: not installed — skipped (gofmt covers formatting)"
fi

echo "-- go build ./... --"
go build ./...

echo "-- go vet ./... --"
go vet ./...

echo "-- go test ./... --"
go test ./...

PEER_BIN=""
if [ "$QUICK" -eq 1 ]; then
  echo
  echo "== quick mode: spore-peer gates skipped (--quick) =="
elif [ -n "$PEER_DIR" ] && [ -d "$PEER_DIR" ]; then
  PEER_DIR="$(cd "$PEER_DIR" && pwd)"
  cd "$PEER_DIR"
  echo
  echo "== spore-peer gates ($PEER_DIR) =="

  echo "-- cargo build --locked --"
  cargo build --locked

  echo "-- cargo fmt --check --"
  cargo fmt --check
  echo "rustfmt: clean"

  echo "-- cargo clippy --locked --all-targets -- -D warnings --"
  cargo clippy --locked --all-targets -- -D warnings
  echo "clippy: clean"

  echo "-- cargo test --locked --"
  cargo test --locked

  if [ -x target/debug/spore-peer ]; then
    PEER_BIN="$PEER_DIR/target/debug/spore-peer"
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
  SPORE_PEER_BIN="$PEER_BIN" go test -race -count=1 ./internal/store ./internal/peerstore
else
  echo
  echo "== go test -race (no spore-peer binary — interop tests will skip) =="
  go test -race -count=1 ./internal/store ./internal/peerstore
fi

echo
echo "== doc-refs checker =="
bash .github/actions/doc-refs/verify_doc_refs.sh

MODE=""
if [ "$QUICK" -eq 1 ]; then MODE=" (quick)"; fi

echo
echo "ALL GATES GREEN${MODE} — spore@$(git -C "$SPORE_DIR" rev-parse --short HEAD)"
if [ -n "$PEER_BIN" ]; then
  echo "              spore-peer@$(git -C "$PEER_DIR" rev-parse --short HEAD)"
fi
