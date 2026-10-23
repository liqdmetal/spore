#!/usr/bin/env bash
# spike.sh — prove the iroh body carrier end to end: the exact "kill the
# mailbox" scenario. Two independent spore-iroh nodes, one real P2P transfer
# (BLAKE3-verified, no server in the middle), plus the honest negative cases.
#
# Usage: bash spike.sh [/path/to/iroh.exe]
set -u
BIN="${1:-$(dirname "$0")/target/release/iroh.exe}"
if [ ! -x "$BIN" ] && [ ! -f "$BIN" ]; then BIN="${1:-$(dirname "$0")/target/debug/iroh.exe}"; fi
[ -f "$BIN" ] || { echo "no built binary at $BIN — run: cargo build"; exit 2; }

W="$(mktemp -d)"
trap 'kill %1 %2 2>/dev/null; rm -rf "$W"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

echo "== 0. version probe (the Wisp seam's constructor check) =="
"$BIN" --version && ok "version probe exits 0" || bad "version probe"

echo "== 1. node A (provider) =="
SPORE_IROH_STORE="$W/A" "$BIN" blob serve > "$W/A.log" 2>&1 &
A_PID=$!
for i in $(seq 1 60); do grep -q "SPORE_IROH_PROVIDERS=" "$W/A.log" && break; sleep 0.5; done
A_ADDR="$(sed -n 's/.*SPORE_IROH_PROVIDERS=//p' "$W/A.log" | head -1 | tr -d '[:space:]')"
[ -n "$A_ADDR" ] && ok "node A online: $A_ADDR" || bad "node A did not come online (log: $(head -3 "$W/A.log"))"

echo "== 2. sender adds a body to A =="
head -c 262144 /dev/urandom > "$W/body.bin"
H="$(SPORE_IROH_STORE="$W/A" "$BIN" blob add "$W/body.bin")"
[ -n "$H" ] && ok "blob add -> hash $H" || bad "blob add returned nothing"

echo "== 3. THE TRANSFER: node B fetches from A by hash alone =="
SPORE_IROH_STORE="$W/B" SPORE_IROH_PROVIDERS="$A_ADDR" "$BIN" blob get "$H" > "$W/got.bin" 2> "$W/Bget.err"
if [ $? -eq 0 ] && cmp -s "$W/body.bin" "$W/got.bin"; then
    ok "B fetched $(wc -c < "$W/got.bin" | tr -d ' ') bytes, byte-exact  — P2P, no mailbox, no server"
else
    bad "cross-node get failed (err: $(head -2 "$W/Bget.err"))"
fi

echo "== 4. negative: a hash nobody serves =="
if SPORE_IROH_STORE="$W/B" SPORE_IROH_PROVIDERS="$A_ADDR" "$BIN" blob get "0000000000000000000000000000000000000000000000000000000000000000" >/dev/null 2>&1; then
    bad "bogus hash succeeded — must fail"
else
    ok "bogus hash rejected"
fi

echo "== 5. honest limit: provider offline => fetch fails =="
kill "$A_PID" 2>/dev/null; wait "$A_PID" 2>/dev/null
if SPORE_IROH_STORE="$W/C" SPORE_IROH_PROVIDERS="$A_ADDR" "$BIN" blob get "$H" >/dev/null 2>&1; then
    bad "fetch succeeded with provider DOWN — overclaim!"
else
    ok "fetch fails when no node serves (P2P honesty) — B still held its copy"
fi

echo "== 6. B reopens its store: the cached body is now LOCAL =="
SPORE_IROH_STORE="$W/B" "$BIN" blob get "$H" > "$W/got2.bin" 2>/dev/null
if cmp -s "$W/body.bin" "$W/got2.bin"; then
    ok "B served its CACHED copy after provider died (persistence + caching)"
else
    bad "cached copy lost after reopen"
fi

echo
echo "result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]