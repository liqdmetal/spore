#!/usr/bin/env bash
# live_e2e_soak.sh — the standing two-party live E2E + adversarial soak gate.
# Runs on the Hetzner box against the real wallet RPC + hosted mailboxes.
#
#   bash tools/live_e2e_soak.sh <spore-binary> <wallet-rpc-url> <rpc-login> <demo-token>
#
# Happy path: A -> B round trip on mainnet (pointer on chain, body via the
# hosted mailbox), decrypted locally on B. Adversarial cases must fail LOUD:
# wrong pinned sig, tampered invite, malformed push, and the host rate limit.
set -u
B="${1:?spore binary}"; RPC="${2:?wallet rpc}"; LOGIN="${3:?rpc login}"; DEMOTOK="${4:?demo token}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $1"; }
run() { "$@"; }
expect_ok()   { if "$@" >/tmp/soak.out 2>&1; then ok "$1"; else bad "$1 (see /tmp/soak.out)"; tail -3 /tmp/soak.out; fi; }
expect_fail() { if "$@" >/tmp/soak.out 2>&1; then bad "$1 (unexpectedly succeeded)"; else ok "$1"; fi; }

cd /tmp && rm -rf soak-a soak-b-state && mkdir -p soak-a soak-b-state
# state.key: a 32-byte hex file both sides can use for the session state
if [ ! -s /tmp/soak-a/state.key ]; then
  openssl rand -hex 32 > /tmp/soak-a/state.key
fi
ADDR=$(curl -s -u "$LOGIN" --max-time 20 -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"a","method":"getaddress","params":null}' "$RPC" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('result',{}).get('address',''))" 2>/dev/null)
[ -z "$ADDR" ] && ADDR=dero1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyqqhl3sy4
echo "wallet addr: $ADDR"
$B init -dir /tmp/soak-a >/dev/null 2>&1

echo "=== 1. happy path: A -> B over mainnet, decrypt on B ==="
$B invite issue -identity /tmp/qr-id/identity.key -spk /tmp/qr-id/spk.key \
  -address "$ADDR" -name demo -mailbox https://mail.sporem3.io/u/demo > /tmp/soak-invite.txt 2>&1
INVITE=$(grep -oE 'spore-invite-v1:[^ ]+' /tmp/soak-invite.txt | head -1)
if [ -z "$INVITE" ]; then
  bad "invite issue produced no URI"; tail -3 /tmp/soak-invite.txt
else
  ok "invite issued (${#INVITE} chars)"
fi
PIN=$(python3 - "$INVITE" <<'PY'
import base64, json, sys
u = sys.argv[1]
b = u.split(":", 1)[1]
try:
    pad = "=" * (-len(b) % 4)
    print(json.loads(base64.urlsafe_b64decode(b + pad))["pinned_sig"])
except Exception as e:
    print("", end="")
PY
)
echo "  pinned: ${PIN:0:16}…"
expect_ok $B msg send -chain dero -rpc "$RPC" -rpc-login "$LOGIN" -ringsize 8 \
  -to "$ADDR" -identity /tmp/soak-a/identity.key \
  -bundle-url https://mail.sporem3.io/u/demo/prekey -bundle-token "$DEMOTOK" \
  -pinned-sig "$PIN" \
  -store https://mail.sporem3.io/u/demo -relay https://relay.sporem3.io \
  -state-dir /tmp/soak-a/state -state-key /tmp/soak-a/state.key -msg-file - <<<"soak probe $(date +%s)"

echo "=== 2. B decrypts locally (pointer seen, body fetched, ratchet opens) ==="
# recv-e2 is a watch loop (no -once): run it in the background and wait for
# the mined pointer + decrypt, up to 150s.
: > /tmp/soak-recv.log
timeout 150 $B msg recv-e2 -chain dero -rpc "$RPC" -rpc-login "$LOGIN" \
  -store https://mail.sporem3.io/u/demo -store-token "$DEMOTOK" \
  -identity /tmp/qr-id/identity.key -spk /tmp/qr-id/spk.key -opk-pool /tmp/qr-id/opk-pool.json \
  -state-dir /tmp/soak-b-state -state-key /tmp/soak-a/state.key > /tmp/soak-recv.log 2>&1 &
RPID=$!
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  if grep -q "soak probe" /tmp/soak-recv.log; then FOUND=1; break; fi
done
kill $RPID 2>/dev/null
if [ -n "$FOUND" ]; then ok "B decrypted the live A->B message (pointer mined, body fetched, ratchet opened)"; else bad "no decrypt in 150s"; tail -4 /tmp/soak-recv.log; fi

echo "=== 3. wrong pinned sig must be refused loudly ==="
expect_fail $B msg send -chain dero -rpc "$RPC" -rpc-login "$LOGIN" -ringsize 8 \
  -to "$ADDR" -identity /tmp/soak-a/identity.key \
  -bundle-url https://mail.sporem3.io/u/demo/prekey -bundle-token "$DEMOTOK" \
  -pinned-sig "$(printf '0%.0s' {1..64})" \
  -store https://mail.sporem3.io/u/demo -relay https://relay.sporem3.io \
  -state-dir /tmp/soak-a/state -state-key /tmp/soak-a/state.key -msg-file - <<<"tamper"

echo "=== 4. tampered invite must fail verification ==="
# flip a character in the MIDDLE of the token (the last char is a no-op on
# some payloads — the URI may legitimately end in '0')
TAMPERED="${INVITE:0:40}9${INVITE:41}"
expect_fail $B invite verify -invite "$TAMPERED"

echo "=== 5. malformed push to the mailbox must be refused (no 500s) ==="
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  --data-binary 'not-a-real-body' --max-time 15 \
  -H "Authorization: Bearer $DEMOTOK" \
  "https://mail.sporem3.io/u/demo/put/0000000000000000000000000000000000000000000000000000000000000000")
[ "$CODE" = "400" ] && ok "malformed push -> $CODE" || bad "malformed push -> $CODE (want 400)"

echo "=== 6. host rate limit: 121 requests in <60s from one IP -> 429 ==="
RC=0; HIT=0
for i in $(seq 1 121); do
  C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://mail.sporem3.io/u/demo/list" -H "Authorization: Bearer $DEMOTOK")
  if [ "$C" = "429" ]; then HIT=1; break; fi
done
[ "$HIT" = "1" ] && ok "rate limit engaged (429 after burst)" || bad "no 429 after 121 requests"

echo
echo "soak: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ]
