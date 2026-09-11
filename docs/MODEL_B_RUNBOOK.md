# Model B — operator runbook (stand up a hosted mailbox + node for a phone)

*How an operator provisions a phone user a private remote node + hosted
mailbox. Phone holds keys; the service is the blind courier. Everything below
uses the shipped spore binary (v0.2.x) on a Linux box like the Hetzner node.*

## 0. What you're running (one per paid user, or shared for free tier)
1. A **node/wallet RPC** the phone's `-rpc` points at (DERO wallet RPC, or a
   chain RPC for EVM/Solana/XMR). Reuse the DERO node already on the box.
2. A **hosted body mailbox** (`spore mailbox host`) for TTL-bound ciphertext
   and prekey delivery. The phone runs `spore msg recv-e2` and decrypts locally.

Phone commands once provisioned:
```
# on the phone (Termux):
printf 'hi\n' | spore msg send -chain dero -rpc https://<your-host>:<port>/json_rpc \
  -to <friend-dero1...> -identity ~/mb/identity.key \
  -bundle ./friend-bundle.json -pinned-sig FRIEND_SIGNING_KEY_HEX \
  -store https://<your-host>/u/<user> -state-dir ~/mb/state -state-key ~/mb/state.key \
  -ringsize 16
spore msg recv-e2 -chain dero -rpc <your-rpc> -rpc-login <user:pass> \
  -store https://<your-host>/u/<user> -store-token <user-token> \
  -identity ~/mb/identity.key -spk ~/mb/spk.key -opk-pool ~/mb/opk-pool.json \
  -state-dir ~/mb/state -state-key ~/mb/state.key   # decrypt locally, secure
```

Use `-ringsize 8` instead when you want smaller DERO message transactions; Spore accepts only 8 or 16.

## 1. Provision a user (operator side)
```bash
# 1. create one subdirectory per user and a bearer-token map
MBROOT=/var/spore/users
mkdir -p "$MBROOT/$user"
# /var/spore/tokens.json: {"$user":"$TOKEN"}
# 2. run ONE shared host for all users (Caddy terminates public TLS)
spore mailbox host -users "$MBROOT" \
  -chain dero -rpc http://127.0.0.1:20209/json_rpc \
  -rpc-login USER:PASSWORD -listen 127.0.0.1:18443 \
  -tokens /var/spore/tokens.json -privacy \
  -notify-file /var/spore/notify.json &
# 20209 is the authenticated DERO wallet RPC; 10102 is daemon RPC and is not
# sufficient for mailbox scanning (get_transfers). Keep both loopback-only.
# notify.json maps users to {"email":"...","sms":"...","webhook":"..."}.
# Provider secrets/settings come from SPORE_NOTIFY_* environment variables.
# 3. publish the user's prekey batch to /u/$user/prekey-batch
spore prekeybatch push -in "$MBROOT/$user/batch.json" \
  -mailbox https://$HOST/u/$user
```

Manage the single shared host as one systemd unit so it survives reboot. Caddy
terminates public TLS and proxies to loopback; `-privacy` omits sender identity
from the hosted log. The user's phone runs `msg recv-e2` and decrypts locally.

## 2. Expose the DERO/node RPC to the phone SECURELY
Do NOT expose the raw wallet RPC port publicly. Front it with:
- **TLS** (the wallet/node behind nginx/caddy with a cert), and
- **auth** (basic/bearer) + rate limiting.
The phone's `-rpc` then points at `https://<your-host>:<tls-port>/json_rpc` and
passes `-rpc-login user:pass`.

A phone cannot run a DERO node, so this remote RPC is the ONLY way it sends.
The operator sees the tx it sends (unavoidable) but never the message content
(DERO encrypts natively; EVM/Solana/XMR ride the E2E envelope).

## 3. TLS for the mailbox
Put Caddy/nginx or another TLS edge in front of the loopback listener. The
public endpoint must be HTTPS; do not expose the mailbox or wallet RPC ports
without authentication and rate limiting. The host stores ciphertext bodies;
E2 ratchet decryption occurs in `spore msg recv-e2` on the phone.

## 4. Don't log metadata
`-privacy` omits sender identity from the hosted log. The service must not log
message plaintext, identity/SPK private keys, or unnecessary IP/UA metadata.

## 5. Billing/packaging (later)
Tier per the plan: free = shared node + small mailbox; premium = private
endpoint + bigger mailbox + privacy/padding (all shipped code). Provisioning +
billing automation is the remaining ops work (a control script / panel), not
core spore code.

## Sanity checklist
- [ ] `spore demo` runs (binary sane)
- [ ] shared `mailbox host` starts on loopback and systemd keeps it alive
- [ ] Caddy/nginx serves the public HTTPS hostname and proxies to the loopback host
- [ ] authenticated `/u/<user>/list` returns 200/JSON
- [ ] same route without or with a wrong token returns 401
- [ ] phone can `msg send` through the remote RPC (test with a real message)
- [ ] phone can `msg recv-e2` and decrypt a real message locally
