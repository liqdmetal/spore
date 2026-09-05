# Model B — operator runbook (stand up a hosted mailbox + node for a phone)

*How an operator provisions a phone user a private remote node + hosted
mailbox. Phone holds keys; the service is the blind courier. Everything below
uses the shipped mycelium binary (v0.2.x) on a Linux box like the Hetzner node.*

## 0. What you're running (one per paid user, or shared for free tier)
1. A **node/wallet RPC** the phone's `-rpc` points at (DERO wallet RPC, or a
   chain RPC for EVM/Solana/XMR). Reuse the DERO node already on the box.
2. A **hosted mailbox** (`mycelium mailbox run -privacy`) the phone receives
   long bodies through.

Phone commands once provisioned:
```
# on the phone (Termux):
mycelium msg send -chain dero -rpc https://<your-host>:<port>/json_rpc \
  -to <friend-dero1...> -msg "hi"
mycelium mailbox run -dir ~/mb -chain dero -rpc <your-rpc> -privacy \
  -token <user-token> -cert /path/cert.pem   # receive, secure
```

## 1. Provision a user (operator side)
```bash
# 1. user's mailbox dir + key (fresh, per user)
MBROOT=/var/mycelium/users
mkdir -p "$MBROOT/$user"
# 2. run their mailbox with TLS + token, bound to their own port
mycelium mailbox run -dir "$MBROOT/$user" \
  -chain dero -rpc http://127.0.0.1:10102/json_rpc \
  -listen 0.0.0.0:$PORT -privacy -token "$TOKEN" \
  -cert /etc/letsencrypt/live/$HOST/fullchain.pem \
  -key  /etc/letsencrypt/live/$HOST/privkey.pem &
# 3. capture the mailbox pubkey (printed on first run) -> give to the phone
#    user's senders so they encrypt bodies to it.
```

Manage these as systemd units (one per user) so they survive reboot. The
`-token` they pass must match what you set; `-privacy` blanks Sender in the log.

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
Use `-cert`/`-key` (Let's Encrypt via certbot) so body pushes/receives are
encrypted in transit. No plaintext bodies over the internet.

## 4. Don't log metadata
The mailbox's durable log only holds decrypted text + txid (no Sender in
`-privacy` mode). Do not add IP/UA logging in front of it.

## 5. Billing/packaging (later)
Tier per the plan: free = shared node + small mailbox; premium = private
endpoint + bigger mailbox + privacy/padding (all shipped code). Provisioning +
billing automation is the remaining ops work (a control script / panel), not
core mycelium code.

## Sanity checklist
- [ ] `mycelium demo` runs (binary sane)
- [ ] mailbox starts, prints pubkey, serves on its TLS port
- [ ] `curl -k -H "Authorization: Bearer $TOKEN" https://host:PORT/list` returns 200/JSON
- [ ] same without token returns 401
- [ ] phone can `msg send` through the remote RPC (test with a real message)
