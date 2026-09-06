# Spore — run your own home node (the privacy default)

**The idea in one line:** your always-on home node **is** the server. Your
phone and laptop dial *your* machine — not a third party's — over TLS + token
auth. Your data, your node, no service in the middle.

There is a fallback for people with **no** home node (a phone can't run a DERO
node): the hosted Model-B service, where the phone still holds the keys and the
service is a blind courier. → [`docs/MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md).

---

## What a home node runs

| Piece | What it is | Command |
|---|---|---|
| **Chain node + wallet RPC** | your chain/block visibility (e.g. `dero-wallet-cli --rpc-server`) | e.g. `dero-wallet-cli --wallet-file mywallet.db --rpc-server --rpc-bind 0.0.0.0:20209` |
| **Mailbox** | your always-on receiver — serves + scans + decrypts long bodies | `spore mailbox run -dir ... -chain dero -rpc ... [-token SECRET] [-cert/-key]` |
| **Relay (optional)** | store-and-forward hop so your home node can also relay for the wider fabric | `spore relay run -listen ... [-dir ...] [-token SECRET]` |

---

## 1. Run the mailbox on your home node

This is the heart of it. It holds your long-term spore key, serves + scans +
decrypts long bodies headless, and stays up while your phone sleeps. Gate its
HTTP surface with a token and serve it over TLS so your phone's dial-home is
encrypted.

```bash
# your always-on mailbox — generate a key on first run, print the pubkey,
# require `Authorization: Bearer <token>` on every route, serve HTTPS:
spore mailbox run -dir /var/spore/home -chain dero \
  -rpc http://127.0.0.1:10102/json_rpc \
  -listen 0.0.0.0:19292 -token <your-secret> \
  -cert /etc/letsencrypt/live/<home>/fullchain.pem \
  -key  /etc/letsencrypt/live/<home>/privkey.pem &
```

- `-token <your-secret>` — every HTTP route requires `Authorization: Bearer
  <token>` (so the box isn't open to the internet).
- `-cert`/`-key` — serve over **HTTPS** (both must be set; get a cert via Let's
  Encrypt/certbot). No plaintext bodies over the internet.
- `-privacy` — add this to keep the sender out of the durable message log.
- First run prints your mailbox pubkey — give it to people who send you long
  bodies so they encrypt to you.

## 2. Point your phone at home

The phone holds the keys; it just can't run a chain node. So it dials *home*
for chain access and receive. **Replace `<home>`/`<port>` and the login.**

```bash
# SEND — route the tx through your home node (TLS + basic auth):
spore msg send -chain dero -rpc https://<home>:<port>/json_rpc \
  -rpc-login user:pass -to <friend-dero1...> -msg "hi"

# RECEIVE — your phone's mailbox, pointed at home so it scans and sees
# your incoming whispers; -token protects this mailbox's own HTTP surface:
spore mailbox run -dir ~/mb -chain dero \
  -rpc https://<home>:<port>/json_rpc -rpc-login user:pass \
  -token <your-secret> -cert /path/home-cert.pem &
```

`-rpc https://<home>:<port>/json_rpc` points the phone's chain access at *your*
home node; `-rpc-login user:pass` authenticates to it. Don't expose the raw
wallet RPC port to the internet — front it with TLS + auth (nginx/caddy) exactly
as in the Model-B runbook, just on your own box.

## 3. (Optional) run a relay on your home node

The same always-on box can act as a **store-and-forward relay** for the wider
fabric: peers push an opaque body to `/relay/<cid>` with `X-Relay-Dest`, the
relay holds it and retransmits to the destination mailbox. The relay only ever
holds content-addressed ciphertext and never decrypts.

```bash
spore relay run -listen :19300 -dir /var/spore/relay -token <your-secret> &
```

---

## Why this is the privacy default

- **Your server, your data.** No third party ever holds your mailbox, your
  bodies, or your connection — the home node is the only server in the path.
- **E2E by construction.** DERO encrypts payloads natively; other chains ride
  the m³ secure envelope. Even your own relay/home node sees ciphertext.
- **Compostable.** Bodies TTL-evict; what's permanent on-chain is a hash + a
  dead key.

## No home node? Use the hosted service

If you can't run a home node, Spore's **Model B** service is the fallback: a
paid service runs the node + mailbox, your phone still holds the keys, and the
service is a *blind courier* (it relays/stores ciphertext, never keys or
plaintext). → [`docs/MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md) for the model and
[`docs/MODEL_B_RUNBOOK.md`](MODEL_B_RUNBOOK.md) for provisioning.
