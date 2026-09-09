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
| **Mailbox** | your always-on ciphertext/prekey service; the phone runs `recv-e2` and decrypts locally | `spore mailbox host -users ... -chain dero -rpc ... [-tokens FILE]` |
| **Relay (optional)** | store-and-forward hop so your home node can also relay for the wider fabric | `spore relay run -listen ... [-dir ...] [-token SECRET]` |

---

## 1. Run the mailbox on your home node

This is the heart of it. It serves ciphertext bodies and prekeys while the
phone retains the E2 keys and runs `spore msg recv-e2` to decrypt locally. Gate
its HTTP surface with per-user tokens and serve it over TLS so the phone's
body/prekey traffic is encrypted.

```bash
# hosted ciphertext/prekey service — one shared watcher, per-user tokens:
spore mailbox host -users /var/spore/users -chain dero \
  -rpc http://127.0.0.1:20209/json_rpc -rpc-login USER:PASSWORD \
  -listen 127.0.0.1:18443 -tokens /var/spore/tokens.json \
  -privacy -notify-file /var/spore/notify.json &
# 20209 is wallet RPC; 10102 is daemon RPC and cannot serve get_transfers.
# Put TLS at Caddy/nginx and proxy the public hostname to 127.0.0.1:18443.
```

- `-tokens /var/spore/tokens.json` — maps each username to its bearer token;
  every hosted route requires `Authorization: Bearer <token>`.
- Put Caddy/nginx or another TLS edge in front of the loopback listener. Do not
  expose the raw mailbox or wallet RPC ports publicly.
- `-privacy` — keeps sender identity out of the hosted durable log.
- Publish each user's prekey batch to `/u/<user>/prekey-batch`; the phone keeps
  its identity/SPK private keys and decrypts with `spore msg recv-e2`.

## 2. Point your phone at home

The phone holds the keys; it just can't run a chain node. So it dials *home*
for chain access and ciphertext/prekey delivery. It decrypts locally with
`spore msg recv-e2`. **Replace `<home>`/`<port>` and the login.**

```bash
# SEND — route the tx through your home node (TLS + basic auth):
spore msg send -chain dero -rpc https://<home>:<port>/json_rpc \
  -rpc-login user:pass -to <friend-dero1...> -msg "hi"

# RECEIVE — the phone scans the chain and decrypts locally; the hosted/home
# mailbox is only the ciphertext + prekey store:
spore msg recv-e2 -chain dero \
  -rpc https://<home>:<port>/json_rpc -rpc-login user:pass \
  -store https://<home>/u/<user> -store-token <your-secret> \
  -identity ~/mb/identity.key -spk ~/mb/spk.key -opk-pool ~/mb/opk-pool.json \
  -state-dir ~/mb/state -state-key ~/mb/state.key
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
