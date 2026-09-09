# Model B — premium private remote-node + hosted-mailbox service

*The service for phone / low-power users who can't run a DERO or XMR node.
Phone holds the spore keys; the service is a BLIND courier — it relays and
stores ciphertext, never keys or plaintext. Model B preserves spore's
privacy promise for devices that can't self-host.*

## Why this exists
A phone can't run a DERO node or a Monero node. But it CAN hold its spore
keys and sign/decrypt locally. What a phone user needs from a service is:
1. a **reachable, always-on node** (to send txs / read the chain), and
2. a **hosted body mailbox** (`spore mailbox host`) that stores TTL-bound
   ciphertext and serves prekeys while the phone's `spore msg recv-e2` process
   performs E2 ratchet decryption locally.

The service hosts the body/prekey endpoint and sells access; the user's device
retains the E2 keys and performs the decryption.

## The trust model (what the operator does / doesn't see)
| Operator sees | Operator does NOT see |
|---|---|
| encrypted blobs (E2E ciphertext) | message content (never plaintext) |
| traffic patterns / timing / volume | who sent what (privacy mode blanks Sender) |
| the phone's connection IP (reduced by Tor) | keys (phone holds them) |
| body sizes (reduced by padding) | decrypted bodies |

**Hosted privacy mode (shipped):** `mailbox host -privacy` avoids recording
sender identities in the hosted log. The hosted service stores TTL-bound
ciphertext and serves prekeys; `spore msg recv-e2` performs E2 ratchet
decryption on the user's device. **Body padding (shipped):** all long bodies
pad to a fixed 1 KiB bucket, so the operator can't fingerprint message length.

## The product (tiers)
| Tier | What the phone gets | What the service runs |
|---|---|---|
| **Free/relay** | short whispers via a shared public node; a mailbox with small quota | 1-2 shared nodes + shared mailboxes |
| **Premium** | private node access (own RPC endpoint), bigger mailbox, no Sender log, body padding, relay-fabric hop | per-user node endpoint + mailbox |

Pricing framing: NOT "RPC access" (public RPC is free/commodity). The premium
is **private, authenticated remote-node + always-on mailbox access that keeps
content and (largely) metadata private** for a phone.

## Architecture (built pieces + what to add)
```
phone (Termux/Android)
   └ spore keys (local) — sign/decrypt on device
      └ -rpc <service-node>        (send txs)      [built: -rpc seam accepts any URL]
      └ mailbox host -privacy      (ciphertext + prekeys) [built: shared host]
         └ spore msg recv-e2        (E2 decrypt locally on phone)
           └ reachable over Tor/hidden service      [add: operator infra]
      └ relay-fabric hop (future)  (hide IP from a single operator) [roadmap item 3]
```

## Honest limits (say these plainly to users)
- The operator sees **that traffic happened + timing** (a tx, a poll). Model B
  is a *chosen* relay — the phone trades full self-hosting privacy for
  reachability. Content stays private; some metadata does not.
- **Tor/I2P** hides the phone's IP from the operator but adds latency.
- The **chain itself** shows tx timing/volume (ring sig hides sender on DERO).
- The full "no single operator sees who↔whom" answer is the **relay fabric +
  decoy traffic**, which is not built yet (roadmap).

## Operations checklist for a hosted node
1. Run a DERO node (already done on Hetzner) + a Monero node (done, synced).
2. Expose the wallet/node RPC to phone clients over **TLS + auth** (not plain),
   optionally behind a Tor hidden service.
3. Run **one** `spore mailbox host -users DIR` for ALL paid users (see below).
   Do NOT run the legacy `mailbox run` per user — that is one chain poller per user; the production E2 path is the shared host plus client-side `recv-e2`.
4. Do NOT log the phone's IP / connection metadata beyond what's needed.
5. Fixed body padding + Sender-blank are already the code defaults for premium.

## `mailbox host` — the multi-user service (built)

```
spore mailbox host -users /srv/spore/users \
    -listen 127.0.0.1:18443 \
    -tokens /srv/spore/tokens.json \
    -notify-file /srv/spore/notify.json \
    -chain dero -rpc http://127.0.0.1:20209/json_rpc \
    -rpc-login USER:PASSWORD
# Put Caddy/nginx in front for public TLS. 20209 is wallet RPC; 10102 is daemon RPC.
# Keep both loopback-only.
```

Every subdirectory of `-users` is one mailbox (own key, own bodies, own log),
all served from **one listener** path-routed at `/u/<name>/...`, behind **one
shared chain watcher** (`mailbox.ScanHub`).

Why it matters — the old design was one process per user, and each process
polled the chain independently. At 10k users on a 3s interval that is ~3,333
RPC/s against a single node, which fails long before RAM does.

### Measured (not estimated)

| Users in one process | Working set | OS threads |
|---|---|---|
| 2 | 15.51 MB | 14 |
| 50 | 21.02 MB | 34 |
| 200 | 24.00 MB | 22 |

- **Marginal cost: ~44 KB/user** → 10,000 users ≈ **0.43 GB**, 50,000 ≈ 2.1 GB.
- One-process-per-user measured 5.23 MB each → 10k ≈ **51 GB**. The hub is a
  **~118× density gain**.
- **OS threads do not grow with user count** (22 at 200 users). Users are
  goroutines, so the old "10k × 4 threads = 40,000 threads" ceiling is gone.
- **Chain RPC is flat**: the hub's scaling test measures 8 polls for 1
  subscriber and 9 polls for 50 in the same window. 10k users still poll once.
- Verified live: **200/200 users served HTTP 200**, and **0 cross-token leaks**
  across 29 wrong-token probes (each returned 401).

### Per-user auth
`-tokens` is a JSON map `{"alice":"...","bob":"..."}`. Each user's route is
wrapped with that user's own bearer token, so alice's token cannot read bob's
mailbox. A user absent from the map gets an **open** route, which is refused
outright on a non-loopback bind.

### Per-user burn
`-auto-burn` is applied **per subscriber**, never at the hub: a slot is erased
only after *that* user accepts a delivery. Hub-level auto-burn would let the
first user's acceptance destroy the payload before the others ever saw it, so
the hub forces `AutoBurn=false` on the shared watcher regardless of the flag.

## What's built vs to-build
- ✅ `-rpc URL` seam accepts a remote node (any URL)
- ✅ hosted `mailbox host` (always-on ciphertext/prekey service with one shared watcher)
- ✅ `mailbox host -privacy` (no Sender in hosted log; E2 decrypt remains client-side)
- ✅ body padding (fixed 1 KiB bucket)
- ✅ `mailbox host`: N mailboxes, 1 process, 1 shared watcher, 1 listener,
  per-user bearer auth, shared reaper (44 KB/user measured)
- ✅ optional email/SMS/webhook arrival bridge (`-notify-file`); alerts contain
  only pending-message metadata, never ciphertext or plaintext
- 🔲 provisioning + billing (create/suspend a user, meter usage)
- 🔲 Tor/I2P front for the node/mailbox endpoints
- 🔲 relay-fabric hop + decoy traffic (the deep metadata answer)

## Summary
Model B is a real, buildable service and the architecture already leans into
it. The phone is a thin key-holder; the service is a blind, always-on courier.
Privacy mode + body padding (just shipped) cut the operator's metadata. The
remaining work is operations (provisioning/auth/billing) and the deeper
relay-fabric metadata hardening when the network is big enough to support it.
