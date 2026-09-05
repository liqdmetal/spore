# Model B — premium private remote-node + hosted-mailbox service

*The service for phone / low-power users who can't run a DERO or XMR node.
Phone holds the mycelium keys; the service is a BLIND courier — it relays and
stores ciphertext, never keys or plaintext. Model B preserves mycelium's
privacy promise for devices that can't self-host.*

## Why this exists
A phone can't run a DERO node or a Monero node. But it CAN hold its mycelium
keys and sign/decrypt locally. What a phone user needs from a service is:
1. a **reachable, always-on node** (to send txs / read the chain), and
2. an **always-on mailbox** (to receive long bodies / messages while offline).

That is exactly what the existing `mailbox` + `-rpc URL` seam already does. The
service = host those endpoints and sell access.

## The trust model (what the operator does / doesn't see)
| Operator sees | Operator does NOT see |
|---|---|
| encrypted blobs (E2E ciphertext) | message content (never plaintext) |
| traffic patterns / timing / volume | who sent what (privacy mode blanks Sender) |
| the phone's connection IP (reduced by Tor) | keys (phone holds them) |
| body sizes (reduced by padding) | decrypted bodies |

**Privacy mode (shipped):** `mailbox run -privacy` blanks Sender before it hits
the durable log. **Body padding (shipped):** all long bodies pad to a fixed 1
KiB bucket, so the operator can't fingerprint message length.

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
   └ mycelium keys (local) — sign/decrypt on device
      └ -rpc <service-node>        (send txs)      [built: -rpc seam accepts any URL]
      └ mailbox run -privacy       (receive long)  [built: hosted mailbox, sender-blank]
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
3. Run `mailbox run -privacy` per paid user (own dir + key), serve over HTTPS.
4. Do NOT log the phone's IP / connection metadata beyond what's needed.
5. Fixed body padding + Sender-blank are already the code defaults for premium.

## What's built vs to-build
- ✅ `-rpc URL` seam accepts a remote node (any URL)
- ✅ hosted `mailbox run` (always-on, chain-scanning, HTTP-push receive)
- ✅ `mailbox run -privacy` (no Sender in log) — just added
- ✅ body padding (fixed 1 KiB bucket) — just added
- 🔲 operator infra (TLS/auth front, per-user mailboxes, provisioning, billing)
- 🔲 Tor/I2P front for the node/mailbox endpoints
- 🔲 relay-fabric hop + decoy traffic (the deep metadata answer)

## Summary
Model B is a real, buildable service and the architecture already leans into
it. The phone is a thin key-holder; the service is a blind, always-on courier.
Privacy mode + body padding (just shipped) cut the operator's metadata. The
remaining work is operations (provisioning/auth/billing) and the deeper
relay-fabric metadata hardening when the network is big enough to support it.
