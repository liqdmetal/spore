# Spore sustainability — grassroots, no VC, no token

Spore is BSD-3 free software and stays free forever. The protocol never phones
home, never gates a feature behind a license check, and never requires an
account. Privacy is not a upsell.

What CAN earn money is **optional convenience operated by a person** — the same
model as Mastodon hosting, Syncthing relays, or a paid email provider: the
software is free, running the always-on infrastructure for someone else is a
service. Three lines, in order of time-to-first-dollar:

---

## Line 1 — Hosted Model-B mailbox + relay (first dollar, lowest effort)

**The pitch:** "You don't want to run a server. We run the blind courier for
you — your phone still holds every key."

A phone can't run a DERO/Solana node and can't stay always-on to receive. The
self-host answer is a home node ([`HOME_NODE.md`](HOME_NODE.md)); the
the no-home-node answer is Model B ([`MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md)): a
hosted `spore mailbox host` + `spore relay run` that

- holds only TTL-bound **ciphertext** bodies and serves **single-use prekeys**,
- never holds identity/SPK/state private keys (those stay on the user's device),
- leaves E2 ratchet decryption on the user's device,
- sees traffic patterns and timing, but not message content.

**Why it's defensible:** the operator is a *blind courier*, not a trusted
server. Compromise of the host yields ciphertext that's already expiring, not
keys. That's a stronger posture than Signal's servers (which hold your account
and metadata) and a paid one (unlike free relays that can vanish).

**Cost/effort to launch:** one systemd unit on the existing hardened Hetzner
node + a token-auth shared `mailbox host` + `relay run`, a pricing page, and a
signup that provisions a per-user mailbox token. The runbook already exists
([`MODEL_B_RUNBOOK.md`](MODEL_B_RUNBOOK.md)). No new protocol work.

**Pricing shape (operator's call):** a small monthly per-mailbox fee. Anchor to
"cheaper than a VPS you'd have to manage yourself." Free tier = self-host,
always.

**Honest limit to publish:** Model B sees metadata (who talks to whom, when).
Users who need metadata privacy too must self-host a home node or run their own
relay. Say this on the pricing page — it's the whole credibility of the product.

---

## Line 2 — Settlement rake on in-chat escrow + swaps (the moat's revenue)

**The pitch:** Spore is the only messenger where money and message are the same
atomic object. Make the *settlement* the revenue, not the messaging.

`spore msg invoice` / `spore msg pay` already move value atomically with a
message on DERO/EVM. The next step is wiring the chat to the **sap escrow** and
**relay-dex** contracts the operator already runs:

- **Escrow in chat:** `/escrow` posts sap escrow terms into the thread;
  milestone release is a reply; the SC rakes a per-hand fee to a baked
  `fee_collector`. The operator is **vendor-only** — never custodial, never
  "the house," never facing the player. (Same low-exposure doctrine as SapTable.)
- **Swap offers in chat:** relay-dex HTLC legs negotiated in-thread and settled
  on-chain — P2P exchange with no arbitrator. The DEX already takes a bps fee
  (90% LP / 10% treasury on AMM; atomic swaps free).

**Why it's defensible:** the rake is on **settlement the operator's own rail
provides**, not on messaging. Free users pay nothing to talk; the operator earns
only when money moves through escrow/swap — and that money moves on a
confidential DERO rail nobody else offers in a chat client.

**Effort:** an SC-call seam in the CLI (the contracts are live on mainnet; this
is integration, not new crypto). Medium.

**Honest limits:** escrow/swap are vendor tooling — the operator never holds
user funds, so this is fee-on-flow, not custody. Publish the exact rake and the
fact that atomic swaps are free.

---

## Line 3 — Business tier (teams, firms, the CPA wedge)

**The pitch:** privacy-preserving team messaging with the audit trail a
regulated firm needs — without giving up the compostable, self-hosted model.

Built on what already exists (`maildb`, threads, search, allowlist, panic):

- **Team maildb + multi-device sync** (Tier 3): mailbox as the always-on node,
  per-device X3DH sessions (same identity, fresh session per device — forward
  secrecy stays device-bound, like Signal). Cross-device catch-up rides the
  chain pointer, no separate sync server.
- **Retention policy controls:** per-thread keep-forever vs. compost, `purge`
  scheduling, panic-wipe for the whole org.
- **Audit log** (optional, local): who messaged whom, hashed — enough for a
  firm's compliance without storing content.

**The natural first customer:** the operator's own CPA/AIS practice
(BookGuardian / Ledger Sentinel). Small incorporated firms and their accountants
need private client comms that can also *settle* (pay an invoice in the same
thread). That's a real, reachable niche the operator already sells into — not a
speculative market.

**Effort:** multi-device is the big build (Tier 3). Medium-high. Team features
on top are mostly UX + policy.

---

## What we will NOT do

- **No VC.** No equity, no growth-at-all-costs, no investor-mandated backdoor.
- **No token.** Spore settles in existing chains' native assets (DERO/EVM); it
  does not issue its own. A token would recreate the custody/speculation
  problem the design avoids.
- **No data sales, no ads on the private path.** The panic button is the brand.
- **No paid privacy.** Forward secrecy, compostability, single-use prekeys, and
  self-hosting are free forever. Only *hosted convenience* and *settlement flow*
  cost money.
- **Grassroots cap or nada.** If the operator can't sustain it from hosting +
  rake + a business tier, the answer is to keep it free and small — not to take
  money that comes with strings.

## Grants (separate track, not a business line)

NLnet / OTF Internet Freedom Fund / EF ESP are plausible non-dilutive funding
for the *protocol* (censorship-resistant, compostable messaging is squarely in
scope), but grants are a different conversation with its own eligibility
constraints (NLnet needs an EU collaborator). Tracked separately; not counted as
revenue here.
