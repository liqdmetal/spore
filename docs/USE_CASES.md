# Mycelium — novel use-cases

*What an E2E-encrypted, no-relay, multi-chain, key-held messenger is genuinely
good for. Written from the architecture, not hype.*

## Why mycelium is different (the properties that create use-cases)

| Property | What it means |
|---|---|
| **No relay / no box** | No intermediary ever holds both halves of a conversation. Nothing to subpoena, kill-switch, or log centrally. |
| **E2E by default, every chain** | DERO encrypts natively; EVM/Solana/XMR carry mycelium's own XChaCha20 envelope. Content private even on public chains. |
| **Compostable / rot-by-design** | Bodies + keys are ephemeral and erasure-able. Old messages become unrecoverable *by design*, not by trust. |
| **Key-held identity** | Your mycelium key is chain-agnostic — the same *you* controls your DERO, EVM, Solana, XMR addresses. |
| **Multi-chain** | One messenger, any tree. Same UI/crypto/seam on every supported chain. |
| **Anonymous-by-default sender** | DERO ring-sig; the tx exists but the sender is hidden. |

---

## The novel use-cases

### 1. DAO quorum & coordination signals — *before* the vote
The user-spotted killer app. A DAO's members signal **privately and
authenticated** before an on-chain vote: "I'm here", "I lean yes", "I need
more info on X". No coordinator, no public forum, no chain-metadata leak of
*who is coordinating*. The vote itself is public; the human coordination around
it stays nobody-but-us. This is coordination the DAO treasury can't see —
exactly what a decentralized org that wants real member sovereignty needs.

### 2. Private settlement context (the "payment + note" pattern)
A payment happens on-chain (DERO/XMR ring-private, or EVM/Solana public). The
*human meaning* — "here's the invoice, this covers March, reference #42" —
rides mycelium E2E to the counterparty. Result:
- On private chains: the payment is anonymous AND its context stays off the
  public record.
- On public chains (EVM/Solana): the tx is visible but its *purpose* is not.
- Cross-chain: pay on XMR, send the note on Solana — the note references the
  payment without either chain revealing the link.

### 3. Sovereign multi-chain ops channel
A person running nodes/wallets on DERO + EVM + Solana + XMR gets **one
messenger, one identity per chain, one inbox**. Operations chatter — alerts,
coordinated actions, key-rotation notices between *your own* endpoints — stays
off central, subpoena-able, kill-switchable Discord/Telegram. This is the
"mycelium relay network operator" use-case: the people who run the fabric talk
on the fabric.

### 4. Chain-independent identity (the seed of cross-chain proof)
Because the mycelium key is chain-agnostic, a message sent *from your DERO key*
and *received on your EVM key* (via a relay/rendezvous) is the practical proof
that one controller owns both. The messenger is the first app to exercise this.
It's the stepping stone to real cross-chain identity — "the entity controlling
these addresses is one" — which is what unlocks atomic swaps and settlement
that trust a single controller across chains.

### 5. Compostable secrets & dead-drops with enforced expiry
A one-time credential, a time-boxed instruction, a temporary capability. The
compost model means it **must** rot: key erased after read, body TTL-evicted,
on-chain record is a dead hash. This is *cryptographically enforced
forgetting* — useful for anything where "this shouldn't exist in a month" is a
requirement (ephemeral handoffs, short-lived tokens, deniable records).

### 6. Witness / receipt signaling (anti-censorship notice)
A no-relay, chain-anchored whisper that a specific event happened or a specific
statement was made — with the *sender hidden* by ring signature. Unlike a
tweet or a forum post, it can't be taken down: once mined it's on-chain, dead
keys or not. For whistleblowing-style signals where the message's *existence and
receipt* matter but the sender must stay anonymous.

### 7. Local-first mesh for offline-ish groups
Long bodies ride peer-to-peer, store-and-forward between *participants' own
nodes*. A group that's intermittently online (field ops, a caravan, a dev team
across time zones) can run private rooms that don't need any always-on central
service — just each member's node when it's up. No server to provision, no
uptime to buy.

### 8. The "mycelium relay fabric" itself
Operators run always-on relay nodes that connect trees *across chains*. The
nodes relay ciphertext they cannot read (same "box holds no keys" property).
The fabric is a commons — the mycelium under the forest. Use-cases for the
operators: cross-chain notifications, cross-chain pointer handoff, and — when
the identity proof lands — cross-chain settlement signaling.

---

## What it is NOT (stay honest)
- **Not** a WhatsApp/Signal replacement for consumer chat — the wallet/key
  friction is real and the no-relay model means no giant room of casual users.
- **Not** anonymous *mass* broadcast — no-relay is unicast/sparse by design;
  group broadcast needs a relay/SC.
- **Not** a place where a cockbiter reading the chain learns your message
  content (E2E), but they *can* see that a tx/event happened at ~a time (metadata).

## The wedge
The people this serves are **already living on-chain**: DAO members, node/relay
operators, settlement counterparties, multi-chain power users. They have keys,
they understand rot, and they're the ones who most need comms that answer to no
central party. Mycelium is their underground — the common mycorrhizal network
under the forest they already stand in.
