# Spore — the full picture

*A private, E2E-encrypted, no-relay messenger — but really it's a
**blockchain live pager system**: you carry a device, your home base is
always on, and messages reach you no matter which chain or where you are.
Compostable by design — they rot.*

## The one-sentence mental model
> **Your home node is your pager base station. Your phone is the pager.
> The chain is the airwaves. Spore is the protocol that makes a private
> message find you — silently, point-to-point, with no operator in the
> middle.**

## The layers

```
APPLICATION   spore CLI / mailbox / relay — your tools
─────────────────────────────────────────────────────
TRANSPORT     0xE2 X3DH + Double Ratchet (forward-private), no-relay unicast,
              off-chain TTL bodies (compost), relay-fabric hops, pay-with-msg
─────────────────────────────────────────────────────
CHAINS        DERO (native E2E) · Solana (mainnet) · EVM · Nostr · Bitcoin ·
              Cosmos · TON · XMR (off-chain) — each a "tree" the mycelium
              metaphor grows through
─────────────────────────────────────────────────────
KEYPING       phone holds keys, signs/decrypts locally; your node is a blind
              courier that never sees content
```

## How it works — one message, any device

1. **You run a home node** (the encouraged default): your chain node +
   `spore mailbox host -privacy` — always on, TLS + auth, stores ciphertext and
   prekeys, and never receives the E2 plaintext.
2. **Your phone dials home** over TLS. It holds the keys, sends through your
   node's RPC, and runs `spore msg recv-e2` to decrypt locally. No third party.
3. **A friend messages you** — E2E-encrypted, rides your chain (DERO native, or
   the envelope on Solana/EVM/XMR), the body is content-addressed and
   compostable; `recv-e2` decrypts it locally.
4. **No home node?** A hosted Model-B service (blind courier) runs your node +
   mailbox. You pay for reachability, not trust — the service never sees
   content or (in privacy mode) who sent it.

## The three deployment shapes

| Shape | Who runs the server | Phone connects to | Privacy |
|---|---|---|---|
| **Self-hosted home node** (encouraged) | you | **your own node** | highest — your data, your server, no third party |
| **Relay fabric hop** | a community/anon relay | a relay, then to your node | relay sees ciphertext + dest, not you |
| **Hosted service (Model B)** | a service | the service's node/mailbox | content E2E; service sees traffic + timing |

## What's real and shipped (v0.3.0)
- **Multi-chain** `spore msg send/recv/send-long/keygen -chain dero|evm|xmr|solana`
- **DERO** live mainnet · **Solana** live mainnet (v2, self-messaging) · **EVM**
  anvil + MyceliumMailbox contract · **XMR** mock-verified only (content off-chain, B1)
- **Multi-device sync**: encrypted `e2-device` export/import with a local
  collision guard; conflicted sessions fail closed until replaced.
- **Home/hosted mailbox**: `spore mailbox host` — always-on shared ciphertext
  and prekey service, `-privacy` (no sender in hosted log), per-user tokens,
  TLS at the edge, body padding; `spore msg recv-e2` decrypts on the device
- **Relay fabric hop**: `spore relay run` — store-and-forward of opaque bodies
- **Auto-compost**: `spore msg recv -chain evm|solana` erases each message
  from the mailbox contract/account (`burn()`) the moment it's delivered —
  `-auto-burn=false` to keep it instead. DERO's native message field and
  off-chain long bodies were already ephemeral; this closes the same gap
  for EVM/Solana mailbox storage. Live-verified against anvil: deliver →
  receive → burn → re-query proves the on-chain slot is empty.
- **`spore status`** — connection-health HUD
- **Hardened**: E2E envelope random-nonce fix, adversarial tests, 19 pkgs green

## The arc (where this goes)
From a private messenger to a **private paging mesh**: every home node can
optionally be a relay for the fabric; chain relays + decoy traffic weaken the
metadata a single operator sees; cross-chain identity proof (roadmap) unlocks
true DERO↔Solana↔EVM delivery. The pager becomes a network.

## Repos
- **Spore**: `github.com/liqdmetal/spore` (public) — this codebase.
- Other chain(s) and relay architecture are separate efforts.
