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
TRANSPORT     E2E envelope (X25519+HKDF+XChaCha20), no-relay unicast,
              off-chain long bodies (compost), relay-fabric hops
─────────────────────────────────────────────────────
CHAINS        DERO (native E2E) · Solana (mainnet) · EVM · XMR (off-chain)
              — each a "tree" the mycelium metaphor grows through
─────────────────────────────────────────────────────
KEYPING       phone holds keys, signs/decrypts locally; your node is a blind
              courier that never sees content
```

## How it works — one message, any device

1. **You run a home node** (the encouraged default): your chain node +
   `spore mailbox run -privacy -token <secret> -cert/-key` — always on, TLS +
   auth, never logs who.
2. **Your phone dials home** over TLS. It holds the keys; it sends through your
   node's RPC and receives through your mailbox. No third party.
3. **A friend messages you** — E2E-encrypted, rides your chain (DERO native, or
   the envelope on Solana/EVM/XMR), the body is content-addressed and
   compostable.
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
- **DERO** live mainnet · **Solana** live mainnet (v3, cross-wallet) · **EVM**
  anvil + MyceliumMailbox contract · **XMR** node synced (content off-chain, B1)
- **Home node**: `spore mailbox run` — always-on, cross-chain, `-privacy`
  (no sender in log), `-token` (auth), `-cert/-key` (TLS), body padding
- **Relay fabric hop**: `spore relay run` — store-and-forward of opaque bodies
- **`spore status`** — connection-health HUD
- **Hardened**: E2E envelope random-nonce fix, adversarial tests, 19 pkgs green

## The arc (where this goes)
From a private messenger to a **private paging mesh**: every home node can
optionally be a relay for the fabric; chain relays + decoy traffic weaken the
metadata a single operator sees; cross-chain identity proof (roadmap) unlocks
true DERO↔Solana↔EVM delivery. The pager becomes a network.

## Repos
- **Spore**: `github.com/liqdmetal/spore` (public) — this codebase.
- Rhizome / Obscura architecture is a separate private effort.
