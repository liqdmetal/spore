# Solana + EVM delivery & mycelium use-cases

## Decision: Solana backend is next (2026-09-05)

User has wallet access (Phantom/MetaMask) to Solana AND EVM chains (bridging).
Direction: build the **durable Solana program** (per-recipient PDA inbox),
memo/transfer as a get-going fallback.

### The Solana reality (honest)
- Solana is NOT EVM — different RPC (`sendTransaction`, `getSignaturesForAddress`)
  and tx model (accounts, PDAs, programs). Needs a **new `chain.Chain` backend**
  (`internal/solana`), mirroring `internal/evm` but on Solana's RPC.
- Delivery model chosen: **Solana program with per-recipient PDA inbox** storing
  the mycelium E2E envelope (opaque bytes; the program never holds a key).
  Recipient queries their inbox PDA. Durable.
- Memo/transfer model = program-free fallback (memo is a log, not durable).

### Toolchain status (BLOCKED)
- `release.solana.com` has a TLS failure from both the Hetzner node AND local
  Windows (curl error 35) — the standard Solana installer can't fetch from it.
- GitHub + crates.io are reachable. `solana-program` crate v1.18.26 + solana-sdk
  are already cached locally, so the program can be written + cargo-compiled as
  a standard Rust crate. But the **BPF build + deploy needs the Solana CLI
  toolchain** (`cargo-build-sbf`), which is the blocked part.
- Path to unblock: `cargo install cargo-build-sbf` (fetches from crates.io, not
  release.solana.com) OR get the Solana CLI from GitHub releases. Heavy compile.

### Build plan (once toolchain unblocks)
1. `internal/solana` backend (gagliardetto solana-go v1.11.0 is available):
   PostPayload -> send tx w/ envelope to recipient's inbox PDA (via program
   instruction); ListIncoming -> read recipient inbox PDA via getAccountInfo.
2. Solana program (Rust, solana-program crate): `deliver(to_pda, data)`,
   `read`, `burn`, PDA = sha256("mycelium", recipient_pub).
3. Memo/transfer fallback backend if program deploy is delayed.

---

## What mycelium messaging is useful for (strategic)

E2E-encrypted, no-relay, multi-chain point-to-point messaging. Real value:

1. **DAO/coordination quorum signals** (user-spotted). Private authenticated
   "I'm online / I signal this way" before on-chain voting. No-relay = no
   coordinator sees who's coordinating.
2. **Private settlement context.** On-chain payment (DERO/EVM/XMR) + the
   human detail (invoice, what it's for) rides E2E off the public record. The
   *context* stays private even on public chains.
3. **Multi-chain operator ops channel.** People running nodes on DERO+EVM+XMR
   get one mycelium identity per chain, one inbox — sovereign ops messaging
   with no subpoena-able/central Discord/Telegram.
4. **Chain-independent identity.** The mycelium key is chain-agnostic — the seed
   of the cross-chain identity proof (same you controls DERO+EVM+XMR addrs).
   Messaging is the first app on that identity.
5. **Compostable secrets / dead-drop with expiry.** One-time credentials,
   time-boxed instructions; burn enforced by design, not trust.

### What it is NOT (honest)
- Not a WhatsApp/Signal replacement for consumer chat (key/wallet friction).
- Not anonymous mass communication.
- It's a sovereign, key-held, chain-anchored comms layer for people already
  living on-chain: operators, DAO members, settlement counterparties, and the
  mycelium relay-network operators themselves.
