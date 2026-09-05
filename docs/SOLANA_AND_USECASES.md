# Solana + EVM delivery & spore use-cases

## Decision: Solana backend is next (2026-09-05) — NOW DONE

User has wallet access (Phantom/MetaMask) to Solana AND EVM chains (bridging).
Built the **durable Solana program** (per-recipient PDA inbox). **Deployed +
live-verified on Solana mainnet.**

### The Solana reality (honest)
- Solana is NOT EVM — different RPC (`sendTransaction`, `getSignaturesForAddress`)
  and tx model (accounts, PDAs, programs). Needed a **new `chain.Chain` backend**
  (`internal/solana`), mirroring `internal/evm` but on Solana's RPC.
- Delivery model chosen: **Solana program with per-recipient PDA inbox** storing
  the spore E2E envelope (opaque bytes; the program never holds a key).
  Recipient queries their inbox PDA. Durable.
- Memo/transfer model = program-free fallback (memo is a log, not durable);
  not needed — the program deployed.

### Status — DEPLOYED + LIVE-VERIFIED (2026-09-05)
- BPF mailbox program `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs` (v2; v1 had
  a rent bug) deployed on Solana mainnet. Source + tests in `solana-program/`.
- Go `internal/solana` backend live-verified against the program (self-messaging:
  the program requires the recipient to sign). RPC default
  `https://api.mainnet-beta.solana.com`.
- **Remaining:** cross-wallet delivery — both parties run the backend (the
  recipient must sign to read their own inbox). See `README.md` / `ROADMAP.md`.

### Build path (what was done)
1. `internal/solana` backend (gagliardetto solana-go v1.11.0):
   PostPayload -> send tx w/ envelope to recipient's inbox PDA (via program
   instruction); ListIncoming -> read recipient inbox PDA via getAccountInfo.
2. Solana program (Rust, solana-program crate): `deliver(to_pda, data)`,
   `read`, `burn`, PDA = sha256("spore", recipient_pub).
3. Deployed to mainnet after the BPF toolchain was unblocked
   (`cargo install cargo-build-sbf` / Solana CLI from GitHub, since
   `release.solana.com` had a TLS failure).

---

## What spore messaging is useful for (strategic)

E2E-encrypted, no-relay, multi-chain point-to-point messaging. Real value:

1. **DAO/coordination quorum signals** (user-spotted). Private authenticated
   "I'm online / I signal this way" before on-chain voting. No-relay = no
   coordinator sees who's coordinating.
2. **Private settlement context.** On-chain payment (DERO/EVM/XMR) + the
   human detail (invoice, what it's for) rides E2E off the public record. The
   *context* stays private even on public chains.
3. **Multi-chain operator ops channel.** People running nodes on DERO+EVM+XMR
   get one spore identity per chain, one inbox — sovereign ops messaging
   with no subpoena-able/central Discord/Telegram.
4. **Chain-independent identity.** The spore key is chain-agnostic — the seed
   of the cross-chain identity proof (same you controls DERO+EVM+XMR addrs).
   Messaging is the first app on that identity.
5. **Compostable secrets / dead-drop with expiry.** One-time credentials,
   time-boxed instructions; burn enforced by design, not trust.

### What it is NOT (honest)
- Not a WhatsApp/Signal replacement for consumer chat (key/wallet friction).
- Not anonymous mass communication.
- It's a sovereign, key-held, chain-anchored comms layer for people already
  living on-chain: operators, DAO members, settlement counterparties, and the
  spore relay-network operators themselves.
