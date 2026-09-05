# m³ — Multi-chain roadmap (the mycorrhizal network, tree by tree)

*Trees are the endpoints — each a wallet+node on its own chain. Spore is the
underground no-relay substrate. m³ is the common mycorrhizal network they form.
Adding a tree means one `chain.Chain` backend + one payload codec. The seam
(`internal/chain`) makes each new chain bounded.*

> **Authoritative chain status lives in [`README.md`](README.md#chain-status).**
> This roadmap tracks what's done vs. what's left; it does not re-state per-tree
> live status.

## Done
- **DERO** — tree #1. Whisper (no-relay unicast), long nobody-but-us bodies,
  rooms, browser UI. Live, mainnet-verified.
- **m³ seam** — `internal/chain` (Chain + Watch) + `internal/whisper` canonical
  codec (kind 0x01 text / 0x02 pointer). Core has zero chain-specific dependency
  (proven by a mock chain, then on 3 real backends).
- **EVM** — Go `internal/evm` backend **live-verified** on a local anvil node
  (same JSON-RPC path a real chain uses). `contracts/MyceliumMailbox.sol`
  written for scalable inbox-on-busy-chains (deploy pending).
- **Solana** — Go `internal/solana` backend + Rust BPF mailbox program
  (per-recipient PDA inbox) **deployed and live-verified on Solana mainnet**
  (program `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs`, v2). Client currently
  self-messaging.
- **E2E secure layer** — `internal/secure` X25519 ECDH + HKDF-SHA256 +
  XChaCha20-Poly1305 envelope (`kind 0xE0`) that keeps EVM/Solana/XMR content
  private on public chains. `internal/crypto` holds the primitives + key-zeroing.
- **Donate rail** — `spore donate [chain] | --all`, per-chain address registry.
- **Multi-chain CLI** — `spore msg send|recv|send-long|keygen -chain
  dero|evm|xmr|solana` dispatch via `internal/backend`.

## Remaining (honest, in rough priority order)

| # | Item | Why it's gated |
|---|---|---|
| 1 | **XMR live-verify** | pruned `monerod` syncing on Hetzner node (~60%); needs a real `monero-wallet-rpc`. Scope = short ≤8-byte signals (knock) + off-chain rendezvous; no native payload encryption. |
| 2 | **Deploy `MyceliumMailbox.sol`** | written + backend proven; needs a funded EVM account on a real chain. |
| 3 | **Solana cross-wallet delivery** | program requires recipient to sign; today client self-messages. Both parties must run the backend to deliver cross-wallet. |
| 4 | **L1 mempool catch (~1–2s)** | Rust scanner on derohe-rs (BSD-3, clean-room, mainnet-proven) watches the node txpool and decrypts before mining. |
| 5 | **Relay fabric interconnection** | spore relay node forwarding encrypted pointer/body across a substrate mesh (Waku/Iroh/libp2p) — the underground trunk between chains. |
| 6 | **Zcash / ARRR / Decred / Verge** | each a `chain.Chain` backend reusing the envelope/relay pattern. |
| 7 | **Cross-chain identity proof** (DERO↔EVM) | research crypto — the hard piece. Gates true interchain messaging (a pointer from a DERO tree read by an EVM tree). |
| 8 | **Zama / FHE** | compute-on-encrypted, a different primitive — parked. |

## Honest notes
- "Finish to 7 tonight" isn't real: #7 is research crypto; #1–3 are
  integrations with real-node dependencies. This doc is the map, not a promise
  of tonight.
- Where a chain has no native encrypted rail, m³ supplies secrecy — the tradeoff
  is metadata (a tx/event/inbox record exists) still visible at that layer, same
  as DERO whisper's honest limit.
- **Cross-chain direct messaging is impossible** (different key crypto).
  Cross-chain = rendezvous/relay + identity proof (#7), signaling + handoff.
- Group *broadcast* still needs a relay or an SC — no-relay is unicast by
  construction.
