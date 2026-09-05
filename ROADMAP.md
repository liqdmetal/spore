# m³ — Multi-chain roadmap (the mycorrhizal network, tree by tree)

*Trees are the endpoints — each a wallet+node on its own chain. Mycelium is the
underground no-relay substrate. m³ is the common mycorrhizal network they form.
Adding a tree means one `chain.Chain` backend + one payload codec. The seam
(internal/chain) makes each new chain bounded.*

## Done (all mainnet/live)
- **DERO** — tree #1. Whisper (no-relay), long nobody-but-us bodies, rooms,
  browser UI. Live, mainnet-verified, in `liqdmetal/mycelium`.
- **m³ seam** — `internal/chain` (Chain + Watch) + whisper `Codec`/`SendChain`/
  `RecvChain`. Core has zero chain-specific dependency (proven by a mock chain).

## Chain map — how each tree joins the CMN

| Chain | Native encrypted-payload rail? | Backend approach | Effort |
|---|---|---|---|
| **DERO** | ✅ point-to-point payload | done | — |
| **EVM-compatible** | ⚠️ calldata/events public (no native per-rcpt msg) | m³ ECDH + `MyceliumMailbox` contract; privacy from m³ crypto (Go `internal/evm` backend built) | M |
| **Zcash** | ⚠️ shielded payments, no free msg field | identity via shielded addr; delivery via rendezvous/relay | M–H |
| **ARRR (Pirate)** | ⚠️ Komodo/Zcash fork | same as Zcash path | M–H |
| **Decred** | ⚠️ tx but no per-rcpt msg | m³ ECDH over a message tx / contract | M |
| **Verge** | ⚠️ | m³ ECDH over tx payload | M |
| **Monero** | ⚠️ no per-rcpt msg; only 8-byte payment id | identity + signal rail; content off-chain rendezvous (Go `internal/xmr` backend built, mock-verified; needs live wallet-rpc to confirm) | M–H |
| **Zama (FHE)** | ⚠️ NOT a message chain | FHE = compute-on-encrypted, different layer — likely out of transport scope | design |

**Rule:** where the chain has no native per-recipient encrypted message field,
privacy comes from **m³'s own ECDH** (the crypto that already powers DERO
whispers) layered on whatever the chain can carry (calldata, tx_extra, a
contract blob). The chain is identity + a carrier; m³ is the secrecy.

## Build order (honest)

1. ✅ **m³ seam** (chain.Chain + Codec) — done.
2. **EVM mailbox** — `MyceliumMailbox.sol` (store m³-encrypted blob per
   recipient + emit `Inbox(to, from, cid)` event) + Go `internal/evm` backend +
   codec. Covers any EVM-compatible chain. **Testable against any
   EVM RPC** — this is the concrete next build.
3. **Relay fabric interconnection** — mycelium relay node: forward encrypted
   pointer/body across the substrate mesh (Waku/Iroh/libp2p). Relay nodes become
   the underground trunk between chains.
4. **Monero** — identity + signal rail; 8-byte payment-id knock, content off-chain
   rendezvous (no reliance on native payload encryption). Go `internal/xmr`
   backend built + mock-verified; confirm against a live `monero-wallet-rpc`.
5. **Donation addresses** — `mycelium donate`, config `{chain: addr}`, one
   address per supported tree.
6. **Cross-chain identity proof** (DERO↔EVM) — prove one key controls an
   address on both chains. Research-grade; the hard piece. Gates true
   interchain messaging (pointer from DERO tree read by EVM tree).
7. Zcash / ARRR / Decred / Verge — each a `chain.Chain` backend after 2+3 land
   (reuse the mailbox/relay pattern).

## Honest notes
- "Finish to 6 tonight" isn't real: step 6 is research crypto; 2–4 are
  multi-hour integrations. This doc is the map, not a promise of tonight.
- Where a chain has no native encrypted rail, m³ supplies secrecy — the
  tradeoff is metadata (a tx/event exists) still visible at that layer, same as
  DERO whisper's honest limit.
- Zama/FHE is computation-on-encrypted-data, a different primitive; parked until
  the transport trees are in.
