# Spore — M³: Spore multi-chain messenger

*Vision / architecture note. Spore was built and verified live on DERO, then
proven portable across the chain seam — the same core now runs on DERO, EVM and
Solana (live-verified), with Monero pending. This doc sketches where the
expansion goes and what "private" means per chain.*

---

## 1. What spore actually is (don't lose this)

M³ (Spore multi-chain messenger) is NOT a chain. It is a **transport + coordination layer** that rides on
a chain. It depends on only two things any chain provides:

1. **A point-to-point encrypted payload** (the tx message field) — carries a
   short whisper, or the *pointer* to a long body.
2. **A wallet/signer** holding keys, exposed over RPC.

Everything else in spore — the ephemeral-ECDH crypto, the secure E2E
envelope, the rendezvous peer-fetch, the compostable rooms, the nobody-but-us
body store, the UI — sits **above** the chain and never touches consensus. That
is what makes it portable.

The seam is `internal/chain` (`Chain` + `Watch`), the codec is
`internal/whisper`, and `internal/backend` dispatches `-chain` to the right
backend. The seam is **proven on three chains** (DERO, EVM, Solana). Adding a
chain means one backend behind that interface — nothing above it changes.

## 2. The chain map — what "private" really means per chain

| Chain | Encrypted payload | Wallet/signer | Spore fit |
|---|---|---|---|
| **DERO** | ✅ native (point-to-point, ring sig) | ✅ `--rpc-server` | **live, mainnet-verified** |
| **EVM-compatible** | ⚠️ calldata/events public → m³ secure envelope | wallet/signer | **live-verified** (local anvil); `MyceliumMailbox.sol` for busy chains |
| **Solana** | ⚠️ inbox PDA public → m³ secure envelope | signer keypair | **live on mainnet** (BPF program `GbNWrv…BraAs`) |
| **Monero** | ⚠️ different model (see §3) | wallet RPC | built, **mock-verified** — pending node sync |
| **other privacy chains** | varies | varies | same rule: needs the 2 primitives |

**The rule that makes it multi-chain:** where a chain has no native per-recipient
encrypted message field (EVM, Solana, XMR), privacy comes from **m³'s own
secure envelope** — X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305
(`internal/secure`, `kind 0xE0`) layered on whatever the chain carries. The
chain is identity + a carrier; m³ is the secrecy. On-chain records (calldata,
inbox PDAs) carry ciphertext only; the recipient's private key is the only key.

## 3. The Monero wrinkle (be honest)

Monero's tx payloads are NOT a general message field like DERO's. Monero has:
- `tx_extra` — free-form bytes, but **not encrypted to a recipient key** the way
  DERO encrypts payload-0.
- Payment IDs / integrated addresses — for identifying payments, not messaging.
  Modern Monero (≥0.18) only allows **8-byte** payment IDs.

So a "whisper on Monero" can't ride native per-recipient payload encryption the
way it does on DERO. The honest model (matching `internal/xmr`, built):

- **XMR tx = a knock, not content.** The backend posts a dust transfer whose
  8-byte payment id carries a short spore signal (a reference/knock), never
  the full whisper or pointer (which don't fit 8 bytes).
- **Content rides off-chain rendezvous** (chain-agnostic, already in the core),
  keyed by that signal — the actual private body never sits on-chain.
- **Monero gives m³ identity + a payment rail**, not an encrypted-message
  channel. The rendezvous layer does the private delivery.

`internal/xmr` implements `chain.Chain` over the Monero wallet RPC
(`transfer` with payment id, `get_transfers`, `get_address`, `get_height`) and
is **mock-verified** (seam + payment-id→signal flow tested with a fake wallet
RPC). It needs **live verification against a real `monero-wallet-rpc`** — a
pruned `monerod` is syncing (~60%) on the Hetzner node to enable that — before
it's trusted the way DERO/EVM/Solana are.

## 4. The interconnection model — the spore relay fabric

The stack treats **substrate as replaceable delivery, not authority**. The
transport seam can be any p2p/gossip substrate (Waku/Iroh/libp2p, or the node's
own P2P). Spore slots in at the transport seam:

```
spore app (whisper / rooms / long-body)
   -> spore core (ECDH crypto, secure envelope, rendezvous, compost, UI)  [chain-agnostic]
      -> signer seam:  DERO | EVM | Solana | Monero                  [per-chain]
      -> transport seam: node P2P | substrate mesh (Waku/Iroh/libp2p)
           -> spore relay nodes = the shared "spore relay" fabric
```

**Spore relay nodes as the fabric:** an always-on relay node connects
spore instances across chains — a DERO user and an EVM user both reach their
local relay node, which forwards the encrypted pointer/body across the substrate
mesh. The node relays ciphertext it cannot read (same "box holds no keys"
property as spore rooms).

**Interchain spore (DERO wallet ↔ EVM wallet) — the honest model:**
direct point-to-point encryption across chains is impossible (different key
crypto). What IS possible is the **cross-chain rendezvous / relay**:
1. Sender encrypts the body to a key the recipient can derive by proving control
   of both wallets (a cross-chain identity proof — a cross-chain settlement
   problem, NOT a Spore messenger problem).
2. The pointer/notification crosses chains via the spore relay mesh.
3. Delivery is single-chain; cross-chain is signaling + handoff.

This is a hard, gated future item — not built.

## 5. Donation addresses on every chain

Because spore is identity = your wallet address on whatever chain you're on,
a "spore node/relay" operator can advertise **one address per supported
chain** (DERO / EVM / Solana / XMR) as the donation rail. `spore donate`
already prints the right one from a `{chain: address}` registry. The relay
operator's cross-chain identity is just "the entity controlling these
addresses" — the same cross-chain-proof problem as §4.

## 6. Build order (what's done, what's left)

1. ✅ **The chain seam** — `internal/chain` (Chain + Watch) + `internal/whisper`
   codec. Core has zero chain-specific dependency.
2. ✅ **Second + third chain** — Go `internal/evm` (live-verified on anvil) and
   Go `internal/solana` (live on mainnet). Proves the seam is real.
3. ✅ **E2E secure envelope** — `internal/secure` seals EVM/Solana/XMR content
   against public chains.
4. ✅ **Donation rail** — per-chain address registry + `spore donate`.
5. ⏳ **Monero live-verify** — mock-verified backend; needs the syncing node +
   a real `monero-wallet-rpc`.
6. ⏳ **Relay fabric interconnection** — spore relay node (encrypted pointer
   forwarding across the substrate mesh).
7. ⏳ Cross-chain identity proof (DERO↔EVM) — the hard piece, gated on that work.

## 7. Guardrails (from how it was built)

- **Keep the core chain-agnostic.** Never bake DERO semantics into the crypto /
  rendezvous / rooms / UI layers. DERO is one backend.
- **Content stays nobody-but-us.** The relay fabric relays ciphertext only; it
  must never hold a key. If a substrate can read the body, it's not spore.
- **Compost still means rot.** Bodies + keys must remain ephemeral and
  erasure-able on every chain — don't trade the privacy model for reach.
