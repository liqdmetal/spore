# Mycelium — cross-chain private communication & transport

*Vision / architecture note. Mycelium was built and verified live on DERO
(short no-relay whisper, long nobody-but-us bodies, rooms that rot). This doc
sketches the expansion: the same core running on every private chain, and
RelayOS nodes as the interconnection fabric.*

---

## 1. What mycelium actually is (don't lose this)

Mycelium is NOT a chain. It is a **transport + coordination layer** that rides on
a chain. It depends on only two things any chain provides:

1. **A point-to-point encrypted payload** (the tx message field) — carries a
   short whisper, or the *pointer* to a long body.
2. **A wallet/signer** holding keys, exposed over RPC.

Everything else in mycelium — the ephemeral-ECDH crypto, the rendezvous
peer-fetch, the compostable rooms, the nobody-but-us body store, the UI — sits
**above** the chain and never touches consensus. That is what makes it portable.

The only chain-specific piece today is `internal/dero` (the DERO wallet-RPC
seam). To add a chain you replace that seam. Nothing above it changes.

## 2. The chain map — what "private" really means per chain

| Chain | Encrypted payload | Wallet RPC | Mycelium fit |
|---|---|---|---|
| **DERO** | ✅ native (point-to-point, ring sig) | ✅ `--rpc-server` | **done, mainnet-verified** |
| **Obscura** | ✅ (EVM-compatible; has txs + signing) | wallet/signer | easy port (swap signer seam) |
| **Monero** | ⚠️ different model | wallet RPC | real work — see §3 |
| **XMR forks / other privacy chains** | varies | varies | same rule: needs the 2 primitives |

## 3. The Monero wrinkle (be honest)

Monero's tx payloads are NOT a general message field like DERO's. Monero has:
- `tx_extra` — free-form bytes, but **not encrypted to a recipient key** the way
  DERO encrypts payload-0.
- Payment IDs / integrated addresses — for identifying payments, not messaging.

So a "whisper on Monero" can't ride native per-recipient payload encryption the
way it does on DERO. Options, honest:
- **Off-chain mycelium on top of Monero identity**: use Monero wallet keys for
  auth/identity but carry the encrypted body over the P2P/rendezvous layer
  (which is chain-agnostic anyway). The whisper/pointer can ride a Monero
  transaction's `tx_extra` as opaque bytes; privacy of the *content* then comes
  from mycelium's own ECDH, not Monero's tx model.
- **RelayOS substrate** (Waku/Iroh/libp2p) as the actual carrier, with Monero
  as identity/settlement.

Real talk: Monero gives mycelium an identity + a payment rail but NOT a free
encrypted-message channel. The rendezvous layer does the private delivery.

## 4. The interconnection model — mycelium + RelayOS nodes

RelayOS's stack already treats **substrate as replaceable delivery, not
authority** (ADR-0004). Mycelium slots in exactly there:

```
mycelium app (whisper / rooms / long-body)
   -> mycelium core (ECDH crypto, rendezvous, compost, UI)   [chain-agnostic]
      -> signer seam:  DERO | Obscura | Monero | EVM        [per-chain]
      -> transport seam: node P2P | RelayOS (Waku/Iroh/libp2p)
           -> RelayOS nodes = the shared "mycelium relay" fabric
```

**RelayOS nodes as the mycelium relay fabric:** a RelayOS node can be the
always-on rendezvous that connects mycelium instances across chains — a DERO
user and an Obscura user both reach their local RelayOS node, which forwards the
encrypted pointer/body across the substrate mesh. The node relays ciphertext it
cannot read (same "box holds no keys" property as mycelium rooms).

**Interchain mycelium (DERO wallet ↔ Obscura wallet) — the honest model:**
direct point-to-point encryption across chains is impossible (different key
crypto). What IS possible is the **cross-chain rendezvous / relay**:
1. Sender encrypts the body to a key the recipient can derive by proving control
   of both wallets (a cross-chain identity proof — RelayOS's cross-chain
   settlement problem, NOT a mycelium messenger problem).
2. The pointer/notification crosses chains via the RelayOS relay mesh.
3. Delivery is single-chain; cross-chain is signaling + handoff.

This is exactly the layer RelayOS already exists to solve (cross-chain
settlement, atomic swaps, identity across chains). Mycelium rides it.

## 5. Donation addresses on every chain

Because mycelium is identity = your wallet address on whatever chain you're on,
a "mycelium node/relay" operator can advertise **one address per supported
chain** (DERO / XMR / EVM / Obscura) as the donation rail. This is trivial to
add once the signer seam is per-chain — a config file listing
`{chain: address}` and a `mycelium donate` command that prints the right one.
The relay operator's cross-chain identity is just "the entity controlling these
addresses" — the same cross-chain-proof problem as §4.

## 6. Build order (suggested)

1. **Lock the signer seam** — abstract `internal/dero` behind an interface so a
   chain backend is a clean swap. (Refactor, no behavior change; test stays
   green.)
2. **Second chain: Obscura** — EVM-compatible, lowest effort. Proves the seam.
3. **RelayOS interconnection** — mycelium relay over a RelayOS node (encrypted
   pointer forwarding across the mesh).
4. **Monero backend** — identity + rendezvous delivery, no reliance on native
   payload encryption.
5. **Donation scheme** — per-chain address config + `mycelium donate`.
6. Cross-chain identity proof (DERO↔Obscura) — the hard RelayOS piece, gated on
   that work.

## 7. Guardrails (from how it was built)

- **Keep the core chain-agnostic.** Never bake DERO semantics into the crypto /
  rendezvous / rooms / UI layers. DERO is one backend.
- **Content stays nobody-but-us.** The relay fabric relays ciphertext only; it
  must never hold a key. If a substrate can read the body, it's not mycelium.
- **Compost still means rot.** Bodies + keys must remain ephemeral and
  erasure-able on every chain — don't trade the privacy model for reach.
