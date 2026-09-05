# Mycelium — M³: Mycelium Multi-chain Messenger

*Vision / architecture note. Mycelium was built and verified live on DERO
(short no-relay whisper, long nobody-but-us bodies, rooms that rot). This doc
sketches the expansion: the same core running on every private chain, joined by
a shared off-chain relay fabric.*

---

## 1. What mycelium actually is (don't lose this)

M³ (Mycelium Multi-chain Messenger) is NOT a chain. It is a **transport + coordination layer** that rides on
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
| **EVM-compatible** | ⚠️ calldata/events public; m³ ECDH supplies secrecy | wallet/signer | Go `internal/evm` backend built |
| **Monero** | ⚠️ different model | wallet RPC | real work — see §3 |
| **other privacy chains** | varies | varies | same rule: needs the 2 primitives |

## 3. The Monero wrinkle (be honest)

Monero's tx payloads are NOT a general message field like DERO's. Monero has:
- `tx_extra` — free-form bytes, but **not encrypted to a recipient key** the way
  DERO encrypts payload-0.
- Payment IDs / integrated addresses — for identifying payments, not messaging.
  Modern Monero (≥0.18) only allows **8-byte** payment IDs.

So a "whisper on Monero" can't ride native per-recipient payload encryption the
way it does on DERO. The honest model (matching `internal/xmr`, built):

- **XMR tx = a knock, not content.** The backend posts a dust transfer whose
  8-byte payment id carries a short mycelium signal (a reference/knock), never
  the full whisper or pointer (which don't fit 8 bytes).
- **Content rides off-chain rendezvous** (chain-agnostic, already in the core),
  keyed by that signal — the actual private body never sits on-chain.
- **Monero gives m³ identity + a payment rail**, not an encrypted-message
  channel. The rendezvous layer does the private delivery.

`internal/xmr` implements `chain.Chain` over the Monero wallet RPC
(`transfer` with payment id, `get_transfers`, `get_address`, `get_height`) and
is **mock-verified** (seam + payment-id→signal flow tested with a fake wallet
RPC). It needs **live verification against a real `monero-wallet-rpc`** — e.g.
the Hetzner node running an XMR node — before it's trusted the way DERO is.

## 4. The interconnection model — the mycelium relay fabric

The stack treats **substrate as replaceable delivery, not authority**. The
transport seam can be any p2p/gossip substrate (Waku/Iroh/libp2p, or the
node's own P2P). Mycelium slots in at the transport seam:

```
mycelium app (whisper / rooms / long-body)
   -> mycelium core (ECDH crypto, rendezvous, compost, UI)   [chain-agnostic]
      -> signer seam:  DERO | Monero | EVM                  [per-chain]
      -> transport seam: node P2P | substrate mesh (Waku/Iroh/libp2p)
           -> mycelium relay nodes = the shared "mycelium relay" fabric
```

**Mycelium relay nodes as the fabric:** an always-on relay node connects
mycelium instances across chains — a DERO user and an EVM user both reach
their local relay node, which forwards the encrypted pointer/body across the
substrate mesh. The node relays ciphertext it cannot read (same "box holds no
keys" property as mycelium rooms).

**Interchain mycelium (DERO wallet ↔ EVM wallet) — the honest model:**
direct point-to-point encryption across chains is impossible (different key
crypto). What IS possible is the **cross-chain rendezvous / relay**:
1. Sender encrypts the body to a key the recipient can derive by proving control
   of both wallets (a cross-chain identity proof — a cross-chain settlement
   problem, NOT a mycelium messenger problem).
2. The pointer/notification crosses chains via the mycelium relay mesh.
3. Delivery is single-chain; cross-chain is signaling + handoff.

## 5. Donation addresses on every chain

Because mycelium is identity = your wallet address on whatever chain you're on,
a "mycelium node/relay" operator can advertise **one address per supported
chain** (DERO / XMR / EVM) as the donation rail. This is trivial to
add once the signer seam is per-chain — a config file listing
`{chain: address}` and a `mycelium donate` command that prints the right one.
The relay operator's cross-chain identity is just "the entity controlling these
addresses" — the same cross-chain-proof problem as §4.

## 6. Build order (suggested)

1. **Lock the signer seam** — abstract `internal/dero` behind an interface so a
   chain backend is a clean swap. (Refactor, no behavior change; test stays
   green.)
2. **Second chain: EVM-compatible** — the Go `internal/evm` backend (built)
   rides any EVM RPC. Proves the seam on a second chain.
3. **Relay fabric interconnection** — mycelium relay node (encrypted pointer
   forwarding across the substrate mesh).
4. **Monero backend** — identity + rendezvous delivery, no reliance on native
   payload encryption.
5. **Donation scheme** — per-chain address config + `mycelium donate`.
6. Cross-chain identity proof (DERO↔EVM) — the hard piece, gated on
   that work.

## 7. Guardrails (from how it was built)

- **Keep the core chain-agnostic.** Never bake DERO semantics into the crypto /
  rendezvous / rooms / UI layers. DERO is one backend.
- **Content stays nobody-but-us.** The relay fabric relays ciphertext only; it
  must never hold a key. If a substrate can read the body, it's not mycelium.
- **Compost still means rot.** Bodies + keys must remain ephemeral and
  erasure-able on every chain — don't trade the privacy model for reach.
