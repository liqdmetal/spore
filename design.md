# Compost — a compostable messenger on DERO

Messages that rot. The body never enters a block; the key never survives the
exchange. What stays on-chain is a hash and a dead public key — permanently
inert no matter what breaks later.

## The two hard facts this design is built around

1. **You cannot delete bytes from a DERO block.** Immutability is the point. So
   "compostable" means one of two things: (a) the *key* is erased so the
   ciphertext is permanent garbage, or (b) the *data never goes on-chain*.
2. **The tx message field is ≤111 bytes CBOR** — too small for a body
   regardless. Bulk must live off-chain.

Compost does both.

## Architecture: Model A (mailbox)

Each endpoint runs its own `compost daemon` — its **mailbox**. There is no
shared or third-party store. A sender pushes the encrypted body straight to
the recipient's daemon, then posts the anchor on-chain.

| Layer | Where | Holds | Compost mechanism |
|---|---|---|---|
| Body | recipient's mailbox daemon (durable DiskStore) | the actual ciphertext | TTL + reaper evicts it; never on chain; never in a third party's hands |
| Anchor | on-chain tx message field (4 CBOR args, 91 B) | commitment hash + ephemeral pubkey + deadline + flags | a hash and a dead key — inert by construction |
| Key | endpoints only | ephemeral X25519 (sender `a`, recipient rotating `b`) | erased after use |

Privacy property: the only node that ever holds a given body is the intended
recipient's own daemon, for at most the TTL window. No aggregator can correlate
the on-chain anchor with a body's network origin, because no node holds many
conversations' ciphertext.

The store interface is transport-agnostic: a durable `DiskStore` is the mailbox
backend; the HTTP client/server are the push/receive seam. A p2p inbox or
RelayOS store with the same contract can replace the HTTP seam without touching
crypto or anchors.

Each anchor rides inside a minimum-postage transfer (1 atomic unit = 0.00001
DERO). Postage must be non-zero: the wallet scan treats a transfer whose
recipient balance is unchanged as a ring-member decoy and never surfaces it to
`get_transfers` (derohe `daemon_communication.go`).

## Crypto

- X25519 ephemeral ECDH: sender picks one-time `(a, aG)`; recipient advertises
  rotating `(b, bG)`. Shared secret `s = a·bG`.
- HKDF-SHA256(s, salt=∅, info="compost/v1/key"|"compost/v1/nonce") → 32-byte
  AEAD key and 24-byte nonce, both derived from the per-message secret.
- XChaCha20-Poly1305 for the body (24-byte nonce, misuse-resistant).
- Body CID = sha256(ciphertext): doubles as the mailbox key and the on-chain
  commitment.

## Anchor wire format

The DERO message field is 111 bytes (`PAYLOAD0_LIMIT`) of CBOR-encoded
`rpc.Arguments`. Compost packs four typed arguments (measured 91 bytes CBOR):

| name | type | content |
|---|---|---|
| `K` | H (32B) | sender ephemeral X25519 pubkey `aG` → ECDH handle |
| `C` | H (32B) | body CID = sha256(ciphertext) → mailbox key + commitment |
| `D` | U | burn deadline, unix seconds |
| `F` | U | meta = version | kind<<8 | flags<<16 |

No plaintext, no ciphertext, no long-term key material ever rides the anchor.

## Why this is "compost" and not just "encrypted forever"

- After the sender erases `a` and the recipient rotates + erases `b`, the
  shared secret is unreconstructable by anyone, including the participants.
- The anchor holds only `aG` (public), a CID (a hash), and a deadline.
- Kills harvest-now-decrypt-later: even a quantum adversary with the full chain
  + full store gets nothing — key material never left the endpoints and the
  body never touched the chain.
- Forward secrecy + post-compromise recovery via key rotation (grace window of
  one previous key).

## Channels: compostable IRC (three tiers)

Group chat reuses the same "body off-chain, key-rotates" principle, but broadcast
over a no-carrier fabric needs a rendezvous point. The **channel box** is that
point: it relays TTL-bounded lines and tracks presence. It never holds a channel
key, so a private room's ciphertext passes through unreadable even to its
operator.

| Tier | Channel key | Who reads live | After TTL |
|---|---|---|---|
| Unicast | per-message ephemeral ECDH | only recipient | gone + key erased |
| Private room | shared `Key`, members only | members (box holds unreadable ciphertext) | gone + key rotated |
| Public room | none | anyone connected to the box | readable live, gone after TTL |

Privacy is enforced by **encryption at the endpoints**, not by the box deciding
who may read. Access to the key (membership, DERO-signature identity, invites) is
a separate layer the box deliberately does not own.

Presence lives on the always-on box (a heartbeat window): you cannot learn if an
offline peer's own daemon is up — it is the thing that would answer. Unicast
direct-send shows only best-effort reachability (last ack / push success).

Endpoint channel crypto: a shared 32-byte `Key` per private room; each line
sealed under HKDF-derived per-channel key with a fresh random XChaCha20 nonce
(nonce rides in the clear; the box never sees the key). Sender's line seq comes
from the box after posting, so crypto uses no shared sequence state.

## Honest residual weaknesses

- **Metadata persists.** The anchor is a real on-chain tx; ring sigs hide the
  sender but "a message was exchanged at height H" is observable forever.
- **The anchor is forever.** A permanent tombstone, semantically dead.
- **Key erasure is unverifiable.** No portable proof a device overwrote memory.
  TEE/SGX would harden it but adds a trust boundary DERO's ethos avoids.
- **Compost = unrecoverable by design.** Miss the TTL window and it's gone.
- **Recipient must be reachable at send time** (Model A push). Offline mailbox
  delivery requires store-and-forward, which reintroduces a carrier and its
  metadata exposure — the one honest limit of the no-third-party design.

## Status

Verified live on DERO mainnet (2026-09-05), Model A (mailbox):
- crypto, anchor, session, DiskStore, HTTP push seam all unit-tested (green),
  including restart-durability and TTL-reap.
- `compost daemon` = durable inbox + chain scanner + decrypt, one process. Body
  persisted on disk (0600), survives restart, reaped at TTL.
- `compost send` pushes the body to the recipient's mailbox URL, then posts the
  minimum-postage anchor. Message mined + decrypted exactly once, on mainnet,
  with no shared store.
- Remaining work: key rotation / peer-inbox discovery (KEYROTATE), a real p2p or
  RelayOS inbox seam, systemd units to keep the daemon always-on.

## Channels: verified

`internal/channel` (box + client + endpoint crypto) unit-tested green:
public roundtrip, private seal/open (box stores ciphertext, wrong/missing key
reads nothing), seq-dedupe polling, presence heartbeat + stale eviction, line
TTL reap, per-channel ring cap. Live smoke test (local box, no chain): bob
posted a private line in `#team`, read it back with the key; eve with no key got
nothing; the raw box line was unreadable base64 ciphertext even to the operator;
presence listed both online nicks. CLI: `compost channel` runs a box,
`compost chat -box ... -channel ... -nick X [-key HEX] [-say|-online]` joins one.
