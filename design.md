# Spore — a forward-private, compostable multi-chain messenger

The target invariant is stronger than "encrypted on-chain": per-message keys
must rotate and die so a later device-key compromise cannot unlock old
conversation history. Bulk bodies stay off-chain and expire; chains carry only
opaque delivery records.

Current direct whispers and `0xE1` envelopes are encrypted but **not**
forward-secret, and remain **compatibility-only**. The forward-private path is
`0xE2` (`internal/ratchetwire`): X3DH + Double Ratchet over every carrier,
off-chain TTL bodies, durable encrypted endpoint state, single-use prekeys, and
adversarial tests green. New conversations use `0xE2`; the target invariant
holds **for the `0xE2` path only** — never claim it for a legacy whisper/`0xE1`
path. See [`docs/RATCHET.md`](docs/RATCHET.md) and
[`docs/CARRIER_MATRIX.md`](docs/CARRIER_MATRIX.md).

Spore is chain-agnostic by design. The **seam** (`internal/chain`: the
`Chain` interface + `Watch` poller) is what any chain plugs into; `internal/whisper`
is the canonical codec; `internal/secure` is the E2E envelope for chains that
don't encrypt natively. This doc spells out the design on the tree that proved
it first (DERO) and how the seam generalizes.

## The one hard fact

DERO's on-chain tx message field is `PAYLOAD0_LIMIT` = 111 bytes of CBOR-encoded
Arguments. Content can never be deleted from a block. So "compostable" means:
(a) the key is erased so ciphertext is permanent garbage, and (b) bulk never
goes on-chain at all. Every layer below obeys both.

## Two transport families, one privacy goal

DERO encrypts every tx payload **point-to-point** to the recipient's wallet —
there is no stock "group reads off the mempool." So the architecture is:

### 1. DERO E2 message — short or long
Every new DERO message uses the same `0xE2` pointer/body path. X3DH
establishes the session and Double Ratchet encrypts the body with evolving
message keys. The body is stored off-chain under a TTL; DERO receives only the
opaque pointer and minimum postage in a ring-16 transaction by default (ring 8
is optional). The carrier never receives plaintext or ratchet ciphertext.

Historical native whispers and one-shot long-body records remain receive-only
compatibility data. They are not forward-private and are not the new-send path.

### 2. Other chains — same E2 body, different pointer carrier
The same ratcheted body/store is used across supported carriers. The carrier
gets only the canonical pointer; unsupported carriers refuse rather than
silently downgrading to a legacy envelope.

### 3. Public compostable chans (IRC-style)
Channel box relays TTL-bounded lines; public rooms readable live by anyone,
gone after TTL. Separate lane from the hard-privacy paths. (See design of
`internal/channel`.)

## The E2E secure layer (for chains that don't encrypt)

DERO is native. But EVM calldata/events, Solana inbox PDAs, and Monero records
are **public** — no per-recipient encryption at the chain. `internal/secure`
restores the privacy model:

```
kind 0xE0 ‖ eph_pub(32) ‖ nonce(24) ‖ XChaCha20-Poly1305 ciphertext
```

- Sender does X25519 ECDH between a fresh ephemeral and the recipient's public
  key; shared secret → HKDF-SHA256 → XChaCha20-Poly1305 (24B random nonce, never
  reused per message).
- What rides the chain (EVM calldata, a Solana inbox record, an XMR signal) is
  the **envelope** — ciphertext the chain and any observer cannot read. Only the
  recipient's private key derives the session key and decrypts.
- Metadata still leaks at that layer (a tx/record exists), same honest limit as
  DERO's ring-sig-surfaced "a tx at ~time."

`internal/crypto` holds the primitives — X25519 ECDH, HKDF-SHA256,
XChaCha20-Poly1305 — plus CID = sha256(ciphertext) and key zeroing (hygiene).
`MyceliumMailbox.sol` (EVM) and the Solana BPF mailbox program are durable
inboxes that store envelopes; the program/contract never holds a key.

## Crypto

- X25519 ephemeral ECDH for unicast + long bodies + the secure envelope; shared
  secret → HKDF-SHA256 → XChaCha20-Poly1305 (24B random nonce, never reused per
  message).
- Body CID = sha256(ciphertext): retrieval key + on-chain commitment + tamper
  check (a fetched body whose sha256 ≠ CID is rejected before decrypt).
- Key rotation + erasure = the "spore": after fetch / on rotation, old bodies
  are unrecoverable even by participants.

## Honest residual limits

- **Metadata persists** at the layer used: a whisper tx is chain-wide visible
  ("a tx at ~time", sender hidden by ring sig on DERO). On EVM/Solana/XMR the
  tx/record exists too — content is private only through the envelope.
  Rendezvous bodies are only transferred when both peers are online; the whisper
  pointer is permanent but dead.
- **Long-message fetch needs both peers online simultaneously** (store-and-
  forward tax): if the receiver is down, the body waits on the sender's disk.
- **Group broadcast still needs a relay or an SC** — no-relay is unicast/sparse
  by construction.
- **Cross-chain direct messaging is impossible** (different key crypto);
  cross-chain = rendezvous/relay + identity proof (future, gated).
- **Solana cross-wallet delivery** is gated on both parties running the backend
  (the program requires the recipient to sign; the client self-messages today).

## Status

- **DERO** — live, mainnet-verified (2026-09-05): `spore whisper send`→anchor
  mined, `whisper recv`→decrypted exactly once, long nobody-but-us path proven
  live, bodies survive restart (DiskStore). Whisper, rendezvous, and longmsg are
  unit-tested green (incl. wrong-key + tamper rejection). Channel box + web chat
  build.
- **EVM** — `internal/evm` **live-verified** on a local anvil node (round-trip
  send/recv; calldata carries the m³ envelope). `MyceliumMailbox.sol` written,
  not yet deployed.
- **Solana** — `internal/solana` + BPF mailbox program **deployed and
  live-verified on mainnet** (program `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs`,
  v2). Client self-messages; cross-wallet pending.
- **Monero** — `internal/xmr` built + **mock-verified** only (short ≤8-byte
  signal on payment id; content off-chain rendezvous). A pruned `monerod` is
  syncing (~60%) on the Hetzner node; live-verify needs a real
  `monero-wallet-rpc`.

See `README.md` (authoritative chain-status table) and `WHISPER.md` (the
no-relay unicast architecture) for details.

## Live carrier evidence and current send policy

The DERO carrier and wallet RPC wire shape have been live-verified. The current
new-send policy is stricter than the historical smoke path:

- new short and long DERO command names enter canonical `0xE2`;
- the body is off-chain and ratcheted; DERO carries only the pointer;
- DERO message posts default to ring size 16 and accept only 8 or 16;
- old native/`0xE1`/one-shot records remain receive-only compatibility data.

Parser, backend, full-suite, vet, build, and browser checks prove this routing
and policy. A newly mined live transaction should still be treated as a
separate carrier round-trip check, not inferred from unit tests.
