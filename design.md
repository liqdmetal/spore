# Spore — a forward-private, compostable multi-chain messenger

The target invariant is stronger than "encrypted on-chain": per-message keys
must rotate and die so a later device-key compromise cannot unlock old
conversation history. Bulk bodies stay off-chain and expire; chains carry only
opaque delivery records.

Current direct whispers and 0xE1 envelopes are encrypted, but are not yet
forward-secret. `internal/ratchet` is the mitigation being wired into the
conversation path. Do not claim the target invariant for a path until its
ratchet wire integration and adversarial tests pass.

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

### 1. Whisper — short, no-infra signal (the on-chain seam)
A short line rides the payload (measured: ~95 ASCII chars max, one sentence).
Real tx, propagates P2P, confirms in ~1 block. No box, no relay, no exposed IP —
each party talks only to its own wallet+node. On DERO it is point-to-point
encrypted natively. `internal/whisper` turns this into a chain-agnostic codec
(kind byte 0x01 text / 0x02 pointer, length-prefixed) shared by every backend.

### 2. Long message — nobody but sender & receiver (rendezvous)
Bulk content never rides a whisper. Sender encrypts it to the recipient's
long-term key under a fresh ephemeral, stores the ciphertext **on their own
node**, and sends a whisper/anchor carrying only a **pointer** (sender ephemeral
pub + body CID + deadline). When the recipient is available they fetch the body
peer-to-peer (over the node's existing P2P channel — no new open port), verify
the CID, decrypt, then both sides rotate + erase keys. Nobody but sender and
receiver ever holds the bytes or the key, and after fetch the body + key are
gone. The on-chain record is a dead pointer.

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

## Live end-to-end verified (2026-09-05, DERO mainnet)

Full nobody-but-us long-message path proven live on the node:
1. Alice `whisper keygen` + `whisper send-long` → body encrypted to Bob's key,
   held on Alice's node (disk 0600), pointer-whisper (C cid + K ephemeral) mined
   on-chain.
2. Alice runs `spore-peer serve` on her reachable node.
3. Bob `whisper recv -key bob.key -peer-addr alice:port` → saw the pointer,
   fetched the body over the peer transport, decrypted with his key → printed
   the message. Nobody but Alice and Bob ever held it.

CLI: `spore whisper {send|send-long|recv|keygen}` + the Rust `spore-peer`
transport (derohe-rs); the multi-chain `spore msg ... -chain` path is the
same model on EVM/Solana/XMR.
