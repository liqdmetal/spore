# Mycelium — a compostable messenger on DERO

Messages that rot. The body never enters a block; the key never survives the
exchange. What stays on-chain is a hash and dead public keys — permanently
inert no matter what breaks later.

## The one hard fact

DERO's on-chain tx message field is `PAYLOAD0_LIMIT` = 111 bytes of CBOR-encoded
Arguments. Content can never be deleted from a block. So "compostable" means:
(a) the key is erased so ciphertext is permanent garbage, and (b) bulk never
goes on-chain at all. Every layer below obeys both.

## Two transport families, one privacy goal

DERO encrypts every tx payload **point-to-point** to the recipient's wallet —
there is no stock "group reads off the mempool." So the architecture is:

### 1. Whisper — short, no-infra signal (the on-chain seam)
A short line rides the 111-byte payload (measured: ~95 ASCII chars max, one
sentence). Real tx, propagates P2P, confirms in ~1 block. No box, no relay, no
exposed IP — each party talks only to its own wallet+node. Point-to-point
encrypted by DERO natively.

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

## Crypto

- X25519 ephemeral ECDH for unicast + long bodies; shared secret → HKDF-SHA256 →
  XChaCha20-Poly1305 (24B random nonce, never reused per message).
- Body CID = sha256(ciphertext): retrieval key + on-chain commitment + tamper
  check (a fetched body whose sha256 ≠ CID is rejected before decrypt).
- Key rotation + erasure = the "mycelium": after fetch / on rotation, old bodies
  are unrecoverable even by participants.

## Honest residual limits

- **Metadata persists** at the layer used: a whisper tx is chain-wide visible
  ("a tx at ~time", sender hidden by ring sig). Rendezvous bodies are only
  transferred when both peers are online; the whisper pointer is permanent but
  dead.
- **Long-message fetch needs both peers online simultaneously** (store-and-
  forward tax): if the receiver is down, the body waits on the sender's disk.
- **Group broadcast still needs a relay or an SC** — no-relay is unicast/sparse
  by construction.

## Status

Verified live on DERO mainnet (2026-09-05): `mycelium send`→anchor mined,
`mycelium daemon` recv→decrypted exactly once, bodies survive restart (DiskStore).
Whisper, rendezvous, and longmsg are unit-tested green (incl. wrong-key + tamper
rejection). Channel box + web chat build. TELA UI shell is the remaining layer.

## Live end-to-end verified (2026-09-05, mainnet)

Full nobody-but-us long-message path proven live on the node:
1. Alice `whisper keygen` + `whisper send-long` → body encrypted to Bob's key,
   held on Alice's node (disk 0600), pointer-whisper (C cid + K ephemeral) mined
   on-chain (height 7,573,951).
2. Alice runs `mycelium-peer serve` on her reachable node.
3. Bob `whisper recv -key bob.key -peer-addr alice:port` → saw the pointer,
   fetched the body over the peer transport, decrypted with his key → printed
   the 167-byte message. Nobody but Alice and Bob ever held it.

CLI: `mycelium whisper {send|send-long|recv|keygen}` + the Rust `mycelium-peer`
transport (derohe-rs).
