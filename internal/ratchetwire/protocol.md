# E2 / Ratchet carrier protocol

`0xE2` is Spore's forward-private message mode. It is mandatory for a new
conversation; `0xE1`, DERO native short whispers, and the old one-shot body
path are legacy-only and must never be selected as a silent fallback.

## Carrier invariant

DERO, EVM, Solana, Monero, and `spore-peer` carry only a pointer:

```text
version(1) || reserved(1) || route(32) || cid(32) || burn_deadline(8 LE)
```

The pointer contains no plaintext, ratchet header, X3DH handshake, or private
key. `cid = SHA-256(serialized E2 frame)`. The frame is stored off-chain with
a hard TTL and is deleted/reaped at expiry. A chain observer can retain the
pointer and ciphertext forever, but cannot obtain the body after reaping; if a
body copy was retained elsewhere, the ratchet still prevents a later identity
key leak from deriving old message keys.

DERO uses typed `W/R/C/D` arguments because its transaction payload field is
CBOR typed. EVM and Solana use the canonical binary form or their opaque data
field. Monero's current payment-id signal is only eight bytes and cannot carry
the pointer; its implementation must use a peer/mailbox rendezvous signal and
must not pretend the deprecated standalone payment-ID field is a complete E2
carrier.

## Off-chain frame

```text
0xE2 || flags(0) || session_id(8) || handshake_len(2 LE) ||
message_len(4 LE) || optional X3DH handshake || ratchet message
```

The first frame includes the authenticated X3DH handshake. Continuation frames
include only the Double Ratchet message. Ratchet message headers are AEAD
associated data. The session table is endpoint-local, persisted only through a
protected state store, and never placed in the mailbox or chain body store.

## Required endpoint behavior

- Verify the signed prekey bundle before deriving a session.
- Allocate and consume one OPK atomically; reject reuse.
- Reject unknown versions, malformed lengths, mismatched session IDs, expired
  frames, duplicate initial handshakes, replayed ratchet messages, and gaps
  beyond the configured skipped-key bound.
- Persist state after every send/receive transition before acknowledging the
  message. A restart must not roll a sending counter backward.
- Erase skipped keys after use/TTL and erase session state on conversation burn.
- If an E2 request cannot be fulfilled, fail closed. Never silently emit E1,
  DERO-native plaintext/one-shot payloads, or a static long-body envelope.
- Keep plaintext out of chain payloads, peer body logs, mailbox operator logs,
  and persistent transport metadata.

The current Go package implements the framing, pointer codecs, TTL/CID checks,
endpoint-local session table, and adversarial unit coverage. The command/chain
scanner still needs to call this package for live send/receive before E2 can be
called shipped on mainnet. Until that wiring is complete, the legacy paths are
not future-private and must remain explicitly labelled as such.
