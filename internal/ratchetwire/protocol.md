# E2 / Ratchet carrier protocol

`0xE2` is Spore's forward-private message mode. It is mandatory for a new
conversation; `0xE1`, DERO native short whispers, and the old one-shot body
path are legacy-only and must never be selected as a silent fallback.

## Carrier invariant

DERO, EVM, and Solana carry an opaque E2 pointer. `spore-peer` is an off-chain
body transport, not a chain carrier; Monero currently uses a separate
peer/mailbox rendezvous signal.

V1 canonical pointer:

```text
version(1) || reserved(1) || route(32) || cid(32) || burn_deadline(8 LE)
```

V2 canonical pointer appends the portable Iroh locator:

```text
version(2) || reserved(1) || route(32) || cid(32) || burn_deadline(8 LE) || iroh_blake3(32)
```

`cid` is always `SHA-256(serialized E2 frame)` and remains the integrity
commitment. `iroh_blake3` is only a fetch locator; receivers verify the body
against `cid` before parsing or decrypting it. V1 is byte-exact and unchanged.

DERO's 111-byte payload-0 limit cannot hold an extra 32-byte field. DERO V1
uses typed `W=0xE220` plus `R/C/D`. Compact V2 uses the distinct marker
`W=0xE221` plus `I/C/D`: `I` carries the Iroh hash and the redundant `R` route
is omitted. The receiver skips only that route comparison; the SHA-256 CID,
frame deadline, and ratchet/session checks remain. V1 readers reject `0xE221`
rather than downgrade. Tests enforce the payload-0 size limit.

EVM and Solana use the canonical binary or JSON form and retain both route and
locator. Monero's current payment-id signal is only eight bytes and cannot carry
the pointer; it must use a peer/mailbox rendezvous signal and must not pretend
the deprecated standalone payment-ID field is a complete E2 carrier.

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

The Go package implements the framing, V1/V2 pointer codecs, TTL/CID checks,
endpoint-local session table, and adversarial unit coverage. `cmd/spore` routes
`send-e2`/`recv-e2` through this package. Local unit and loopback peer tests do
not prove a mined mainnet round-trip; keep live-chain status separate and never
fall back to E1/native plaintext when an E2 carrier is unavailable.
