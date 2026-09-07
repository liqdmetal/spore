# Spore Wire Specification v1

*Source of truth for the canonical payload, envelope, pointer, and spore-peer
transport formats. Golden test vectors: [`interop-vectors.json`](interop-vectors.json)
(regenerate: `go test ./internal/secure/ -run TestGenerateWireSpecVectors`).
Conformance tests: Go `internal/secure` `TestSpec*`; Rust `spore_peer.rs`
`spec_*`. Byte-order note: canonical length prefixes are BIG-endian; the
spore-peer transport length prefix is LITTLE-endian (historical).*

Implementers MUST read this document together with `interop-vectors.json` —
every algorithm below has a vector.

---

## 1. Canonical payload (chain-agnostic, inside every envelope)

    byte 0        kind: 0x01 = text, 0x02 = pointer
    bytes 1..2    payload length, uint16 BIG-endian
    bytes 3..     payload:
                    text     = UTF-8 bytes (length = the uint16)
                    pointer  = eph_pub(32) || body_cid(32), uint16 must be 64

Vector: `"meet me at the garden gate"` →
`01001a6d656574206d65206174207468652067617264656e2067617465`
(see `canonical.encode_text_hex`; pointer vectors under `canonical.*`).

## 2. Envelope v2 (kind 0xE1) — signed, E2E-encrypted

    kind(1) || sig_pub(32) || eph_pub(32) || nonce(24) || sig(64) || ciphertext

Algorithms, in order:

    eph_pub   = X25519(eph_priv)                      eph_priv fresh per message
    secret    = X25519(eph_priv, recipient_pub)
    aead_key  = HKDF-SHA256(secret,
                             info = "spore/e2e/v1/key" || eph_pub || recipient_pub,
                             L = 32)
    nonce     = 24 random bytes (in-band, need not be secret)
    ct        = XChaCha20-Poly1305(aead_key, nonce, canonical_payload)
    sig_priv  = Ed25519 seed = SHA-256("spore/sig/v1/seed" || sender_x25519_priv)
    sig_pub   = Ed25519 pubkey of sig_priv
    sig       = Ed25519.Sign(sig_priv,
                    "spore/env/v2" || sig_pub || eph_pub || nonce
                                   || recipient_pub || SHA-256(ct))

The signature binds the sender key, ephemeral, nonce, RECIPIENT prekey, and
ciphertext: no forgery, no ciphertext swap, no cross-recipient replay.

Legacy v1 (kind `0xE0`, `eph_pub || nonce || ct`, unsigned, unbound HKDF) is
decryptable for migration only; strict receivers refuse it.

## 3. Receiver verification order (normative)

1. Parse the kind byte. Unknown → reject.
2. v2: Ed25519-verify `sig` over the transcript (recipient_pub = own pubkey
   derived from own scalar). Failure → reject BEFORE any ECDH/AEAD work
   matters.
3. ECDH + HKDF + XChaCha20 open. Failure → reject.
4. Strict mode additionally rejects kind 0xE0 and any non-envelope payload.
5. If the receiver pins sender keys, `sig_pub` must be pinned (after step 2).

## 4. CID

    CID = SHA-256(ciphertext bytes)

Double duty: off-chain retrieval key (mailbox `/put/{cid}`, spore-peer serve)
and on-chain pointer commitment. Verified on push, pull, relay, and pre-decrypt.

## 5. spore-peer transport frame (Rust)

    frame = uint32 LE length || payload        (length capped at 64 MiB)
    request payload  = JSON {"cid": "<64 hex chars>"}
    ok    payload    = 0x00 || body            (sha256(body) MUST == cid)
    error payload    = 0x01 || ASCII error     ("404 not found", "400 bad cid",
                                                "500 cid mismatch")

Clients decide by the STATUS BYTE only — never by content sniffing (audit H4:
the old client treated bodies starting with ASCII '4'/'5' as errors, rejecting
~1.6% of random ciphertexts). Old servers (raw body, no status byte) are
accepted only if `SHA-256(whole frame) == cid`.

Vectors under `spore_peer_frame`:
`070000000034343434abcd` (ok, body `34343434abcd` — deliberately starts with
ASCII '4') and `0e00000001343034206e6f7420666f756e64` (error).

## 6. Vector file contract

`interop-vectors.json` fields:

- `fixed_scalars` — the X25519 scalars and nonce every vector is built from.
- `derived_keys` — intermediate values for stage-by-stage verification
  (`aead_key`, `alice_sig_pub`, pubkeys).
- `canonical` — text and pointer encodings.
- `envelope_v2_text` / `envelope_v2_pointer` — full deterministic envelopes
  (`expected_payload_hex`) built via `EncryptDeterministic`.
- `spore_peer_frame` — transport frames computed from the layout above.

A new implementation is conformant when, given `fixed_scalars`, it reproduces
every `expected_*` byte-for-byte, and when its receiver accepts the committed
v2 envelopes while rejecting tampered, cross-recipient, and unsigned variants.
