# Spore — message data flow: where bytes are encrypted, decrypted, and rot

*Detailed, byte-level walk of what actually happens to a message's data as it
moves through spore, on every chain. Every claim cites the file+function that
does it. Companion to `WIRE_SPEC.md` (the byte formats), `RATCHET.md` (the
forward-secrecy layer), and `FULL_PICTURE.md` (the deployment shapes).*

---

## 0. The whole model in one table

|| | **Short E2 message** | **Long E2 body** |
||---|---|---|
|| Content size | normal message body | any size |
|| Where content lives | off-chain body store | off-chain body store |
|| What rides the chain | canonical opaque E2 pointer | canonical opaque E2 pointer |
|| Encrypted by | X3DH + Double Ratchet | X3DH + Double Ratchet |
|| Decrypted by | recipient's E2 endpoint | recipient's E2 endpoint |
|| Rot / future-decrypt risk | consumed message key erased | consumed message key erased + body reaped at deadline |
|| Codec | `internal/ratchetwire` + chain codec | `internal/ratchetwire` + chain codec |

---

## 1. Historical native whisper — receive-only compatibility

> This section documents old `W`/`T` records so existing mail remains
> decodable. It is **not** a new-send protocol. All new DERO short and long
> commands enter the E2 pointer/body section below.

### 1.1 Historical sender record

**Step 1 — build the canonical payload** (`whisper.BuildArgs`,
`internal/whisper/whisper.go`):

```
Arg "W" uint64 = WhisperV1 (0x571)      // version/kind marker
Arg "T" string = your message text      // ≤80 bytes (MaxTextLen)
```

These become DERO `rpc.Arguments` — typed name→value pairs, **not** raw bytes.
DERO packs them into the tx's message field, which is capped at
`PAYLOAD0_LIMIT` = **111 bytes** of CBOR (the hard on-chain budget; that is why
`MaxTextLen = 80` — measured to fit ~90 ASCII after CBOR framing).

**Step 2 — the DERO wallet encrypts the whole tx point-to-point.**
The tx (including its payload) is a normal confidential DERO transfer of
minimum postage (1 atomic unit — a 0-amount transfer is treated by derohe as a
ring-member *decoy* and silently skipped, `internal/dero/poster.go`). DERO's
own cryptonote-style scheme encrypts the payload **to the recipient wallet**.
So on DERO, confidentiality is **native**: no spore-layer encryption is added
by default (`secureSendCodec`, `cmd/spore/main.go`: *"DERO already encrypts
natively"*).

**Step 3 — broadcast.** The tx propagates over DERO P2P and mines into a block
(`dero.Client.PostPayload`). The message is now on-chain, forever, as DERO
ciphertext.

### 1.2 Receiver side

The recipient's wallet decrypts the payload automatically when scanning and
returns it as `payload_rpc` in `get_transfers` (`internal/dero/chain.go`
`ListIncoming`). `whisper.Recv`/`ParseArgs` pull the `W`/`T` fields out
(`internal/whisper/whisper.go`). Two receive speeds:

- **L3 (~1 block, ~18s):** the wallet sees it in `get_transfers` after mining.
- **L1 (~1–2s):** a node polling its own **txpool** (`internal/daemon`) can
  catch the tx *before* it mines. The receiver still needs the wallet key to
  read the payload — the pool catch just gets you the timing win.

### 1.3 On public chains (EVM / Solana / XMR)

These chains expose calldata/events/inbox records **in the clear** — no native
per-recipient encryption. So the short line is wrapped in a **spore envelope
before** it rides the chain. That envelope is the subject of §2.

---

## 2. The spore envelope (0xE1) — E2E on chains that don't encrypt

Where DERO is native, EVM/Solana/XMR are public. `internal/secure` restores
the privacy model there (`secure.Encrypt`, `internal/secure/secure.go`). This
is applied whenever the user supplies `-key` + `-peer-pub`, and is **mandatory
(strict)** for receive on public chains (`secureRecvCodec` → `NewRecvCodec`).

### 2.1 Wire layout (byte-exact)

```
kind(1) || sig_pub(32) || eph_pub(32) || nonce(24) || sig(64) || ciphertext
 0xE1                                                              (16-byte AEAD tag inside)
```

Fixed prefix **before** the content = `1 + 32 + 32 + 24 + 64 = 153` bytes; the
ciphertext is XChaCha20-Poly1305 output (content + a 16-byte tag). Total fixed
overhead on top of content = **169 bytes** (the code's `Overhead` const =
168 counts the tag but not the kind byte; the AEAD tag rides inside the
ciphertext, so it isn't a separate prefix — see `secure.go` `sealWith`).

### 2.2 Encryption, step by step

1. **Fresh ephemeral keypair** per message: `crypto.GenerateKey()` — never
   reused, erased after use (`crypto.Zero`).
2. **ECDH** `secret = X25519(eph_priv, recipient_pub)`
   (`crypto.SharedSecret`).
3. **Key derivation** `aead_key = HKDF-SHA256(secret, info=
   "spore/e2e/v1/key" || eph_pub || recipient_pub)` (`crypto.DeriveKeyBound`).
   Both public keys are bound into the info → the same secret with a different
   peer yields an unrelated key (unknown-key-share resistance, key separation
   per peer pair).
4. **Nonce** = 24 fresh random bytes (in-band, public).
5. **Seal** `ciphertext = XChaCha20-Poly1305(key, nonce, canonical_payload)`
   (`crypto.Seal`). Authenticated encryption: tamper fails decryption.
6. **Sign** the whole envelope: the Ed25519 signing key is **deterministically
   derived** from the sender's X25519 scalar (`sigKeypair`:
   `seed = SHA256("spore/sig/v1/seed" || sender_x25519_priv)`), so one secret
   at rest yields both the encrypt key and the sign key — no second secret to
   exchange. The signature covers
   `"spore/env/v2" || sig_pub || eph_pub || nonce || recipient_pub || sha256(ct)`
   (`transcript`). This binds sender key + ephemeral + nonce + the
   **recipient's** key + ciphertext → kills forgery, cross-recipient replay,
   and ciphertext swap.

### 2.3 Decryption (receiver, `secure.Open` → `openSigned`)

Order matters (normative, also in `WIRE_SPEC.md` §3):

1. Parse kind byte; `0xE1` → signed path.
2. **Verify the Ed25519 sig FIRST**, before any ECDH/AEAD work. Bad sig →
   reject (`ErrSig`). The transcript uses the receiver's *own* derived pub.
3. ECDH `secret = X25519(our_priv, eph_pub)`.
4. Derive `key` with `eph_pub || our_pub` bound.
5. `XChaCha20-Poly1305` open; return the inner canonical payload.

Strict mode (`NewRecvCodec`) refuses anything that is not a signed `0xE1`
envelope — closing the plaintext-injection hole on public chains. The sender
can additionally be **pinned**: a recipient's contact list of sig pubs means
only envelopes signed by an accepted identity arrive (`Codec.Pin`).

### 2.4 The DERO nuance

On DERO, the base codec is the DERO codec (no 0xE1 wrap) *unless* the user
explicitly passes spore keys — then the envelope rides *inside* DERO's native
encryption (double protection). On DERO receive, `NewRecvCodecLegacy` is used
so both plaintext-native whispers and envelopes decode, because DERO's own
encryption is the trusted secrecy layer.

---

## 3. E2 body and pointer — short or long (`internal/ratchetwire`)

New DERO messages of any size use the same forward-private path. The body is
sealed by X3DH + Double Ratchet, placed in the configured off-chain store, and
represented on DERO by an opaque pointer. The old native whisper and one-shot
long-body decoders remain only for records created before this upgrade.

### 3.1 Sender (`ratchetwire.DurableEndpoint.SendFirstSession` / `SendNext`)

1. Read the short body from stdin or `-msg-file`; read a long body from `-file`.
2. X3DH establishes the first session against the pinned recipient bundle;
   subsequent messages use the durable Double Ratchet session.
3. Derive a one-time message key, seal the frame with ratchet-header AAD, and
   advance the sending chain. Consumed keys are erased.
4. Store the encrypted frame by CID with a deadline. The body store never gets
   plaintext.
5. Give the DERO carrier only the canonical opaque E2 pointer. The wallet posts
   that pointer as the transaction payload.

### 3.2 The pointer on-chain

The pointer is encoded by `ratchetwire.DeroChainCodec`. It carries routing,
version, CID, and expiry metadata only — never plaintext, ratchet ciphertext,
or long-term key material. DERO's wallet wraps that pointer in its normal
confidential transaction transport.

### 3.3 Receiver (`ratchetwire.DurableEndpoint.ReceiveFirst` / `ReceiveNext`)

1. Scan the recipient wallet and accept only valid E2 pointers for the ratchet
   receiver; the bare legacy receiver handles old native payloads separately.
2. Fetch the encrypted body by CID, verify its content address and deadline.
3. X3DH consumes the recipient prekey for a first message; later messages use
   the durable Double Ratchet session.
4. Open with the one-time message key, advance the receive chain, erase the
   consumed key, and return plaintext locally.

### 3.4 Rot (the erase side of E2 bodies)

- The off-chain ciphertext is reaped at its deadline.
- Consumed message keys and old DH state are erased during ratchet advancement.
- A copied ciphertext without the consumed ratchet key is inert after a later
  device-key compromise; the immutable DERO record contains only the pointer.

---

## 4. Compostability — why it is NOT "on chain forever, decryptable one day"

---

## 4. Compostability — why it is NOT "on chain forever, decryptable one day"

This is the core claim and the honest part. Two distinct mechanisms, and you
must keep them separate:

### 4.1 The bulk content is simply not on-chain

Long bodies **never enter a block**. What's on-chain is the pointer: a dead
public key (ephemeral, zeroed), a hash (of ciphertext that's gone), and a
deadline. There is nothing on the ledger for a future attacker to crack —
the ciphertext itself was never written there, and the one node that held it
deletes it at the deadline. **Off-chain rot**: file deleted, ephemeral key
already erased, nobody retains it.

### 4.2 Old records versus new E2 sends

Old native whispers, 0xE1 envelopes, and one-shot long-body ciphertexts remain
on receive-only compatibility paths. Those records do **not** have forward
secrecy and must not be described as E2.

**On public chains, old spore 0xE1 records:**

- The sender uses a fresh ephemeral key per message and erases the ephemeral
  scalar after sealing. That prevents the sender-side ephemeral from becoming a
  long-term archive key.
- But the receiver's long-term X25519 private key is still the other half of
  every historical ECDH exchange. Anyone who records the 0xE1 ciphertexts and
  later steals that recipient key can recompute each historical shared secret
  from the public `eph_pub` in the envelope and decrypt the history.
- Therefore old 0xE1 provides **confidentiality and sender authentication**, not
  forward secrecy. Old one-shot long-body ciphertexts have the same limitation
  if copied before their TTL expires.

New sends on the DERO command aliases do not use either old construction: they
enter the 0xE2 X3DH + Double Ratchet path described in §5.

**On DERO, old native records:** DERO's wallet encrypts the payload for the
transaction's intended recipient, and the recipient wallet can decode it. A
passive chain observer cannot decode it without the relevant wallet secret, but
the native payload scheme is still a long-term-key scheme: a later compromise
of the wallet key can expose recorded historical payloads. DERO's ring privacy
hides transaction relationships; it does not erase message bytes or add
forward secrecy to old native payloads.

**On DERO, new records:** the wallet carries only the canonical E2 pointer;
X3DH + Double Ratchet protects the off-chain body. The native wallet envelope
is a transport wrapper, not the message encryption protocol.

### 4.3 What is genuinely still decryptable, and by whom — the honest row

| Record | Lives forever on-chain? | If the recipient key leaks later |
|---|---:|---|
| Old native whisper on DERO | **yes** | recorded payloads can be retro-decrypted with the relevant wallet secret |
| Old 0xE1 / one-shot body | chain pointer or off-chain copy | old recipient-key compromise can expose the recorded construction |
| New DERO E2 pointer | yes | pointer only; no plaintext or ratchet ciphertext is there |
| New DERO E2 body | no — off-chain, reaped at deadline | past consumed message keys are erased — a later device-key compromise does NOT unlock old 0xE2 history (forward secrecy holds) |

So the promise is **not** "deleted from the chain" — DERO/EVM blocks are
append-only and permanent. The accurate current promise is:

> **Legacy receive paths (0xE1, old native payloads, old one-shot bodies):**
> passive observers cannot read encrypted payloads without a key, but a later
> recipient-key compromise can expose recorded history. They remain receive-only
> compatibility paths.
>
> **DERO command aliases:** `spore whisper send`, `whisper send-long`, and
> `msg send -chain dero`/`msg send-long` now invoke the canonical 0xE2
> X3DH + Double Ratchet sender. Their familiar names select the DERO pointer
> carrier; they do not select the old native or one-shot crypto.
>
> **The 0xE2 path (shipped):** consumed per-message keys are erased and the
> ratchet ciphertext lives off-chain under a TTL, so a later device-key
> compromise cannot unlock the old ratcheted conversation history. The chain
> keeps only a dead pointer. This is the forward-private path used by every
> new send.

## 4.4 Why erasure is not enough without a ratchet

`crypto.Zero` overwrites secrets in memory (best-effort in a GC'd language —
process death is the true erasure, see the docstring in `crypto.go`). For old
records, erasing a one-shot ephemeral does **not** erase the recipient's
long-term private key; those records remain non-forward-private.

The load-bearing fix used by every new DERO send is the ratchet: derive each
message key from a rotating chain, advance the chain, and erase consumed keys
and old DH state. The chain record may remain forever; without the erased
per-message key it is intended to be computationally inert.

---

## 5. Forward secrecy / post-compromise (the ratchet, 0xE2) — SHIPPED

A one-shot envelope is forward-secret *per message* (fresh ephemeral every
message) but a stolen **long-term** key decrypts everything that key could
read. The ratchet layer fixes that for ongoing conversations:

- `internal/ratchet` implements **X3DH + the Signal double ratchet**
  (`RATCHET.md`): a session root key RK ratchets through each DH exchange, and
  every message key MK is derived from a chain key CK via `KDF_CK`. Each
  message uses a **one-time message key**.
- **Forward secrecy:** a stolen device key decrypts only the in-flight window
  (the messages whose MK hasn't been consumed) — never history, because past
  MKs are already erased.
- **Post-compromise security:** after a compromise ends, the next DH ratchet
  step (fresh X25519 on both sides) re-establishes a secret an attacker who
  lost the device can no longer follow.
- **Skipped-key rot:** out-of-order delivery may need buffering; skipped keys
  inherit the message's burn deadline and are swept at Reap/Trim
  (`SweepSkipped`), so an offline gap can't become a permanent key archive.

**Current status (be honest):** the ratchet is implemented, tested (incl. the
deterministic-vector conformance suite), **and wired**: `spore msg send-e2` /
`recv-e2` / `reply-e2` / `forward-e2` drive `internal/ratchetwire` end to end,
with mailbox prekey discovery (`GET /prekey`, single-use batch pops), durable
encrypted session state, and an off-chain TTL body store. The chain carries the
opaque pointer only; substantive content is the ratcheted off-chain body.

**Forward-compostability policy (2026-09):** every NEW message must be 0xE2.
The DERO command names `spore whisper send`, `whisper send-long`, `msg send
-chain dero`, and `msg send-long` are now compatibility aliases for the
canonical X3DH + Double Ratchet pointer/body path. Their carrier is DERO; their
cryptographic format is E2. The old native whisper, 0xE1 envelope, and
one-shot long-body records remain receive-only compatibility paths. The
browser UI sends and receives through `/e2/send` + `/e2/recv` (server holds
the account's ratchet state; the server is your own). Non-DERO legacy send
aliases remain refused rather than silently downgraded.

---

## 6. Encryption/decryption quick-reference (file → function → primitive)

| Where | Function | Primitive |
|---|---|---|
| DERO tx payload encrypt | DERO wallet (derohe), transport wrapper | cryptonote confidential tx around opaque pointer |
| DERO pointer decode | `dero/chain.go` + `ratchetwire` | wallet scan, `get_transfers`, strict E2 pointer decode |
| E2 send | `ratchetwire` `SendFirstSession`/`SendNext` | X3DH + Double Ratchet + XChaCha20 AAD |
| E2 receive | `ratchetwire` `ReceiveFirst`/`ReceiveNext` | prekey verification → ratchet advance → AEAD open |
| E2 body store | `ratchetwire` body store | ciphertext by CID + TTL/reaping |
| Content address | `crypto/crypto.go` `CID` | sha256(ciphertext) |
| Secret erase | `crypto/crypto.go` `Zero` | overwrite |

*Companion files: `WIRE_SPEC.md` (exact byte formats + golden vectors),
`RATCHET.md` (forward-secrecy design), `SENDER_AUTH.md` (attribution/pinning).*
