# Spore — message data flow: where bytes are encrypted, decrypted, and rot

*Detailed, byte-level walk of what actually happens to a message's data as it
moves through spore, on every chain. Every claim cites the file+function that
does it. Companion to `WIRE_SPEC.md` (the byte formats), `RATCHET.md` (the
forward-secrecy layer), and `FULL_PICTURE.md` (the deployment shapes).*

---

## 0. The whole model in one table

| | **Short whisper** | **Long body** |
|---|---|---|
| Content size | ≤ ~90 ASCII chars | any size |
| Where content lives | **in the tx**, on-chain | **on the sender's own node**, off-chain |
| What rides the chain | the line itself | a **pointer** (32B eph pub + 32B CID) |
| Encrypted by (DERO) | DERO native (wallet E2E) | spore X25519, body-side |
| Encrypted by (EVM/Solana/XMR) | spore 0xE1 envelope | spore X25519, body-side |
| Decrypted by | recipient's wallet / spore key | recipient's spore long-term key |
| Rot / future-decrypt risk | see §4 — this is the honest part | keys erased + body reaped at deadline |
| Codec | `internal/whisper/canonical.go`, `dero/chain.go` | `internal/longmsg/longmsg.go` |

---

## 1. Short whisper — the on-chain line

### 1.1 Sender side

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

## 3. Long body — the off-chain message (`internal/longmsg`)

Bulk content **never** rides a block. It lives only on the sender's own node,
encrypted, and is fetched peer-to-peer. The chain carries just a pointer.

### 3.1 Sender (`Endpoint.SendBody`, `internal/longmsg/longmsg.go`)

1. **Pad** the plaintext to a 1024-byte bucket (`padBody`: 8-byte length prefix
   + content + `0x00` pad to the next multiple of `BodyPaddingBucket = 1024`).
   All ciphertext bodies are now indistinguishable by size → defeats
   size-based fingerprinting of message length.
2. **Fresh ephemeral keypair**, `crypto.GenerateKey()`.
3. **ECDH** `secret = X25519(eph_priv, recipient_longterm_pub)`.
4. **Bound keys** `key = DeriveKeyBound(secret, eph_pub, recipient_pub)` and
   `nonce = DeriveNonceBound(...)` — same transcript, both HKDF-derived.
5. **Seal** `ciphertext = XChaCha20-Poly1305(key, nonce, padded_plaintext)`.
6. **CID** `= sha256(ciphertext)` (`crypto.CID`) — the content address doubles
   as the on-chain commitment and the off-chain retrieval key.
7. **Store** the ciphertext in the sender's own disk store, keyed by CID, with
   a **burn deadline** (`store.Put(cid, ct, now+ttl)`). Default TTL 24h.
8. **Erase the ephemeral secret** (`crypto.Zero(eph.Priv)`). From this moment,
   the only key that can decrypt is the recipient's long-term key.
9. Return a **pointer**: `{eph_pub(32), CID(32), burn_deadline}`.

### 3.2 The pointer on-chain

The pointer rides a whisper as a **kind-0x02 pointer** (`whisper.BuildPointerArgs`):
```
Arg "W" uint64 = PointerV1 (0x5710)
Arg "K" hash   = sender ephemeral X25519 pub  (32B)
Arg "C" hash   = body CID = sha256(ciphertext) (32B)
```
Or, for the compost-anchor form (`internal/anchor`), four typed args
(measured **91 bytes CBOR**, inside the 111-byte budget):
```
K (hash) = sender ephemeral X25519 pub   → ECDH handle
C (hash) = body CID (sha256 of ct)       → retrieval key + commitment
D (uint) = burn deadline (unix seconds)
F (uint) = meta: version | kind<<8 | flags<<16
```
**The on-chain record carries NO plaintext, NO ciphertext, NO long-term key
material.** On DERO it rides inside DERO's native E2E encryption anyway.

### 3.3 Receiver (`Endpoint.ReceiveBody`)

1. Parse the pointer from the whisper / anchor (`whisper.ParsePointer`).
2. **Deadline check** — past the burn deadline → refuse (`"message burned"`).
3. **Fetch** the body by CID. On the home-node path the sender pushes to the
   receiver's mailbox (`/put/<cid>`, `mailboxcmd.go`); otherwise the receiver
   pulls peer-to-peer over **spore-peer** (`internal/peer` shells out to the
   Rust `spore-peer` binary; `rendezvous.FetchByCID`).
4. **Verify CID** — `sha256(fetched) == requested CID` or reject. A tampered
   or hostile peer can never hand you bytes you didn't ask for
   (spore-peer returns `500 cid mismatch`; `rendezvous.go` re-checks).
5. **ECDH** `secret = X25519(our_longterm_priv, eph_pub)`.
6. Derive key+nonce (same bound transcript), **open**, unpad → plaintext.

### 3.4 Rot (the erase side of long bodies)

- **Sender:** after the recipient fetches, both sides can erase. The stored
  ciphertext is reaped once its deadline passes (`store.Reap`).
- **Retention is bounded:** a body is gone after TTL by design — nobody (not
  even the sender) keeps it indefinitely.
- The **ephemeral** was already zeroed at send; only the recipient's long-term
  key ever decrypts, and the body dies at the deadline regardless.

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

### 4.2 The current short-message paths do **not** have forward secrecy

Short whispers DO live on the chain permanently, but as ciphertext. That makes
them private from a passive chain observer today; it does **not** make them
forward-secret.

**On public chains (EVM/Solana/XMR), the current spore 0xE1 envelope:**

- The sender uses a fresh ephemeral key per message and erases the ephemeral
  scalar after sealing. That prevents the sender-side ephemeral from becoming a
  long-term archive key.
- But the receiver's long-term X25519 private key is still the other half of
  every historical ECDH exchange. Anyone who records the 0xE1 ciphertexts and
  later steals that recipient key can recompute each historical shared secret
  from the public `eph_pub` in the envelope and decrypt the history.
- Therefore 0xE1 provides **confidentiality and sender authentication**, not
  forward secrecy. The same is true for the current one-shot long-body
  encryption if an attacker copies the off-chain ciphertext before its TTL
  expires and later obtains the recipient's long-term key.

**On DERO:** DERO's wallet encrypts the payload for the transaction's intended
recipient, and the recipient wallet can decode it. The derohe source also
supports the sender-side derivation for its own sent-transfer view. A passive
chain observer cannot decode it without the relevant wallet secret, but the
native payload scheme is still a long-term-key scheme: a later compromise of
the wallet key can expose recorded historical payloads. DERO's ring privacy
hides transaction relationships; it does not erase message bytes or add
forward secrecy to the payload.

### 4.3 What is genuinely still decryptable, and by whom — the honest row

| Record | Lives forever on-chain? | If the recipient key leaks later |
|---|---:|---|
| Long-body **pointer** (K/C/D/F) | yes | pointer only; no plaintext or ciphertext is there |
| Long-body **ciphertext** | no — off-chain, reaped at deadline | decryptable if an adversary copied it before reap; otherwise no body remains at the honest store |
| Short whisper on DERO | **yes** | recorded payloads can be retro-decrypted with the relevant wallet secret |
| Short whisper 0xE1 (public chains) | **yes** | recorded envelopes can be retro-decrypted with the recipient's long-term spore key |
| Ratcheted content (0xE2) | pointer only (chain); ciphertext off-chain, reaped at deadline | past consumed message keys are erased — a later device-key compromise does NOT unlock old 0xE2 history (forward secrecy holds) |

So the promise is **not** "deleted from the chain" — DERO/EVM blocks are
append-only and permanent. The accurate current promise is:

> **Legacy paths (whisper, 0xE1, one-shot long body):** passive observers
> cannot read encrypted payloads without a key; long bodies are kept off-chain
> and expire; but short on-chain messages remain recoverable if the
> recipient's long-term key is later compromised.
>
> **The 0xE2 path (shipped):** consumed per-message keys are erased and the
> ratchet ciphertext lives off-chain under a TTL, so a later device-key
> compromise cannot unlock the old ratcheted conversation history. The chain
> keeps only a dead pointer. This is the forward-private path — use it.

### 4.4 Why erasure is not enough without a ratchet

`crypto.Zero` overwrites secrets in memory (best-effort in a GC'd language —
process death is the true erasure, see the docstring in `crypto.go`). Erasing a
sender's one-shot ephemeral prevents that particular scalar from being an
archive key, but it does **not** erase the recipient's long-term private key.
That is why the current 0xE1 and long-body paths are not forward-secret.

The load-bearing fix is the ratchet: derive each message key from a rotating
chain, advance the chain, and erase consumed keys and old DH state. The chain
record may remain forever; without the erased per-message key it is intended to
be computationally inert.

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
opaque pointer only; substantive content is the ratcheted off-chain body. The
0xE1 envelope and DERO-native whisper remain available as compatibility
"knocks" — they are NOT forward-secret and the docs say so everywhere.

---

## 6. Encryption/decryption quick-reference (file → function → primitive)

| Where | Function | Primitive |
|---|---|---|
| DERO tx payload encrypt | DERO wallet (derohe), native | cryptonote confidential tx |
| DERO payload decode | `dero/chain.go` `ListIncoming` | wallet scan, `get_transfers` |
| Envelope send | `secure/secure.go` `Encrypt`→`sealWith` | X25519 + HKDF-SHA256 + XChaCha20-Poly1305 + Ed25519 |
| Envelope receive | `secure/secure.go` `Open`→`openSigned` | sig verify → ECDH → HKDF → AEAD open |
| Long body send | `longmsg/longmsg.go` `SendBody` | pad → X25519 → bound HKDF → XChaCha20 → CID → store+deadline |
| Long body receive | `longmsg/longmsg.go` `ReceiveBody` | deadline → CID check → ECDH → bound HKDF → open → unpad |
| Content address | `crypto/crypto.go` `CID` | sha256(ciphertext) |
| Secret erase | `crypto/crypto.go` `Zero` | overwrite |
| Ratchet (future) | `ratchet/ratchet.go` | X3DH + HKDF/HMAC double ratchet + XChaCha20 AAD |

*Companion files: `WIRE_SPEC.md` (exact byte formats + golden vectors),
`RATCHET.md` (forward-secrecy design), `SENDER_AUTH.md` (attribution/pinning).*
