# Spore Ratchet — X3DH + Double Ratchet

*Status: crypto/session implementation landed; wire integration is still
pending. Closes the last big T1/T4 gap: forward secrecy. Today a stolen device
key decrypts every message encrypted to it that still exists — the DERO native
payload, the 0xE1 public-chain envelope, and the one-shot long-body path all
need their ratcheted conversation adapter before they get the stronger claim.
This design makes compromise-of-key ≠ compromise-of-history. Companion docs:
`SENDER_AUTH.md` (identity/authenticity, unchanged), `WIRE_SPEC.md` (0xE1
legacy envelope; 0xE2 ratchet envelope proposed).*

---

## 1. Goals / non-goals

**Goals**

- G1 — **Forward secrecy**: after both parties advance past a message, its
  key is erased; device-key compromise cannot decrypt it (breach recovery).
- G2 — **Post-compromise security (healing)**: after compromise ends, the
  ratchet self-heals via new DH inputs.
- G3 — **Asynchronous, no server**: fits spore's shape — the "server" is the
  recipient's mailbox (holds prekeys) and the chain (carries pointers).
- G4 — **Preserves the spore model**: E2E envelope, CID-addressed bodies,
  rot/deadlines, sender authentication via derived sig keys (SENDER_AUTH.md),
  strict receive, pinning.
- G5 — **Per-message rot**: erased message keys make old ciphertext bodies
  unrecoverable even if the ciphertext itself survives somewhere.

**Non-goals (deferred, explicitly)**

- N1 — Group ratcheting (MLS-class). Unicast first; groups stay fan-out.
- N2 — Metadata hiding (mixnets). Chain-visible timing stays visible.
- N3 — Deniability of participation. X3DH+DR gives weaker deniability than
  the current anonymous envelope; this is a real trade — see §9.
- N4 — Multi-device *sync* (only per-device keys; see §8).

## 2. Why envelope v2 fails FS

Envelope v2 derives `aead_key = HKDF(X25519(eph_priv, recipient_static))`.
The ephemeral protects the sender's past, but the RECIPIENT's static scalar
is a permanent decryptor for every envelope ever addressed to them: whoever
holds Bob's device key at time T decrypts all captured envelopes, all
fetched-and-archived bodies, and (until TTL) everything on Bob's disk.
"Gates the past" must therefore come from rotating Bob's side — that is the
ratchet.

## 3. Key model

Per identity (chain address + derived sig key, unchanged from SENDER_AUTH):

| Key | Lifetime | Location | Purpose |
|---|---|---|---|
| IK (identity X25519) | long-term | device (rotates w/ KEYROTATE) | authentication, X3DH |
| SPK (signed prekey) | ~1 week, 2 grace | device + mailbox | X3DH responder side |
| OPK (one-time prekeys) | one use | mailbox, refilled in batches | offline resilience: init without responder online |
| RK (root key) | per session | memory only | ratchet root |
| CKs (chain keys) | per direction | memory only | message-key derivation |
| MK (message key) | one message | memory only, erased after use | AEAD |

**Prekey publication.** The recipient's mailbox already holds their X25519
prekey and is the natural prekey server: `GET /bundle` returns
`{IK_pub, SPK_pub, SPK_sig, OPK_refs[]}` where `SPK_sig = Sig(IK, SPK_pub)`
(chain-provable ownership, same primitive as SENDER_AUTH §3). OPK public
keys are uploaded in batches of ~100; the mailbox hands each out ONCE
(tracking usage locally is fine — the mailbox is the recipient's own node).
Trust: the bundle's SPK is verified against the pinned `sig` key; OPKs are
covered transitively (hash-chain each OPK to the signed SPK: include
`SHA256(OPK_pub)` list inside the signed SPK blob — no per-OPK signature).

## 4. X3DH initiation (session setup)

Alice→Bob, Alice has fetched Bob's bundle (IK_B, SPK_B, SPK_sig, OPK_Bⁱ):

1. Verify `SPK_sig` against Bob's pinned sig key. Reject on failure.
2. Generate ephemeral EK_A (fresh).
3. `DH1 = X25519(IK_A, SPK_B)`
4. `DH2 = X25519(EK_A, IK_B)`
5. `DH3 = X25519(EK_A, SPK_B)`
6. `DH4 = X25519(EK_A, OPK_Bⁱ)` (when an OPK is available)
7. `SK = HKDF(F || DH1 || DH2 || DH3 || DH4, info="spore/x3dh/v1/sk")`
   where `F = 0xFF…` (32 bytes, domain separation, per Signal).
8. Initial sending ratchet state from SK; first message carries the header
   bundle so Bob can reconstruct: `{IK_A, EK_A, opk_ref, spk_id}`.

Bob consumes `DH1' = X25519(SPK_b, IK_A)`, `DH2' = X25519(IK_b, EK_A)`,
`DH3' = X25519(SPK_b, EK_A)`, `DH4' = X25519(OPK_bⁱ, EK_A)` → same SK,
deletes SPK/OPK private halves after first use (SPK grace window: keep
current + previous for in-flight).

**What rides the chain** is UNCHANGED: the pointer/whisper still carries
`{eph_pub or session handle, CID, deadline}`. X3DH inputs ride inside the
first ratcheted body (or its envelope), not the 111-byte DERO payload.

## 5. Double ratchet

Standard Signal construction (Poe/Gatewood/Marlinspike), adapted:

- `KDF_RK(rk, dh_out) = HKDF-SHA256(salt=rk, ikm=dh_out,
  info="spore/dr/v1/rk") → (rk', ck_s)`
- `KDF_CK(ck) = HMAC-SHA256(ck, 0x01) → mk;  HMAC(ck, 0x02) → ck'`
- Message key → AEAD key via
  `HKDF(mk, info="spore/dr/v1/mk"||header_bytes)`; header authenticated as
  AAD (never trusted separately).
- DH ratchet step on every direction change: each side sends a fresh
  ratchet pubkey `DH_r` in its header; on receipt, receiver performs
  DH_ratchet (new receiving chain), then advances the message chain.

**Header (v3, inside the encrypted body or as envelope extension):**

    dh_pub(32) || prev_chain_len(u32 LE) || msg_num(u32 LE) = 40 bytes

**Skipped-key policy (rot-adapted, this is where spore differs from
Signal):** out-of-order messages may require storing skipped message keys.
Bounds, strictly enforced:

- max 64 skipped keys per chain, 1024 per session;
- every skipped key inherits the message's burn deadline: at Trim/Reap time
  the session drops all skipped keys older than the TTL — an offline gap
  cannot become a permanent key archive;
- a session with exceeded bounds fails closed (sender resends; receiver
  requests re-key), never silently over-keeps.

## 6. Wire mapping — envelope v3 (kind 0xE2), honest about DERO limits

- **Long bodies / ratcheted content**: new envelope kind `0xE2 =
  ratchet_envelope`. Layout: v3 header inside the sealed area
  (`dh_pub || pn || n || session_id(8)`), AEAD key from the ratchet; the
  outer 0xE1-style sig is REPLACED by the ratchet's own authentication
  (the chain of DH handshakes authenticates both ends — X3DH verifies via
  SPK_sig, so a 64-byte per-message sig is redundant). Sender attribution
  stays: the session's X3DH bound both pinned identities.
- **Short DERO whispers** (111-byte payload0): a full ratchet header does
  not fit alongside routing args. Decision: short whispers remain 0xE1
  (authenticated, no FS — they are ≤80 bytes of low-value signal), and any
  substantive content MUST go the 0xE2 body path. The whisper stays the
  knock; the ratchet carries the conversation. This keeps the L1 1–2s
  mempool-catch path intact.
- **Body storage**: ciphertexts under MK-encryption are stored by CID as
  today; because MK is erased after decryption, an archived body becomes
  inert after first read even if the store leaks. `messages.log` must NOT
  be used by ratcheted sessions (see §7).

## 7. Compost integration (the rot story, completed)

- Plaintext never touches the mailbox log for 0xE2 sessions: the mailbox
  stores only ciphertext it cannot decrypt (no endpoint key on the mailbox
  host for ratchet sessions — the phone/desktop holds session state).
- Session state (RK/CKs/skipped keys) lives in a protected store, erased on
  TTL exactly like bodies: `session_expiry = max(message TTL)`.
- Deleting a conversation = erase session + skipped keys + bodies. This is
  finally the "unrecoverable by anyone, including participants" promise the
  original README claimed.

## 8. Multi-device

One session per device-pair. Each device publishes its own SPK/OPK set under
the same IK/signature domain; senders open one session per target device.
No cross-device message sync in v1 (out of scope, N4) — devices are
independent endpoints. This is weaker than Signal's linked devices but
honest, simple, and matches spore's "phone dials home node" architecture:
the home node is a delivery point, not a key holder, for ratcheted sessions.

## 9. Threat model delta

| Adversary | v2 today | with ratchet |
|---|---|---|
| Steal device key at time T | decrypts ALL captured history | decrypts only in-flight/unread windows; past is gone |
| Compromise then heal | permanent | self-heals on next DH step |
| Steal mailbox (no device keys) | decrypts bodies (key co-located!) | nothing: mailbox holds only prekeys (one-time) + ciphertext |
| Forge messages | impossible (v2 sigs) | impossible (X3DH binds pinned identities) |
| Replay old envelope | blocked (recipient binding) | blocked + sequence numbers |
| Deny having said X | weak deniability | WEAKER (ratchet transcript is publicly consistent) — accepted, N3 |

The mailbox colocation point in row 3 is worth emphasizing: today the
mailbox's key decrypts everything it stores; under ratcheting the mailbox
becomes genuinely blind, which was always the README's claim.

## 10. Crypto notes (do-this-exactly)

- Curve: X25519 / Ed25519 (identity) / XChaCha20-Poly1305 — existing libs.
- All HKDF/HMAC labels carry the `spore/` prefix and a version; every KDF
  call's info includes the session_id.
- DH ratchet uses X25519; reject all-zero shared secrets (small-subway
  hygiene: `crypto/ecdh` already errors).
- Header is AAD. `prev_chain_len` enables skipped-key indexing.
- Session id = `SHA256(X3DH transcript)[:8]` — collision-safe for the
  bounded session count, binds all handshakes to the session.
- Never derive a message key twice: chain-key advance is unconditional once
  a message key is released, even if AEAD sealing later fails.
- OPK exhaustion: fall back to DH1–DH3 (2-DH variant) — acceptable,
  signal the degraded mode in the header flags.

## 11. Implementation status and remaining wire work

1. **Crypto/session layer landed:** `internal/ratchet` now contains X3DH,
   Double Ratchet, bounded skipped-key storage, compromise simulation,
   post-compromise healing, header-AAD authentication, export/import, and
   deterministic vectors. This is not the messenger integration by itself.
2. **Still required before the privacy claim is shipped:**
   - a versioned 0xE2 envelope adapter carrying the ratchet handshake/message
     bytes through `chain.Payload`;
   - recipient prekey-bundle publication and one-time-prekey consumption;
   - protected, TTL-bound session-state persistence on the endpoint, with no
     ratchet private state in a blind mailbox or relay;
   - chain-agnostic `SendRatchet`/`RecvRatchet` APIs and CLI selection;
   - end-to-end tests through DERO, EVM, Solana, and XMR's off-chain signal/
     rendezvous path, including restart, replay, out-of-order, tamper, and
     later-device-key compromise.
3. **Feature flag:** keep the current path as legacy only. Enable ratchet mode
   explicitly until the complete matrix passes. A chain carrier MUST be
   treated as an opaque record; it never gets a ratchet key.
4. **Golden requirement:** skipping message keys then receiving 2,3,1 must
   deliver 2,3,1 with 1's key from the skipped store; after delivery + TTL the
   store must contain zero skipped keys. Repeat the invariant through every
   carrier, not only an in-memory fake.

## 12. Open questions

- Q1: Should SPK rotation be chain-anchored (KEYROTATE anchor carries
  SPK_sig) for mailboxes the user doesn't control? Leans yes for Model-B.
- Q2: Skipped-key TTL inheritance vs. hard cap — interacts with the
  "offline for 3 weeks" case; needs a product decision.
- Q3: Sealed-sender for the pointer (hide recipient on-chain) — separate
  design; ratchet does not depend on it.
- Q4: **Resolved** — 0xE2 (X3DH + Double Ratchet) has shipped and is the
  forward-private path. The DERO-native `0xE1` whisper path stays as-is (no
  ratchet) and is documented as compatibility-only / not forward-private:
  whispers are knocks. New conversations use `0xE2`.
