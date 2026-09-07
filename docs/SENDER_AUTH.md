# Sender Authentication — Threat Model & Design

*Implements invariant T1 (Authenticity) of `ROADMAP-PRODUCTION.md`. The
mechanism: derived signing keys + signed envelopes (envelope v2, kind 0xE1).
Wire details: [`WIRE_SPEC.md`](WIRE_SPEC.md). Implementation:
`internal/secure`.*

---

## 1. The hole this closes

Envelope v1 (kind 0xE0) was anonymous ECDH: anyone who knew your published
X25519 prekey could encrypt to it, and the AEAD carried no sender identity.
On public chains (EVM/Solana) the receive codec also passed non-envelope
payloads through to the plaintext codec. Net effect: **any network observer
could inject a message that rendered as real mail** — impersonation was free,
and nothing in the crypto could prove who sent what.

## 2. Assets, adversaries, trust assumptions

**Assets to protect:** the authenticity of delivered messages (who minted
them), message confidentiality (unchanged — see T2), the recipient's inbox
integrity (no deletions/forgeries), and the recipient's pinned contact list.

**Adversaries:**

- **A1 — Network observer / chain scanner.** Sees all calldata, inbox
  records, and pointers. Wants to inject plausible mail.
- **A2 — Any funded address (spoofer).** Can post to your EVM mailbox or
  Solana inbox PDA; wants to appear as someone else.
- **A3 — Malicious relay/mailbox operator.** Holds ciphertext, can replay,
  swap bodies under a CID? (no — content addressing), can withhold (T5
  accepts), and can see metadata.
- **A4 — Compromised sender device.** Holds the sender's X25519 scalar (and
  therefore the derived signing key). Out of scope for authenticity: a stolen
  identity IS the identity. Mitigations are rotation + pinning transparency
  (P2 ratcheting/KEYROTATE), not this layer.
- **A5 — Cross-recipient replay artist.** Takes a genuine envelope minted for
  Bob and presents it to Carol (to launder context or pin suspicion).

**Trust assumptions:** X25519/Ed25519/XChaCha20/HKDF-SHA256 are sound;
the recipient performs the out-of-band step of learning each contact's
`sig` key (from the sender, via a channel they already trust — the same trust
that Signal's safety numbers require); the chain delivers bytes unmodified
(it may censor, not forge).

## 3. The design

1. **Identity = one 32-byte X25519 scalar.** The Ed25519 signing keypair is
   derived deterministically: `seed = SHA-256("spore/sig/v1/seed" || scalar)`.
   No second secret exists to store, back up, or rotate out of sync. Publish
   BOTH the X25519 pub (`pub:`) and the signing pub (`sig:` — printed by
   `spore keygen`).
2. **Signed envelopes (v2, kind 0xE1):** the sender signs
   `"spore/env/v2" || sig_pub || eph_pub || nonce || recipient_pub || SHA256(ct)`.
   This kills A1/A2 (forgery requires the sender's signing key), A5 (the
   recipient's prekey is inside the transcript — Bob's envelope fails
   verification when presented to Carol), and ciphertext substitution.
3. **HKDF identity binding:** `info = "spore/e2e/v1/key" || eph_pub ||
   recipient_pub`. The AEAD key is unique per (sender-ephemeral, recipient)
   pair — no unknown-key-share laundering.
4. **Strict receive on public chains:** only kind-0xE1 envelopes decode;
   the plaintext passthrough (the A1/A2 injection path) is gone. DERO keeps
   `NewRecvCodecLegacy` — its native point-to-point payload encryption is the
   trusted secrecy layer there.
5. **Pinning (`Codec.Pin`):** a signature proves WHO holds the signing key;
   pinning turns that into enforcement. Once the recipient pins their
   contacts' `sig` keys, unpinned senders' mail never decodes. Mallory can
   still sign with Mallory's key — it attributes honestly and is dropped.

## 4. Attack walkthroughs (post-design)

| Attack | Outcome |
|---|---|
| A1 injects plaintext on EVM | strict codec refuses non-envelope payloads |
| A2 forges "from Alice" | cannot sign under Alice's `sig_pub`; pinned inbox drops it |
| A2 signs under own key, claims Alice in text | attributes to Mallory's key; refused once Alice is pinned |
| A5 replays Bob's envelope to Carol | transcript binds recipient_pub → sig fails |
| Body swap under a CID | signature covers SHA-256(ct) → fails; plus CID gate upstream |
| Relay rewrites the envelope | same as body swap |
| Malicious app strips the sig byte | payload becomes kind-unknown → rejected |

## 5. Residual risks (honest list)

- **No forward secrecy** — a compromised current device key decrypts
  everything encrypted to it that still exists. Designed fix:
  [`RATCHET.md`](RATCHET.md) (X3DH + double ratchet, status: design).
- **First-contact trust** — the first `sig` key exchange is trust-on-first-use
  unless done out-of-band; key-change transparency (surfacing rotations
  loudly) is a UX task, not crypto.
- **Metadata** — sender/recipient remain chain-visible on EVM/Solana
  (accepted; documented in the README's honest limits).
- **Key derivation couples secrets** — deriving the signing key from the
  encryption scalar means one leak compromises both (they live and die
  together at rest anyway; explicit, documented trade).

## 6. Tests mapping

| Property | Test |
|---|---|
| Round-trip + wire shape | `TestEnvelopeRoundTrip` |
| Attribution | `TestSenderAttribution` |
| Forgery + pinning enforcement | `TestForgedSenderRejected` |
| Signature tamper | `TestSignatureTamperRejected` |
| Cross-recipient replay | `TestCrossRecipientReplayRejected` |
| Plaintext/legacy injection refused | `TestStrictRejectsLegacyAndPlaintext` |
| Panic-free garbage handling | `TestDecryptNeverPanicsOnGarbage` |
| Interop vectors | `TestSpec*` (docs/WIRE_SPEC.md) |
