# Spore Production Roadmap

*Derived from `../spore-stack-audit-2026-09-07.md`. Defines what separates a
production-ready private messenger from a research artifact, the minimum
viable trust model, and the ordered work to get there.*

---

## 1. The line between research artifact and product

A research artifact says "the crypto is sound." A product must be able to say
all of the following simultaneously:

1. **An attacker who can reach your network cannot read, delete, or spend.**
   (Today: false — C1/C2/C3 in the audit.)
2. **You can prove a message came from the person you think it did.**
   (Today: false — no sender authentication.)
3. **Delivery works end-to-end on every live chain.** (Today: Solana receive
   broken past message #1; burn bricked; spore-peer rejects ~1.6% of bodies.)
4. **The data-at-rest story matches the data-on-chain story.** ("Messages rot"
   is currently falsified by `messages.log`.)
5. **An ordinary user cannot configure it into an unsafe state by default.**
   (Today: every dangerous surface is the default.)

Rule of thumb: ship nothing that listens on a socket until (1) and (5) hold.

---

## 2. Minimum viable trust model (MVTM)

The design goal: **each user trusts only (a) themselves, (b) their own
always-on node, and (c) the chain's liveness** — nothing else. Enumerating
what currently breaks that:

| Party | Must NOT be trusted for | Status today |
|---|---|---|
| Chain observers | message content | ✅ held (E2E envelope / DERO native) |
| Chain observers | sender identity, recipient identity | ❌ exposed on EVM/Solana (from/to in the clear); DERO ok |
| Chain observers | message existence & timing | accepted limitation (documented) |
| Mailbox operator | content | ✅ (E2E bodies) |
| Mailbox operator | who messaged whom, when | ⚠️ `-privacy` flag exists but off by default; log retains timing regardless |
| Mailbox operator | availability (can delete/withhold bodies) | ✅ acceptable — delivery is retryable |
| Relay operator | content | ✅ opaque ciphertext |
| Relay operator | destination metadata | ❌ relay sees plaintext dest URL per push |
| Anyone on the network | forging a message to you | ❌ **anyone can** (anonymous ECDH + plaintext passthrough) |
| Anyone on the network | deleting your mail | ❌ open `DELETE /body` / relay drop |
| `spore web` visitors | spending your wallet | ❌ unauthenticated proxy |

**Minimum viable trust model = the invariants below. If a change breaks one,
it doesn't ship.**

- **T1 — Authenticity.** A delivered message is readable *and* attributable to
  a chain identity the recipient chose to accept. Unattributable ciphertext is
  spam, not mail.
- **T2 — Confidentiality.** No party other than sender/receiver endpoints
  (including their own nodes) ever holds plaintext or key material.
- **T3 — Least exposure.** Every network listener defaults to loopback; any
  non-loopback bind requires an explicit credential and (for anything
  plaintext-carrying) TLS.
- **T4 — Rottable at rest.** Anything a user can recover, an attacker who
  later takes the disk cannot — or the retention is explicit and bounded.
- **T5 — Availability is best-effort, never trusted.** Any node can silently
  drop bodies; the protocol must make withholding equivalent to nonexistence
  (retryable pointers + burn deadlines), not data loss.
- **T6 — Content-addressing everywhere.** No body is accepted without
  sha256 == CID (already held — keep it sacred).

What the MVTM deliberately does NOT promise: metadata privacy against global
passive observers (unrealistic without mixnets), forward secrecy against a
compromised *current* device (needs real ratcheting — see P2), or anonymity
from chain analytics (dero ring sigs help; EVM/Solana don't).

---

## 3. P0 — Stop the bleeding (1–2 weeks, blocking everything else)

All are small, mechanical, testable. No protocol changes.

1. **Listener hygiene** (C1, C2, C3):
   - Default `-listen 127.0.0.1:PORT` for mailbox, webchat, relay, daemon inbox.
   - Refuse non-loopback binds without `-token` (and `-cert/-key` for anything
     serving plaintext or bearer tokens). Error, don't warn.
   - `spore web`: delete `/whisper/send` unless an explicit
     `-allow-browser-spend` flag (with token) is set; `/whisper/recv` requires
     the same token.
2. **Relay SSRF + quotas** (C3):
   - `X-Relay-Dest` restricted to an operator-configured allowlist (or removed
     entirely — the sender can push direct; relay-chooses-dest is the wrong
     trust direction).
   - Auth-by-default, per-IP rate limits, disk quota, max deadline (e.g. 7d cap),
     bounded `pending` map.
3. **Delivery correctness** (H2, H4):
   - Solana: give every `Incoming` a real txid (fetch signatures per message,
     or dedup key on `seq`), stop re-reading the full inbox per poll.
   - spore-peer: replace first-byte error sniffing with a 1-byte status frame
     (`0x00 ok || 0xNN error`) — wire version bump, keep compat.
4. **Data-at-rest** (H5): encrypt `messages.log` (same XChaCha machinery, key
   derived from the mailbox key), TTL-trim it, make it single-line-corruption
   tolerant, kill the O(n²) full-file `Has()` scan (index file or SQLite).
5. **Delete footguns**: `EncryptStatic`, committed test artifacts in
   `internal/peer/`, stale package docs.

Exit criteria: an external tester with only network access to a default
deployment cannot read, write, delete, spend, or crash anything.

## 4. P1 — Earn the name "private messenger" (4–8 weeks)

6. **Sender authentication** (H1) — the single most important protocol change:
   - Each identity = chain address + X25519 *signed* prekey. Signature made
     with the chain's native key (Ed25519 on Solana, secp256k1 on EVM, DERO
     addr-key) over the X25519 prekey pub → chain-provable key ownership.
   - Envelope carries `sig(sender_id, eph_pub || cid || context)`; recipient
     rejects unsigned/unknown-sender envelopes. Drop plaintext passthrough on
     public chains (DERO keeps its native path).
   - Bind both pubkeys into HKDF `info` (M11) while touching this code.
   - First-contact flow: out-of-band pub exchange (like Signal safety
     numbers), with a "verify" UX later.
7. **Solana program v4** (H3): burn must shrink or compact — either
   `realloc` down + lamport reclaim, or a fixed-slot layout with a
   tombstone bit so `copy_from_slice` can't mismatch. Add `owner == program_id`
   checks, cap per-inbox growth, and ship an on-chain test for burn-after-deliver.
8. **Chain status honesty** (M7): XMR either moves to integrated addresses /
   tx_extra with real wallet-rpc verification, or the backend is explicitly
   feature-flagged off. No mock-verified paths in a production binary.
9. **DoS hardening** (M1, M3): spore-peer connection/thread caps; channel box
   auth (even a shared room token), room-count cap, incremental persistence.
10. **Ops basics**: structured logging, metrics, proxy/Tor support for all
    outbound RPC, `spore doctor` (validates key file, RPC reachability, listen
    exposure, log health).

## 5. P2 — Becoming a real messenger (months, after P1)

- **Ratcheting / forward secrecy**: the current design has long-medium-term
  X25519 keys — a stolen device key decrypts everything in flight. Move to
  X3DH + double-ratchet (or at least per-message ratchet seeded from ECDH) —
  the anchor/pointer split already fits: pointer carries the ratchet header.
- **Group messaging without the box**: the docs correctly note unicast-only.
  Minimum path: sender-side fan-out to member mailboxes (no relay), then
  MLS-style group keys over that. The channel box remains a fallback, clearly
  labeled lower-trust.
- **Verified contact UX**: fingerprint/safety-number display, key-rotation
  transparency (the KEYROTATE anchor exists — use it, log rotations, surface
  unverified rotations loudly).
- **Mobile story**: the Model B hosted mailbox is the weakest trust point.
  Target: phone runs a light client against the user's home node with mTLS +
  per-device tokens; Model B becomes "bring your own relay you pay," not
  "trust our courier."
- **Fuzzing**: libFuzzer/oss-fuzz targets for the CBOR walker, canonical
  codec, ABI decoder (M2 overflow), and the spore-peer framing. The repo
  already carries an oss-fuzz fork — eat your own dog food.

## 6. P3 — Ecosystem bets

- derohe-rs L1 mempool catch (already in ROADMAP.md) — the 1–2s receive path
  is the product differentiator; make it default once stable.
- MyceliumMailbox.sol deploy + gas-sponsored delivery via a permit/relayer.
- Cross-chain identity proof (gated, hard — keep it gated).
- A formal spec of the wire format (envelope, canonical, pointer) with
  interop test vectors — right now the spec is the Go code.

## 7. Sequencing & gate

```
P0 ──► ship "hardened research release" ──► P1 ──► beta with real users ──► P2 ──► 1.0
```

### Status (2026-09-07)

- **P0 COMPLETE.** Loopback defaults + token gating (C1/C2, `internal/safehttp`),
  relay SSRF allowlist + quotas (C3), Solana seq-keyed dedup (H2), Solana
  burn un-bricked with bank tests (H3), spore-peer status-frame protocol (H4),
  encrypted + TTL-trimmed message log (H5), footguns removed. All suites green
  (Go 20 pkgs, Rust 14 tests, Solana program 9 tests).
- **P1 sender authentication COMPLETE** (H1): signed prekeys + envelope v2
  (0xE1), HKDF identity binding, strict receive, contact pinning. Threat
  model: `docs/SENDER_AUTH.md`.
- **Wire spec COMPLETE**: `docs/WIRE_SPEC.md` + `docs/interop-vectors.json`,
  conformance tests in Go and Rust.
- **P0 items 4/10 remain open**: XMR honest-or-off decision, DoS caps on
  channel box, `spore doctor`, metrics, Tor/proxy support, fuzz targets.

**Beta gate** (the honest "production-ready for a private messenger" claim):
T1–T6 all hold; DERO + one public chain (Solana) deliver/burn correctly under
a 48h adversarial testnet soak; spore-peer has fuzz-clean framing; an external
reviewer can run a default deployment with only the docs and find no C-level
finding. Until then, every artifact should say what this audit says: sound
core, unshippable edges.
