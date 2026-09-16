# E2 Path Security Audit — internal/ratchet, ratchetwire, secure, mailbox

*Date: 2026-09-16 · Scope: the forward-private 0xE2 path end to end — X3DH, Double
Ratchet, wire frames, durable state, prekey serving, CLI send/recv wiring — checked
against the claims in `SENDER_AUTH.md`, `RATCHET.md`, and `WIRE_SPEC.md`.*

> **FIX STATUS (2026-09-16): every finding is fixed.** H1/H2 — SecureWire removed
> from the ratcheted path (see the "Remediation" section at the bottom); M1 —
> per-IP prekey-pop rate limiter (`internal/mailbox/ratelimit.go`); M2 —
> documented in SENDER_AUTH.md §5; L1 — u32 wrap guards (`internal/ratchet/
> ratchet.go`); L2 — moot with the SecureWire removal. Regression tests:
> `cli_asymmetry_test.go`, `e2cmd_flags_test.go`, `overflow_test.go`,
> `ratelimit_test.go`, `fuzz_wire_test.go`. L3 and INFO items needed no action.
> Known follow-up: `TestDoctorAllGood` depends on `doctorKeyFilesCheck("")`
> resolving the real user home — it should pass an explicit `-home` (pre-existing
> doctor-check issue, outside this audit's scope).

---

## Verdict

The crypto core is sound and unusually well-engineered: primitives are stdlib
(`crypto/ecdh` X25519 with small-subgroup rejection, Ed25519, XChaCha20-Poly1305,
HKDF-SHA256), all KDF labels carry the `spore/` + version prefix, X3DH uses the
0xFF…F prefix and binds the recipient into the HKDF info (UKS-resistant), envelope
signatures are verified **before** ECDH/AEAD work, header-is-AAD is done right, the
ratchet snapshots state and rolls back on AEAD failure, skipped-key bounds fail
closed, and anti-rollback state persistence uses an append-only log that survives
process restarts. Test coverage includes adversarial fuzzing, interop vectors, and
compromise-simulation.

The findings below are at the seams, not in the crypto: one functional bug in the
default CLI path, one doc/code divergence, and a set of hardening opportunities.

---

## Findings

### H1 — HIGH (functional, not cryptographic): default CLI send path cannot be received

`cmd/spore/e2cmd.go`:

- **Send** (`sendE2Core`, ~line 606): `SecureWire` is attached **only if `-key`
  and `-peer-pub` are passed**. `config.json` (cmd/spore/config.go) has **no
  `key`/`peer-pub` field**, so the documented flow (`docs/ONBOARDING.md` shows
  `spore msg send-e2 -to … -bundle … -pinned-sig … -store nostr://…` with no
  `-key`) sends **bare ratchet frames** (`sw == nil`).
- **Recv** (`msgRecvE2`, ~line 839): `SecureWire` is derived from `-identity`
  (**always** — `-identity` is required), so every incoming frame is pushed
  through `secure.Open` and must be a 0xE1 envelope.

Result: a default-flags sender produces frames a default receiver refuses
(`securewire: decode: cannot decrypt envelope`), with no diagnostic pointing at
the flag asymmetry. `FuzzEndpointSecureWireFullRoundTrip` passes only because it
manually attaches SecureWire to **both** endpoints — a construction the CLI never
reaches by default.

**Confirmed by test**: `internal/ratchetwire/cli_asymmetry_test.go`
(`TestCLIDefaultPathCannotDeliver` — red as shipped; `TestCLISymmetricSecureWireDelivers`
— green), which mirrors the CLI's exact endpoint construction.

**Fix (pick one):**
1. Remove SecureWire from the E2 path entirely (my recommendation). RATCHET.md §6
   already specifies: "the outer 0xE1-style sig is REPLACED by the ratchet's own
   authentication… a 64-byte per-message sig is redundant." Drop `secureWire` from
   `Endpoint`, delete `SecureWire`/`NewSecureWire`/`NewEndpointWithSecureWire`,
   update the two fuzz tests to the bare ratchet, and correct the endpoint.go
   doc-comment. This also removes double-encryption overhead per frame.
2. Keep it but make it symmetric and required: senders must pass `-key`/`-peer-pub`
   (and then say why it isn't in config defaults), or auto-derive the send side
   from `-identity` + the recipient's bundle `IKPub` exactly as recv derives from
   `-identity`.

### H2 — MEDIUM: RATCHET.md §6 is not what the code does

The spec says the 0xE2 envelope **replaces** the outer 0xE1 signature; the
implementation (when SecureWire is active) **double-wraps** — envelope-v2 inside
the ratchet ciphertext. This is not a vulnerability (each layer is individually
sound; the outer sig is bound to the recipient's key via the transcript), but it
is a spec violation in the one document labeled "source of truth," it wastes a
127-byte overhead + an Ed25519 sign/verify per frame, and it creates the H1
asymmetry. Either the doc or the code should move; H1's fix (1) makes the code
match the doc.

### M1 — MEDIUM: `GET /prekey` and the mailbox body store are unauthenticated by default

`internal/mailbox/http.go`: `Handler()` (no token) serves `GET /prekey` — the
single-use OPK pop — to anyone. Anyone who discovers a mailbox URL can exhaust a
user's prekey batch (1000 max), forcing every subsequent sender into degraded
no-OPK mode and degrading X3DH to DH1–DH3 (weaker offline resilience, still
authenticated). `PUT /put/{cid}` also lets anyone fill the store up to 64 MiB per
body.

**Mitigations already present**: batch pop is durable-before-return (no double
serve), bodies are content-addressed (no wrong-body planting), `HandlerToken`
provides constant-time bearer auth, and no private key ever touches the mailbox.

**Fix**: make `GET /prekey` respect the token gate in *all* hosted documentation
and consider rate-limiting the pop endpoint (e.g. token-bucket per IP) for the
tokenless self-host case. `docs/MODEL_B_SERVICE.md` should require `HandlerToken`
explicitly.

### M2 — MEDIUM: exposed prekey-availability oracle (same endpoint, acknowledged trade)

`GET /prekey` responses distinguish "batch has N left" (bundle with OPK) from
"exhausted → static degraded bundle" from "404". A prober learns the victim's
refill cadence and batch size. Lowercase risk since the mailbox URL is typically
only known to contacts, but worth one sentence in the threat model if it is
intended.

### L1 — LOW: ratchet message-number exhaustion is unreachable but unpoliced

`Header.N` is u32; skipTo's per-chain cap (64) prevents gaps from reaching wrap,
and sequential sends would need 2³² messages in one chain. Still, `Encrypt`
doesn't refuse `ns == MaxUint32` before overflow, and `skipTo` doesn't refuse
`to` near MaxUint32. One `if` each, purely defense-in-depth.

### L2 — LOW: SecureWire single-contact pin is a footgun

`SecureWire.PinnedSig` (non-zero ⇒ reject any other signer) is never set by the
CLI (`NewSecureWire(..., nil)` everywhere), so contact pinning lives only in
`secure.Codec.Pin`. If a future caller passes a pin while talking to a
multi-contact endpoint, delivery becomes confusingly zero. Worth a doc-comment
warning on the field.

### L3 — LOW / INFO: panic wipe is best-effort by design (documented, correct)

`cmd/spore/paniccmd.go` zeroes regular files before unlink, refuses dangerous
targets (root, `/home`, `/windows`, …), requires `-confirm`, and honestly
documents SSD/FTL and remote-store limits. No action needed; noted as correct.

### INFO — things checked and found correct

- Envelope verification order: parse kind → verify sig **before** ECDH → AEAD →
  pin check (WIRE_SPEC §3 normative order honored).
- Transcript binds `sigPub || ephPub || nonce || recipientPub || SHA256(ct)` —
  cross-recipient replay and ciphertext substitution die at the signature.
- X3DH: F-prefix, DH1–DH4 mapping matches Signal exactly; session id =
  SHA256(transcript)[:8] bound into every KDF label **and** every AEAD AAD.
- Ratchet: per-message keys via HMAC(ck,0x01/0x02); mk→AEAD expansion mixes the
  header + session id; header authenticated as AAD; speculative-state rollback on
  AEAD failure prevents tampered frames from burning chain keys; DH step retires
  the sender scalar on direction change (post-compromise healing).
- Skipped keys: hard caps (64/chain, 1024/session) fail closed; deadline
  inheritance + `SweepSkipped` implements the rot property.
- `FileStateStore`: temp+fsync+rename, log-before-rename ordering, restart-safe
  sequence recovery, torn-tail tolerance, hex-ID parse fix documented in-code.
- `OPKPool.Take` persists the removal before returning — a crash can lose a
  prekey, never resurrect one.
- Frame parsing (`SPR2`): strict length algebra (`frameHeaderLen+hlen+mlen == len`),
  magic/version/flags validation, 16 MiB cap, handshake/session-id binding.
- Pointer binding on fetch: deadline and route both re-verified against the frame.
- Mailbox log is now encrypted per-line with an HKDF-separated key and TTL-trimmed
  (old audit H5 closed).
- `crypto/ecdh` rejects all-zero/small-order ECDH outputs — no contributory-behavior
  gap.

---

## Suggested test additions (beyond the two committed here)

1. CLI-level round trip in `cmd/spore`: `send-e2` (flags exactly as ONBOARDING.md)
   → memory carrier → `recv-e2` — the test that would have caught H1.
2. Fuzz `Parse` + `UnmarshalHandshake` + `UnmarshalMessage` as standalone fuzz
   targets in your oss-fuzz fork (they are currently fuzzed only through
   endpoint flows).
3. A test asserting `Encrypt` refuses to send at `ns == MaxUint32` (with L1).

## Bottom line

Ship-blocking: H1 only, and it is a wiring bug, not a crypto break. Everything
else is hardening and hygiene in a codebase that is already well ahead of typical
hobby-protocol standards.

---

## Remediation (2026-09-16)

**H1 + H2 — SecureWire removed from the ratcheted path.** Per RATCHET.md §6, the
0xE2 envelope's authentication is the X3DH handshake plus the double-ratchet
chain; the per-frame 0xE1 wrapper is gone.

- `internal/ratchetwire/endpoint.go`: `SecureWire`, `NewSecureWire`,
  `ErrPinMismatch`, and the `Endpoint.secureWire` field deleted; all four
  encode/decode hook sites removed; `Endpoint` doc-comment now states the
  no-outer-envelope invariant. `NewEndpoint` is the only constructor.
- `internal/ratchetwire/lifecycle.go`: `NewDurableEndpointWithSecureWire`
  removed; `NewDurableEndpoint` / `NewDurableEndpointWithExpiry` build
  wrapper-free endpoints.
- `cmd/spore/e2cmd.go`: the `-key`/`-peer-pub` flags deleted from send and recv;
  both commands build symmetric endpoints via `NewDurableEndpointWithExpiry`.
  Flag registration extracted into testable `newSendE2Flagset` /
  `newRecvE2Flagset` constructors (mirroring `newDeroE2SendFlags`).
- `docs/MESSAGE_DATAFLOW.md`: §2 now scopes the 0xE1 envelope to the legacy
  one-shot path and points 0xE2 readers at RATCHET.md §6.
- Regression tests: `TestCLIDefaultPathDelivers` (the documented ONBOARDING.md
  flags deliver end to end), `TestRatchetFramesCarryNoOuterEnvelope`,
  `TestE2SendFlagsetHasNoSecureWireFlags`, `TestE2RecvFlagsetHasNoSecureWireFlags`.
  The obsolete `fuzz_secure_wire_test.go` was removed; its three durable-parser
  fuzz targets were re-homed as standalone byte-level targets in
  `fuzz_wire_test.go` (Frame.Parse, UnmarshalHandshake, UnmarshalMessage) with
  invariant + round-trip assertions.

**M1 — prekey-pop rate limiting.** `internal/mailbox/ratelimit.go`: per-client-IP
token bucket (burst 30, refill 1/6s, bounded map) applied to `GET /prekey` only —
`PUT /prekey` (owner publish) is never throttled. Anonymous drainers can no
longer exhaust a batch in minutes; the complete fix for public deployments
remains `HandlerToken` (HOME_NODE.md already mandates it for hosted routes).
Tests: `ratelimit_test.go` (burst+429, refill, per-IP separation,
publish-unthrottled, spoof-flood map bound).

**M2 — prekey-availability oracle** documented in SENDER_AUTH.md §5 (residual
risks), including the rate-limit numbers and the degraded-mode consequence.

**L1 — u32 message-number exhaustion.** `Encrypt` refuses a sending chain at
MaxUint32; `decrypt` refuses an incoming MaxUint32 header before any state is
touched; `skipTo` refuses to park the receiving cursor at MaxUint32. Tests:
`internal/ratchet/overflow_test.go`.

**L2** — moot: the single-contact pin field was part of SecureWire.

Not touched (pre-existing uncommitted work by the owner, discovered mid-fix):
`cmd/spore/doctorcmd.go` + `doctor_test.go` (doctor checks 4–7) and
`internal/sporrelay/sporrelay.go` (UUIDv7 object IDs).
