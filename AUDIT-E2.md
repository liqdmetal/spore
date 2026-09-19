# E2 Path Security Audit — internal/ratchet, ratchetwire, secure, mailbox

*Date: 2026-09-16 · Scope: the forward-private 0xE2 path end to end — X3DH, Double
Ratchet, wire frames, durable state, prekey serving, CLI send/recv wiring — checked
against the claims in `SENDER_AUTH.md`, `RATCHET.md`, and `WIRE_SPEC.md`.*

> **FIX STATUS (2026-09-16): every finding is fixed — landed in commit `25206a2`.** H1/H2 — SecureWire removed
> from the ratcheted path (see the "Remediation" section at the bottom); M1 —
> per-IP prekey-pop rate limiter (`internal/mailbox/ratelimit.go`); M2 —
> documented in SENDER_AUTH.md §5; L1 — u32 wrap guards (`internal/ratchet/
> ratchet.go`); L2 — moot with the SecureWire removal. Regression tests:
> `cli_asymmetry_test.go`, `e2cmd_flags_test.go`, `overflow_test.go`,
> `ratelimit_test.go`, `internal/wirefuzz/wirefuzz_test.go`. L3 and INFO items needed no action.
> Known follow-up resolved: `TestDoctorAllGood` is now hermetic (explicit
> temp-dir `Home`/`Config`; doctor tests hardened in commit `257073c`).

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

All fixes below landed in commit `25206a2` ("fix(e2): drop SecureWire
double-wrap; add sporepeer:// store backend").

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
  `internal/wirefuzz/wirefuzz_test.go` (Frame.Parse, UnmarshalHandshake,
  UnmarshalMessage) with invariant + round-trip assertions — the dedicated
  package also insulates the OSS-Fuzz build from the main package's test-file
  layout.

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

Not touched (pre-existing work by the owner, discovered mid-fix; since landed
in separate commits): `cmd/spore/doctorcmd.go` + `doctor_test.go` (doctor
checks 4–7) and `internal/sporrelay/sporrelay.go` (UUIDv7 object IDs).

---

## Release pipeline remediation (2026-09-17)

The throwaway `v0.0.0-ci` tag (five attempts, all on the same tag name) was the
first end-to-end exercise of `.github/workflows/release.yml` — cross-compile,
GitHub Release, SLSA provenance — after the SLSA parse-time restructure. It
found five real defects. All fixes are on `main`; the final run of the exercise
was fully green, the provenance was verified as a sigstore bundle (predicate
`https://slsa.dev/provenance/v0.2`, builder `generator_generic_slsa3.yml` of
the SLSA generator at its v2.1.0 tag, four subject digests, Fulcio certificate,
one Rekor transparency-log entry), and the release + tags were deleted after
verification.

**R1 — startup_failure on every tag: `action-gh-release@v1`.** GitHub
refuses to start any workflow referencing an action that runs on the
decommissioned node16 runtime; the whole Release run died at startup with no
jobs and no logs (run 35167009653), so the defect was invisible to every
job-level check. Found by actionlint's runner-too-old rule while triaging.
Fixed by bumping to `@v2` — commit `8c192aa723e39a8ad3ddadfd265158e60df260ea`.

**R2 — startup_failure, second cause: job-level `permissions:` on a
reusable-workflow-call (`uses:`) job.** The SLSA call job carried a
`permissions:` block; GitHub rejects the workflow at startup despite some docs
describing that as valid. Isolated by a 14-probe bisect: five temporary
workflows per throwaway tag, each isolating one construct (header variants,
local vs external `uses:`, verbatim/truncated copies, per-key deltas of the
provenance job). Every variant keeping the block startup-failed; every variant
without it started. The probe scaffolding and the throwaway tags were removed
from history after triage (main was rewritten to drop them); the surviving
remediation is commit `a7ad5f8ed0d93b8478be94146de9f4c85e50f3f9`, which drops
the redundant block (the generator inherits the workflow's top-level permissions,
which already grant `id-token: write`, `actions: read`, and `contents: read`).
The quirk is documented in the workflow comment.

**R3 — generator job failed before signing: SLSA generator v1.9.0 pins
`actions/upload-artifact` v3 internally,** which GitHub now auto-fails at step
setup (deprecated runtime). Not fixable from this repo; fixed by bumping the
generator to its v2.1.0 line — commit `e20cda26ded9ebdaa3f2db73b9f6e0f4a51eace8`.

**R4 — attest rejected the subjects file: the format was backwards from the
file's first commit.** The generic builder parses field 1 of each subjects
line as the digest (generic.go: `shaDigest = parts[0]`, name = `parts[1]`) and
expects plain `sha256sum` output; the hash job transformed it to
"name sha256:digest" via awk, so attest died with `sha: unexpected sha256
hash format` and every downstream job cascaded (empty provenance name →
upload-artifact "path required" → final exit 27). The hash job now passes
sha256sum lines through untransformed, excluding the `*.sha256` files whose
content is not a sha256sum line — commit `2dd05f873f0d4f9debee375fe9f456a65d6dd13d`.

**R5 — silent artifact collision in the release itself.** The build matrix
produced bare `spore` for linux and both darwin targets; flattening artifacts
for release/hash would overwrite all but one Unix binary while every job stayed
green. Artifacts are now `spore-<os>-<arch>[.exe]`, and `upload-assets: true`
attaches the signed provenance to the release — commit `c877e4fbac6a8d259f0d5161d837d1b9b64a19cd`.

**Guardrail follow-up:** gate the release/`upload-assets` jobs on the tag not
being a `0.0.0.*` dry-run, so throwaway exercises never publish a public
release. **Landed:** `release.yml` gates `Create GitHub Release` and the
generator's asset upload off for `v0.0.0*` tags — build, subjects hashing,
and detached keyless signing still run on a dry-run tag, and the skipped
publish propagates to provenance verification. Proven live with a throwaway
`v0.0.0-gate` tag: all build/hash/provenance jobs green, both publish jobs
skipped, no release created — commit `33106b1bbfc0aaaf09cdcdd50b5582f5844dfa0b`.
Superseded method: throwaway tags are retired entirely — `release.yml` now
also accepts `workflow_dispatch`, and the publish gates key on the trigger
event (`push`) with the `v0.0.0*` clause retained as a second belt, so a
dispatched dry-run creates no ref, has no publish path at all, and stamps
its binaries `dry-run-<ref>` — commit `eaeed012223a828bd473a217984d9d54adb919d6`.
Extended: dry-runs now also exercise the consumer verification itself —
`verify-provenance` runs offline against the run's own artifacts (the signed
provenance is uploaded as an artifact even when detached), with
`--source-uri` still enforced and tag binding only on real releases — commit
`42f265de9d3952481c794a2b6c7c428c41b2c608`.

## Test-timing conventions (2026-09-18)

Every CI flake this week was one anti-pattern family: a test observing
asynchronous state on a schedule instead of synchronizing with it. The
hardening campaign (four suites swept) also exposed a real production bug the
old fixed sleeps had been masking. The conventions below are recorded so new
tests inherit the discipline instead of rediscovering it; every rule is
backed by a pinned commit.

**T1 — poll a monotone property; never sleep a fixed window before a
positive assertion.** If a test asserts that something HAS happened, poll
for it (generous budget, small step, fatal with collected state on
timeout). Polling is only sound when the property is monotone — the state
only ever moves one way — because then a poll cannot mask a bug; it can
only wait. A fixed sleep can be starved entirely under CI load and fails
with a misleading signature. Evidence chain: the starved reaper flake
("2 .body files on disk, want 1" under full gate load) fixed by polling in
commit `3f74afaeb4ea4914ed6520e742453a324e2e1758`; the suite-wide sweep
(httpserver reaper, relay backoff boundary, evm chain latency, scanhub
goroutine-leak counts) in commit `f865275fbb2a6d195bcfd6e8af4f6e70fe9ca2d3`;
and the payoff — the strengthened 3-second poll failed on Windows CI because
~120 tick opportunities passed with no reap, which was NOT a flake but a
production bug: DiskStore.Reap removed the .body before the .exp marker and
ignored remove errors, so one transient sharing violation orphaned the body
forever (the glob keys on *.exp). Fixed in commit
`0385e32fe7612f44db9eafd9d445d27fa54e2ef8` by treating the marker as the
commit point: payload first, marker last, abort and retry the hold on the
next pass if any remove fails. The stronger test found the bug; the fixed
sleep had hidden it.

**T2 — quiesce before observing; never read worker-mutated state
concurrently.** If a constructor starts a background worker, a test must
not read that worker's state while it runs — neither internal fields (the
race detector fires: the Linux `-race` outbox failure was the drain
worker's post-send removal racing the test's unsynchronized read, fixed in
commit `d04727910d05ad1ca1ddfbb25b27c0ca3b0f1ba1`) nor files the worker
rewrites (Windows refuses a concurrent open: the outbox compaction
file-sharing violation, fixed in commit
`684e3a3f5c7b6f4f90ddcb9dc4d81b1e629ffdb4`). Quiesce with the type's own
shutdown (Close/Close-join gives happens-before via the WaitGroup), then
read once. Precedent inside the suite: TestOutboxRetainsFailedEventAcross
Restart already did exactly this. Caveat that bit once: closing changes
the state — a drain worker with a succeeding dispatcher empties the queue,
so the test must arrange the state it wants to observe BEFORE quiescing
(delivery failure keeps events pending), not assume quiesce is
observationally neutral.

**T3 — the test must pin the case it claims to pin.** The outbox
dedup test used a no-op dispatcher while claiming to pin enqueue-time
deduplication — a property only observable while delivery is FAILING (a
succeeding dispatcher legitimately removes the event). T1 and T2 alone
would have made the broken assertion deterministic. Choose fixture state
so the property under test is both observable and stable.

**T4 — verify by execution, under repetition, on the platform that
failed.** Every hardening above was proven with `-race` repeats (20–50x)
locally on the failing platform before push, and the pre-push gates re-run
the suite under load. The same behavioral-over-inspection discipline exists
for the hook shims: scripts/test-pre-push-failclosed.sh renders and
EXECUTES the shim through its scenario battery instead of grepping for
text — commit `c6ca2f01c90aeb42251a094ea32d71967f6cbf9e`.

**Verified-clean classes (do not "fix" these):** negative windows (a
must-NOT-happen assertion cannot flake — it can only miss a detection,
which more waiting improves); rate-measurement windows that measure
throughput over an interval; pacing sleeps that exist to trigger a
rate-limit; deadline waits bounded by the monotonic clock (a sleep longer
than a TTL cannot pass early); and poll loops that already poll a
monotone property. The reap deadline-mint helpers (`mintDeadline`,
`spinPastDeadline`, mirrored across the store and peerstore test
packages) remain the reference implementation for wall-clock-step
tolerance — commit `adfc03545f1a655edc575abba1d88b01ccf4d578`.
