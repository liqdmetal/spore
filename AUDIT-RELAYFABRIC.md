# Relay Fabric Security Audit — the pointer-forwarding surface

*Date: 2026-09-18 · Scope: the F1/F2 relay-fabric surface end to end — the
Rust relay verbs (`freg`/`fput`/`fpop` on the spore-peer socket behind
`-fabric`), the registry/lease and queue/quota state they drive, the Go
client (`internal/fabric`), the `spore fabric subscribe` drain loop into the
shared E2 ingest path, and the deploy posture of a public relay listener —
audited against [`docs/RELAY_FABRIC.md`](docs/RELAY_FABRIC.md) (design law,
threat model, and the F1 adversarial-review dispositions) and
[`WIRE_SPEC.md`](docs/WIRE_SPEC.md) §8.*

> **FIX STATUS (2026-09-18): the F1-baseline HIGHs are already fixed in
> spore-peer `fee4d8a` `no-verify-hash`; the new findings from this review (H-N1, M-N2/M-N3)
> are fixed in spore-peer `78e69a4` `no-verify-hash`; R-N1 (drain-union dedupe) is fixed in
> spore `3ec84c0`; R-N2 (drain jitter) is fixed in spore `444122f`.** Regression tests:
> `src/fabric.rs` `tests` mod (`fput_deadline_horizon_cap_refuses_immortal_envelope`,
> `freg_sweep_is_time_gated`, `expired_registration_re_registrable_before_sweep`)
> plus the pre-existing hostile-frame battery. The accepted risks at the end
> are documented posture, not open bugs.
>
> **Provenance pins** (full hashes; spore-peer is a sibling repo, so its
> hashes are enforced by the owning repo's tooling, not here — `no-verify-hash`):
>
> | What | Hash | |
> |---|---|---|
> | F1 verbs landed (`3546b56`) | `3546b56` `no-verify-hash` | spore-peer: freg/fput/fpop behind `-fabric` |
> | F1 adversarial-review hardening | `fee4d8a` `no-verify-hash` | budget+sweep, chained refresh, token shape, dedupe fix, bounded reap |
> | Real-binary serve-path smoke | `1a17844` `no-verify-hash` | pre-push gate coverage |
> | One-shot fabric client subcommand | `1f929b0` `no-verify-hash` | cross-binary interop |
> | `--pidfile` / `--announce-addr` | `2a701c9` `no-verify-hash` | process-manager operation |
> | Deploy wrappers (systemd + Windows) | `7691059` `no-verify-hash` | `deploy/` |
> | Graceful shutdown (SIGTERM/Ctrl+Break) | `7be409a` `no-verify-hash` | pidfile removal on the graceful path |
> | **This review's fixes (H-N1, M-N2/M-N3)** | `78e69a4` `no-verify-hash` | horizon cap + sweep gate |
> | F2 client face audited here | `9996fbc` | spore: `internal/fabric` + drain loop + `-route-fabric` |
> | F2 contact-card plumbing | `6953092` | spore: seed + relays ride the invite |
> | F2 docs | `823fbc2` | spore: RELAY_FABRIC status, WIRE_SPEC §8 |

---

## Verdict

The relay surface inherits the right spine and it held under review: the hold
is reused (envelopes are content-addressed §7 objects, temp+rename, rebuilt at
startup — no new storage code), the ratchet is the filter (relays validate
74-byte shape and nothing else, so a hostile or garbage pointer cannot do
anything but fail closed at the recipient), and the possession-token model
means a relay operator is exactly as dangerous as the threat model says — no
more. The F1 adversarial-review HIGHs (registry DoS, handle takeover,
empty-token bypass, dedupe corruption) are all real fixes with real tests,
verified present in the shipped code.

This review re-attacked the pushed surface from the F3 vantage (durable
state, quota math, the deploy posture a public relay actually runs) and found
one genuine HIGH — an immortal-envelope DoS the design doc's own MUST was
supposed to prevent — plus two MEDIUM-class amplifiers now fixed, and
confirmed four earlier accepted risks as correctly bounded.

## Scope audit: pushed commits vs the F3 slice definition

The F3 slice promises: N-relay redundancy + drain-union dedupe, per-handle
quotas + jitter, a durable fabric index, and this audit with hash-pinned
remediation. What the pushed history actually contains is the F1/F2 surface,
its hardening, and the operator/deploy story:

| F3 deliverable | Pushed state (at `2a701c9` `no-verify-hash`) | Verdict |
|---|---|---|
| Durable fabric index | **Shipped** — envelopes persist as `<cid>.fenv`, temp+rename, re-indexed at `open()` with FIFO order restored; the dedupe-refresh corruption (F1 #4) is fixed. Registrations deliberately stay memory-only (F1 #9). | done |
| Per-handle quotas | **Shipped for abuse** — `max_per_handle` FIFO eviction, per-IP rate windows on fput AND fpop, `max_regs` budget. Not yet *operator-facing* config: knobs exist in code, `-fabric` exposes no flags to tune them. | partial |
| N-relay redundancy + drain-union dedupe | **Client-side only** — the F2 sender fputs to every `-route-fabric` relay (best-effort, ≥1 accepted ⇒ send). The drain-union dedupe-by-CID across relays is NOT in the pushed code: `spore fabric subscribe` feeds every pointer from every relay into the ingest path, and dedupe happens implicitly at the ratchet (a replayed pointer fails closed) rather than explicitly before ingestion. | gap → tracked below (R-N1) |
| Jitter | **Not shipped** — the drain loop's cadence is a fixed `-every` interval; the sync-loop-style jitter the design promises is not wired. | gap → tracked below (R-N2) |
| `AUDIT-RELAYFABRIC.md` | This document. | done |

**Conclusion**: F3 is *startable*, not complete — the audit deliverable is
here, but redundancy/jitter work remains, tracked as the two roadmap-class
items below. Nothing in the pushed history overclaims: RELAY_FABRIC's status
table says exactly this.

## Findings (this review)

### H-N1 — HIGH: no deadline horizon cap ⇒ immortal envelopes (unbounded disk + index growth)

The design doc is explicit: *"deadline MUST be nonzero and within the relay's
horizon cap."* The pushed code enforced the nonzero half and ignored the
horizon half. Every compost path in the fabric is **deadline-triggered**
(drain-time, fput-touch, `open()` rebuild) — so a pointer with
`BurnDeadline = u64::MAX` (or any far-future value) is never reaped by
anything: it sits on disk forever, survives every restart (the rebuild
re-indexes it), and each `fput` under a different CID adds another. A single
unauthenticated sender with one registered handle can grow the hold's disk
and the in-memory queue index without bound at the per-IP rate limit's
cadence — the exact "immortal garbage" failure mode the §7 TTL design exists
to prevent, resurrected one layer up.

**Fix** (`78e69a4` `no-verify-hash`): `fput` refuses deadlines beyond
`max_deadline_horizon_sec` (default 7d, mirroring `max_lease_sec`) with
`400 deadline beyond horizon cap`; the `open()` rebuild composts
beyond-horizon leftovers retroactively (a node upgraded mid-flight), and the
case-identity of the check matches the `410 gone` expiry path already there.

**Pinned by** `fput_deadline_horizon_cap_refuses_immortal_envelope`: u64::MAX
and a beyond-horizon-but-plausible deadline are refused at fput; an
in-horizon fput still succeeds; a hand-planted beyond-horizon `.fenv` is
neither re-indexed nor left on disk after a rebuild.

### M-N2 — MEDIUM: registry sweep was a per-request CPU amplifier

The F1 fix for registry growth retained the whole `HashMap` on **every**
`freg`. freg is unauthenticated and (deliberately, finding 10) outside the
per-IP rate window — an attacker driving freg at line rate forced an O(live
regs) retain per request under the state mutex: 50k live entries turn each
unauthenticated request into real CPU under the lock that every fabric verb
shares.

**Fix** (`78e69a4` `no-verify-hash`): the sweep is time-gated to at most one per second
(`last_sweep_sec`). Correctness between sweeps is preserved by the live-check
treating expired-but-present entries as absent — see M-N3.

**Pinned by** `freg_sweep_is_time_gated`: the first freg of a second sweeps;
a same-second call skips the retain; an expired-but-present entry reads as
not-live.

### M-N3 — MEDIUM: expired-but-present registrations must read as absent (sweep-gate corollary)

Once the sweep is no longer guaranteed per-request, the chained-refresh and
budget checks could have re-introduced the F1 takeover window (an expired
entry blocking re-registration until the next sweep) or counted stale entries
against the budget. The live-check is now `expires > now` explicitly
(`is_some_and`), not mere map presence — a squatter holds nothing past expiry
regardless of sweep cadence, and the budget counts what the cap was written
to count.

**Pinned by** `expired_registration_re_registrable_before_sweep`, plus the
live-check contract asserted inside `freg_sweep_is_time_gated`.

### R-N1 — FIXED (spore `3ec84c0`): drain-union dedupe across relays is now explicit and pre-ingest

With N-relay redundancy, the same pointer legitimately arrives from several
relays. The F2 loop deduped only per (relay, handle) in memory: a send fput'd
to M relays cost M body fetches, and a restarted recipient re-fetched every
still-queued copy. The drain loop now keeps ONE consumed-CID union
(`internal/fabric.SeenCIDs`, persisted beside the ratchet state, bounded at
64k entries with burn-deadline pruning, save-gated 1/s). Crucially it is a
**consumed** set: a CID is marked only on successful ingest and un-marked on
failure, so redundancy still works where it matters — a pointer whose body
fetch failed stays eligible for a second relay's copy.

**Pinned by** `TestSeenObserveIsFirstSightingOnly`, `TestSeenForgetRestoresEligibility`,
`TestSeenPersistAcrossRestart` (internal/fabric) and `TestDrainUnionDedupesAcrossRelays`,
`TestDrainUnionKeepsFailedIngestEligible`, `TestDrainUnionSurvivesRestart` (cmd/spore).

### R-N2 — FIXED (spore `444122f`): drain cadence now jitters per pass

The design promises sync-loop-style jitter for the subscribe loop; the loop
was a fixed `-fabric-interval` ticker — a timing signature a relay operator
can read per handle. The drain wait is now recomputed per pass as
`interval ±N%` (`-fabric-jitter`, default 20 — the shape internal/relay's
backoff uses, `fabric.JitteredInterval`), so drain starts decorrelate across
processes and relays. Timer replaces Ticker (per-pass recomputation, and the
explicit zero-interval panic is now a clean flag error).

**Pinned by** `TestJitteredIntervalBounds` (bounded + seeded-reproducible),
`TestJitteredIntervalDegenerateInputs` (never negative, no-op for
percent<=0), and `TestJitteredIntervalDiffuses` (both halves of the range
across seeds).

## Verified correct (no action)

- **Chained refresh is real**: overwriting a LIVE registration requires
  `prev_token`, compared constant-time; expired registrations are
  intentionally re-registrable (M-N3 pins the boundary).
- **Token shape rule holds**: 16..=128 bytes at freg, closing the fpop
  empty-token bypass; fpop compares constant-time and 403s on mismatch.
- **Dedupe cannot corrupt the hold**: the superseded envelope file is dropped
  only when the content-address actually changed (the byte-identical refresh
  case is preserved) — the F1 #4 fix is present and tested.
- **Shape-only validation**: pointer length (exactly 74), version/header
  bytes, nonzero deadline — relays never interpret pointer semantics (design
  law 4); a garbage pointer survives the relay and dies at the ratchet.
- **Compost-on-read + drain-time reap**: expired entries are deleted, never
  delivered; the worst-case never-drained residue is bounded by
  `max_per_handle` (and now, by the horizon cap, in time as well as count).
- **Hex case is not identity**: handles normalized to lowercase at every verb.
- **The drain feeds ONE decrypt path**: fabric pointers enter the same
  `e2Ingestor` pipeline as chain-carried pointers, with the bootstrap fence
  (FrameInit refused on the fabric path) pinned by unit tests in spore —
  no second receive path exists to attack.
- **Go/Rust derivation agreement** is pinned by generated interop vectors
  (`fabric_v1` in `interop-vectors.json`), not by review — handles, tokens,
  and the envelope codec are byte-identical across implementations, with
  negative vectors refused.
- **Deploy posture** (`7691059` `no-verify-hash`, `7be409a` `no-verify-hash`): the systemd unit sandboxes the
  relay (DynamicUser, ProtectSystem=strict, AF_INET/AF_INET6 only), asserts
  readiness via the pidfile, and the daemon's graceful shutdown removes the
  pidfile on SIGTERM/Ctrl+Break while SIGKILL correctly leaves the dead-run
  signal — the supervisor contract an operator actually needs.

## Accepted risks (dispositions carried and confirmed)

1. **Lease-vs-takeover race window** (F1 #8): between lease expiry and
   renewal, a squatter can take the handle. Bounded by the owner-chosen
   expiry; squatting one epoch's slot reads nothing (fpop needs the token)
   and the seed derives the next epoch's handle anyway. Confirmed bounded by
   M-N3's live-check. Revisit only with F3 telemetry showing griefing.
2. **No cross-restart registry persistence** (F1 #9): a relay restart clears
   leases; owners re-register at next drain (the F2 client does this);
   queued envelopes persist and re-index. Durability belongs to the queue,
   not the lease. Confirmed correct — and the `open()` rebuild now also
   enforces the horizon cap retroactively.
3. **Distributed freg budget-fill** (F1 #10): junk leases can fill the 50k
   budget and 503 real users. Unchanged; the seed-bound token (which F2
   clients always have) remains the natural default-path upgrade if
   telemetry justifies it.
4. **Timing correlation across relays** (threat model, v1): real and
   unmitigated; jitter is R-N2, cover traffic is F4. The fabric starts no
   worse than the shipped pointer-on-chain posture.

## Remediation record

| Finding | Fix | Tests |
|---|---|---|
| H-N1 immortal envelopes | spore-peer `78e69a4` `no-verify-hash` — `max_deadline_horizon_sec` enforced at fput, composted at rebuild | `fput_deadline_horizon_cap_refuses_immortal_envelope` |
| M-N2 sweep amplifier | spore-peer `78e69a4` `no-verify-hash` — 1s-gated sweep | `freg_sweep_is_time_gated` |
| M-N3 expired-equals-absent | spore-peer `78e69a4` `no-verify-hash` — explicit live-check | `expired_registration_re_registrable_before_sweep` |
| R-N1 drain-union dedupe | spore `3ec84c0` — SeenCIDs consumed-set in the drain loop | `TestDrainUnion*` + `TestSeen*` |
| R-N2 drain jitter | spore `444122f` — per-pass ±20% cadence jitter (`-fabric-jitter`) | `TestJitteredInterval*` |
