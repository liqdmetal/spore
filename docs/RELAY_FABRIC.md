# Relay fabric — the pointer-forwarding half (design)

*Status: slice F1 (relay verbs + envelope, vector-pinned) **shipped**;
F2 (Go client, `spore fabric subscribe` drain loop, `-route-fabric` on send,
cross-binary interop) **shipped**. Roadmap row #8. The
body half it builds on is shipped: `sporepeer://` + `spore serve` (see
[`WIRE_SPEC.md`](WIRE_SPEC.md) §5/§7/§8, [`PEER_SETUP.md`](PEER_SETUP.md),
[`AUDIT-SPOREPEER.md`](../AUDIT-SPOREPEER.md)).*

## The problem, precisely

E2 message delivery has two halves:

| Half | What it is | Status |
|---|---|---|
| Body | the encrypted frame, 74-byte pointer's CID → bytes | **shipped** — spore-peer P2P, both directions, interop-tested |
| Pointer | `Version(1) + Route(32) + CID(32) + BurnDeadline(8)` | rides DERO whisper (needs a chain node) or the mailbox hop (needs an always-on server) |

The pointer is 74 bytes and contains no plaintext, no ciphertext, and no key —
`Route` is a public lookup handle, `CID` commits to the off-chain body, and
`BurnDeadline` is the TTL. The relay fabric forwards exactly these 74 bytes
through volunteer-run relay nodes, so neither endpoint needs an always-on
server: the sender publishes pointers into the fabric, the recipient drains
them from it, and bodies still travel strictly peer-to-peer over the shipped
spore-peer path. Relays see what a DERO node's mempool would see about a
whisper pointer — and nothing more, because there is nothing more.

## Design law (inherited, not invented)

1. **Reuse the spore-peer socket.** The fabric is a verb family on the JSON
   subset the peer transport already serves (coexisting with rpc2/CBOR
   per-frame, exactly as fetch/put/sync/push do today). A relay node is
   `spore-peer serve --dir … -fabric` — one flag, no new port, no new stack.
   Waku/Iroh/libp2p adapters are a later slice behind a `FabricTransport`
   interface, mirroring the pluggable-seam pattern `internal/rendezvous`
   already uses.
2. **Reuse the hold.** A queued pointer is a tiny body: the envelope is
   content-addressed (`cid = sha256(envelope)`), stored in the same
   `DiskStore` with the same `.exp`/`.expms` TTL records, the same crash-safe
   write ordering, the same reap/`410 gone` semantics, the same §7 contract,
   and the same sub-second precision. The fabric adds *no* new storage code —
   it adds an index, exactly the way `internal/relay` already does (the store
   seam is content-addressed and exposes no key iteration).
3. **Reuse the hardening.** `ServeConfig`'s put rate limiting, store quota,
   and write-token gate apply to fabric verbs unchanged. Per-handle caps are
   the fabric's addition, shaped like the existing per-IP window.
4. **The ratchet is the filter.** Relays never parse, validate, or interpret
   pointer semantics beyond size and deadline. A garbage pointer published at
   a handle is indistinguishable from a real one until the recipient's
   ratchet fails it closed — which is shipped behavior (AAD-bound sessions,
   rollback protection). The fabric's job is capacity hygiene, not meaning.
5. **Recipients dial; relays listen.** Only relay operators open ports. A
   recipient drains by dialing — the same posture as `spore-peer sync-loop`
   and the same privacy property: nobody can connect *to* a recipient.

## Wire additions (WIRE_SPEC §8, legacy JSON verbs)

Three verbs on the existing socket, following §5 conventions
(`0x00` + payload on success, `NNN text` errors):

```
freg  {handle, token, lease}          → 0x00 {token}
      Register/refresh a handle. token = HMAC-SHA256(seed,
      "spore/fabric/v1/reg" || handle || server_nonce), seed = the contact-
      card secret behind handle epochs (see Open question 1, DECIDED).
      Proves possession of the epoch seed; the relay stores and echoes it —
      no signature, no identity-key exposure to relays. Same trust model as
      the body side's write-token gate.
      Relays MUST cap lease <= min(requested, 7d) and <= pointer deadlines.

fput  {handle, pointer_b64, deadline}  → 0x00 | 413 caps | 429 rate | 410 late
      Queue a pointer envelope. pointer_b64 is the 74-byte
      PointerPayload verbatim — relays MUST reject any other length.
      deadline MUST be nonzero and within the relay's horizon cap.
      Dedupe on (handle, CID): re-publishing refreshes, never duplicates.

fpop  {handle, token, max}             → 0x00 {pointers: [...]}
      Drain up to max queued pointers, oldest first, deleting on read
      (compost-on-read — the store's own philosophy). Token = the freg HMAC,
      echoed. Wrong/missing token is 403; unknown handle is 404 (same string
      discipline as the body side).
```

CBOR/rpc2 variants (`Peer.FabricPut/Pop`) follow in the slice that ports
sync/push conventions; the legacy verbs land first for testability, as the
body transport did.

Envelope on disk (inside the hold, namespaced by the fabric index — the body
files themselves are ordinary §7 objects):

```
fabric envelope v1:
  version      u8            = 1
  handle       [32]byte      (== pointer.Route — the epoch-salted fabric
                             derivation for this send; indexed, never
                             interpreted)
  pointer      74 bytes      (PointerPayload verbatim; CID + BurnDeadline inside)
  received_at  u64           (unix-seconds, for FIFO order + diagnostics)
cid = sha256(envelope) — the object obeys the full hold contract
```

## Flow

**Publish (sender):**
`spore msg … -route-fabric relay1.example:8099,relay2.example:8099`
— after the normal E2 send produces the pointer, the CLI `fput`s it to every
named relay (parallel, best-effort; ≥1 accepted ⇒ send succeeds, and the
honest-limit note names the redundancy). Relay list comes from the contact —
the same out-of-band channel that already carries route keys and
`sporepeer://` addresses (`PEER_SETUP.md` gains a "fabric relays" line, not a
new discovery protocol).

**Subscribe + drain (recipient):**
`spore fabric subscribe -relay … -fabric-interval 90s -fabric-jitter 20`
— registers the handle at each relay, then loops: dial, `fpop` the queue,
feed each 74-byte pointer into the **same ingestion point** that consumes
chain/carrier pointers today (`ratchetwire.ParsePointerPayload` → E2 receive →
body fetch over `sporepeer://`, which enforces `RouteKey(sid) == p.Route` —
the binding that also makes fabric handles derivable rather than minted). No
new receive path exists; fabric pointers are carrier pointers that arrived
over TCP. Drain failures back off
exponentially — the cadence and jitter knobs are `sync-loop`'s, reused.

**Relay:**
`spore-peer serve --dir HOLD -fabric` — stores envelopes in the hold,
reaps at their deadlines (background ticker inherited), enforces per-handle
queue caps (default 32, FIFO-evict-oldest — compost, don't hoard), per-IP
publish rate windows, and global store quota. Restart safety = the §7
contract + the fabric index persisted temp+rename, exactly
`internal/relay`'s durable-index lesson, cited here so it isn't relearned.

## Threat model (honest, per this repo's audit culture)

| Adversary | Capability | Outcome |
|---|---|---|
| Relay operator | reads/stores/drops/delays pointers | Sees handle, timing, sender IP, constant size — the same metadata a chain node sees for a whisper pointer. Cannot read bodies (CID is a content address; bodies are E2-encrypted), cannot forge (ratchet fails foreign pointers closed), cannot redirect (AAD-bound sessions). Can deny service — availability is the fabric's honest weak point, mitigated by N-relay redundancy, never eliminated. |
| Handle spammer | floods `fput` at a public handle | Per-handle FIFO cap evicts oldest under flood; per-IP rate windows; 74-byte objects make the flood cheap to absorb and expensive to matter. The recipient's ratchet rejects what isn't hers; drain cost is bounded by the cap. |
| Handle hijacker | registers someone else's handle | `freg` requires the epoch-seed HMAC over a server nonce — possession of the seed, not knowledge of the public handle, drains. The seed rides the contact card (same channel and trust as `sporepeer://` addresses); a stolen seed holds the handle only until the next epoch rotation — bounded blast radius, the same class as a stolen single-use prekey. Registration binding is the fabric's one new crypto primitive; everything else is inherited discipline. |
| Remote prying eyes | port-scans a relay | Unauthenticated-body-fetch limits inherited verbatim from AUDIT-SPOREPEER: reachability ≠ readability; pointers are inert without the ratchet; loopback/firewall defaults unchanged. |
| Timing correlator | watches publish + drain across relays | Real and unmitigated in v1 — state it plainly. Jitter knobs and cover traffic are F4; the pointer-on-chain model has the identical exposure (the chain is a public timing oracle), so the fabric starts no worse than the shipped posture. |

## What this is NOT (scope fences)

- **Not anonymity infrastructure.** v1 hides recipient listening (none — they
  dial) and moves trust from mailbox operators to N-of-M volunteers. Sender
  IP is visible to first-hop relays. Onion hops and Iroh-style transports are
  F4 with their own honest analysis.
- **Not a body path.** Bodies never touch the fabric; they ride the shipped
  spore-peer transport with its sha256-both-sides guarantees. A relay that
  also holds bodies does so as an ordinary spore-peer node, separately.
- **Not incentivized.** Volunteers and Model-B operators, same as today's
  relays. No token, no payments — per this repo's sustainability stance.

## Staged slices (each ships gated, vectors-first)

| Slice | Delivers | Gate |
|---|---|---|
| **F1** — **shipped, adversarially reviewed** | envelope + store/reap reuse; `freg`/`fput`/`fpop` in spore-peer behind `-fabric`; hostile-frame tests (wrong-length pointers, deadline abuse, handle/token mismatches, cap eviction) | **done**: `fabric_v1` vectors in `interop-vectors.json` ([`WIRE_SPEC.md`](WIRE_SPEC.md) §8) generated first, then consumed by Go (`internal/fabric` + `internal/secure` conformance) and Rust (spore-peer `fabric` mod) — byte-identical handles from `(seed, epoch, sid)` proven, negatives refused. Post-ship adversarial review (leases, quota abuse, token handling, dedupe) landed the hardening below |
| **F2** — **shipped** | Go side: `internal/fabric` client (freg/fput/fpop + lease renewal + re-register-on-403), `spore fabric subscribe` drain loop → shared `e2Ingestor` pipeline (ONE decrypt path with `msg recv-e2`), `-route-fabric` on `msg send-e2`/`msg reply-e2` (dual-publish n/n−1, chain stays carrier of record), seed + relays ride the contact card (`-invite` → `mail add`), `spore fabric handle` for derivation. Cross-binary: real Rust relay + real `spore fabric subscribe` binary end-to-end (publish-poll past the honest 404 → freg → fpop → decrypt → maildb) plus Go-side drain interop in `internal/peerstore`; bootstrap fence pinned by unit tests (unknown sessions are never derivable; FrameInit refused on the fabric path) | the cross-binary test rides `SPORE_PEER_BIN` + `RACE_PKGS` (every push via gates, and on tagged releases via `release.yml` → `spore-peer-contract.yml`, where it gates the publish path); unit fence tests run hermetic |
| **F3** — **audit opened; drain-union + jitter shipped; knobs remaining** | N-relay redundancy + drain-union dedupe by CID, per-handle quotas + jitter, durable fabric index, `AUDIT-RELAYFABRIC.md` with the same hash-pinned remediation treatment. Landed so far: the audit (scope-vs-commits table; one HIGH fixed — immortal envelopes, spore-peer `78e69a4` `no-verify-hash`; two MEDIUMs fixed), the **drain-union** (spore `3ec84c0`: one consumed-CID set across relays and restarts, marked on ingest success only — M-relay redundancy costs ONE body fetch), and the **drain jitter** (spore `444122f`: per-pass ±N% cadence, `-fabric-jitter 20` default, closing R-N2's timing-signature fidelity gap). Remaining: operator-facing fabric knobs | doc-refs CI over the new audit (live in `docs/refs.yml`) |
| **F4** | transport adapters (Iroh/Waku) behind `FabricTransport`; cover traffic; multi-hop onion publish; CBOR method variants | separate design addendum per adapter, same audit discipline |

F1+F2 make roadmap #8 honest to close the way the serverless row closed:
when the fabric carries a real pointer from a real send to a real drain in CI,
the row moves to Shipped — not before.

## F1 adversarial review — findings and dispositions

Scope: lease expiry races, queue-quota abuse, token handling, and the fput
dedupe path on the shipped relay surface. Every HIGH is fixed; the rest are
disposed below.

| # | Finding | Disposition |
|---|---|---|
| 1 | **HIGH — unauthenticated `freg` memory DoS.** No cap on live registrations; an attacker grows the registry unboundedly. | **Fixed.** `max_regs` budget (default 50,000): full budget → 503; expired slots swept by the next `freg`; new registrations never evict others'. |
| 2 | **HIGH — handle takeover via re-`freg`.** The handle is public; a third party could re-register a live handle under their own token and drain the victim's queue. | **Fixed.** Chained refresh: overwriting a LIVE registration requires `prev_token` matching the current token (403 otherwise), constant-time. Expired registrations are intentionally re-registrable — a squatter target like a fresh handle. |
| 3 | **HIGH — fpop token auth bypass via empty tokens.** `fpop` defaults a missing token to `""`; a registration with an empty/short token made the queue drainable by anyone. | **Fixed.** Token shape rule 16..=128 bytes at `freg` (400 otherwise); ceiling also bounds registry memory per entry. |
| 4 | **HIGH — dedupe refresh corrupted the hold.** The envelope bytes include `received_at`, so a dedupe refresh usually re-persists under a NEW cid; the old code dropped the OLD file and re-pointed the queue entry — correct — but on a byte-identical refresh (same `received_at`) old and new cid are the SAME file, which the drop deleted: the queue entry was left fileless and the envelope silently vanished at the next restart. | **Fixed.** Drop the superseded file only when the cid actually changed; the refresh test now pins exactly one `.fenv` on disk and post-restart integrity. Found by a test, not by reading — the vectors-first culture again. |
| 5 | **MED — burned envelopes were never reaped.** Envelopes whose deadline passed while nobody drained lingered on disk forever. | **Fixed (bounded reap, no ticker).** Compost at `fput`-touch, at `fpop` drain (expired entries are deleted, not delivered), and at `open()` rebuild. Worst case: `max_per_handle` expired envelopes per never-drained handle, all gone at its next touch. Declared honestly in WIRE_SPEC §8; a periodic ticker stays available for long-lived nodes (the body store's `ReapEvery` pattern). |
| 6 | **LOW — hex-case identity split.** `AB…` and `ab…` could register/publish into two different slots. | **Fixed.** Handles normalized to lowercase hex at every verb; case-is-not-identity is tested. |
| 7 | **LOW — fpop flood asymmetry.** `fpop` was rate-unlimited while `fput` was not; both are unauthenticated parser paths. | **Fixed.** `fpop` shares `fput`'s per-IP window. |
| 8 | **Accepted risk — lease-vs-takeover race window.** Between a lease expiring and the owner's renewal, a squatter can take the handle. Bounded by the expiry the owner chose; the same window exists for a fresh handle and the seed derives the next epoch's handle anyway — squatting one epoch's slot cannot read anything (fpop needs the token) and costs the attacker nothing but the slot. | **Accepted.** Revisit only if F3 telemetry shows slot-squatting griefing. |
| 9 | **Accepted risk — no cross-restart registry persistence.** Registrations are in-memory; a relay restart clears all leases. Owners re-register (the client does this at next drain in F2); pointers already queued are NOT lost — envelopes persist and re-index. | **Accepted.** Durability belongs to the queue, not the lease; a persisted registry would need its own churn/expiry design for no recipient-visible gain. |
| 10 | **Accepted risk — per-IP rate window is the only flood bound for `freg`.** Budget caps memory; the shared per-IP window caps request rate. A distributed `freg` flood can fill the 50k budget with junk leases (each ≤7d) and cause 503s for real users. | **Accepted for F1.** Candidate F3 mitigation: proof-of-possession already exists — require the `freg` HMAC token (seed-bound) as the default path and keep open registration as a fallback with a lower budget. Deferred until the F2 client exists to say what the default path needs. |

## Open questions (carried, not hidden)

1. **Handle epochs — DECIDED (this decision is F1's wire-freeze baseline).**

   *Problem.* `Route = RouteKey(sid)` and `sid` is fixed per session, so the
   fabric handle for a conversation is stable for the session's lifetime —
   linkable across every relay-choice change in that window, by any relay the
   pointer transits or any observer correlating handle across relays.

   *Decision.* The fabric handle is **not** `Route` — it is the
   `Route`-preserving epoch-salted derivation:

   ```
   FabricHandle = HKDF-Expand(seed, "spore/fabric/v1/handle" || epoch_be || sid, 32)
   ```

   - `seed` — 32 random bytes, generated once per contact, riding the contact
     card. Out-of-band, same channel and trust model that already carries
     `sporepeer://` addresses (PEER_SETUP gains one line, no new channel).
   - `epoch` — big-endian u32, incremented on prekey-batch rotation (batches
     already rotate; the increment rides the rotation that already happens).
   - `sid` — the session id; the term that keeps `RouteKey(sid) == p.Route`
     intact end-to-end.

   **Design law 4 preserved exactly.** The published pointer is unchanged:
   `Route = RouteKey(sid)` verbatim, verified by `FetchFrame`'s existing
   `RouteKey(f.SessionID) == p.Route` check on ingest. `FabricHandle` is the
   *lookup* handle only — relays index envelopes by it and never learn `sid`
   (HKDF is one-way); the recipient derives it from `(seed, epoch, sid)` and
   drains. The pointer/Route plane stays derivation-pinned; the fabric plane
   adds salt. The two layers touch at exactly one seam: on drain, the
   recipient pops `pointer.Route` and feeds the pointer to E2 ingestion —
   which already enforces the RouteKey binding.

   **Why HKDF over the raw pointer salt:** salting the pointer's Route itself
   would force *senders* to mutate `p.Route` to the salted value, violating
   the receive-side binding (`FetchFrame` refuses salted Routes) or forcing
   both sides to store a per-message salt map — coordination cost without
   adding unlinkability, since sid itself is stable per session. Salting the
   lookup handle and leaving the pointer plane untouched gets rotation at
   zero wire cost.

   **Rotation protocol — zero coordination via dual-publish.** During the
   rotation window, the sender publishes to *both* `FabricHandle(n)` and
   `FabricHandle(n-1)`, where n is the newest epoch the sender has learned.
   The window closes when every frame published under n−1 has burned (the
   senders' burn deadlines bound the window; no epoch handshake is needed).
   Recipients drain both epochs for the window, then drop n−1. Handles never
   collide across epochs: even if a sender lags an epoch (learned the new
   batch late), the worst case is continued publish to the drained, retired
   handle — pointers lost only if the lag outlasts the burn deadlines, the
   same failure mode as a missed rotation of prekeys themselves.

   **Seed rotation and compromise.** Contact-card seed compromise holds the
   handle only until the next epoch rotation; the recovery is *re-keying the
   contact out-of-band* (new seed ⇒ all handles change at the next epoch),
   the same recovery as a leaked prekey: rotate and re-exchange. Blast
   radius is bounded by epoch cadence, not by 7-day leases.

   **Cross-epoch linkage remains — honestly.** If both n and n−1 handles are
   observed at the same relay in the rotation window, the linkage is
   *inferable* (dual-publish is public). This is the same correlation the
   timing row already declares unmitigated in v1. Mitigations live in F4:
   asymmetric dual-publish (publish to n on all relays, n−1 only on relays
   still in the window), and bounded-window dual-publish (strictly cap the
   n−1 window at the max burn deadline of n−1-era frames — the window is
   self-expiring).
2. **Relay discovery.** Out-of-band (contact exchange) in v1. A gossip
   endpoint on the fabric socket is tempting and deferred — it reintroduces
   the discovery metadata the design exists to avoid centralizing.
3. **Multi-device.** Two devices draining one handle compete for pointers.
   v1: drain is delete-on-read, so each pointer lands on exactly one device —
   the E2 device-sync path (`e2-device`) is the reconciliation story, and the
   interaction needs its own slice before F3 closes.
