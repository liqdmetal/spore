# SporePeer Serving-Surface Security Audit — internal/peerstore (sporepeer://)

*Date: 2026-09-16 · Scope: the unauthenticated spore-peer serve listener and its
client — `internal/peerstore/sporepeer.go`, `internal/peerstore/peerstore.go`
(framing/Fetch), `internal/store/diskstore.go` (TTL) — checked against
`docs/WIRE_SPEC.md` §5. Threat model: anyone on the network can open TCP to the
listener; nothing is authenticated at this layer.*

> **FIX STATUS (2026-09-16): every finding is fixed — landed in commit `c0be97d`.**
> The sporepeer:// backend under review landed in `25206a2`; the CLI flag
> surface it rides on was extracted to `cmd/spore/e2store.go` in `8d31f44`.
> Regression tests: `internal/peerstore/sporepeer_hardening_test.go`.
> The three recommendations below are documented posture, not open bugs.

---

## Verdict

The serving surface is deliberately minimal and the core posture is sound: the
wire is **read-only** — there is no remote write path to attack, so a hostile
client can only read (200/404/410), never store, modify, or delete. Responses
are dispatched by **status byte only**, never by content sniffing (the H4 class
of bug from AUDIT-E2 — treating bodies starting with ASCII '4'/'5' as errors —
cannot recur here). The server re-verifies `sha256(body) == cid` before every
`0x00` answer, the legacy raw-body fallback is accepted only when the whole
payload hashes to the CID, and the burn deadline is enforced by `DiskStore.Get`
on **every** access. Requests accept only the exact documented
`{"cid":"<64 hex>"}` shape.

The findings were resource-exhaustion and resilience seams — the classic failure
modes of an unauthenticated TCP listener — not protocol-logic bugs. All three
were found and fixed in the same review.

---

## Findings

### H1 — HIGH: remote OOM via attacker-sized request pre-allocation

The serve path reused the client's `readFrame`, which does
`make([]byte, n)` from the attacker-chosen uint32 LE length prefix (up to the
64 MiB frame cap) **before reading a byte of payload**. N idle connections ×
64 MiB × the 30 s deadline was a trivial remote memory-exhaustion vector
against an unauthenticated listener. A legitimate request payload is 74 bytes
(`{"cid":"<64 hex>"}`); the 64 MiB cap exists for RESPONSE frames (bodies), not
requests.

**Fix**: a dedicated `readServeFrame` with a 64 KiB request cap, rejected on
the prefix alone — one request per connection, so there is nothing to drain —
answered with `400 bad frame` at constant cost.

**Pinned by** `TestServeRejectsOversizedRequest`: a declared 64 MiB prefix with
no payload must draw the `400` answer without the server ever allocating for it.

### H2 — HIGH (client side, same class): hostile-server pre-allocation

The client's `readFrame` had the identical flaw in the other direction: a
hostile or compromised *server* could declare a 64 MiB length prefix and make
every fetching client pre-allocate it before the first payload byte arrived.

**Fix**: `readFrame` now grows on demand in 32 KiB chunks — a lying prefix
costs a 4-byte read and a small buffer, never a length-prefix-sized allocation.

### M1 — MEDIUM: fatal accept loop

Any transient `Accept` error (fd pressure, connection aborted before accept)
silently and permanently killed the listener — and for long bodies this
listener **is** the whole delivery path. A hostile client could plausibly
induce exactly that error class.

**Fix**: back off 100 ms and continue; only a deliberate `Close()` ends the
loop. A hostile client can now cost the listener its backoff, not its endpoint.

**Pinned by** `TestServeSurvivesHostileThenServesValid`: oversized, zero-length,
and garbage probes, then a well-formed fetch must succeed.

---

## Verified correct (no action)

- **Read-only wire**: no remote write or delete path exists at this layer.
- **Content-addressed serving**: `sha256(body) == cid` re-verified before every
  `0x00` answer; the legacy raw-body fallback (old servers, WIRE_SPEC §5) is
  accepted only when the whole payload hashes to the CID; dispatch is by status
  byte only.
- **TTL is real**: `DiskStore.Get` enforces the burn deadline on every access —
  expired → `410 gone`, never served, and a burned-on-access body cannot
  reappear (`.exp` is checked before `.body`, reap composts).
  **Pinned by** `TestServeExpiredBodyReports410OnWire`.
- **Request parsing**: `parseCIDRequest` accepts only the exact documented
  shape — a hostile client cannot make the server act on anything else.
- **Peer verdicts are definitive**: a remote peer's `404`/`410` stops the
  fetch and is never masked by the local hold; only transport-level failures
  fall through to it.
- **Concurrency posture** is documented at `handleConn`: one goroutine per
  connection (an idle conn blocks in a 4-byte read; the 64 MiB pre-alloc is
  gone via the request cap), each hard-deadlined at `ioTO` (30 s), so a
  slowloris holds only its own goroutine for at most 30 s.

---

## Recommendations (documented posture, not fixed)

1. **No token gate or per-IP connection-rate limiting** beyond the deadlines —
   fd exhaustion is the remaining bound, and it is the OS's to enforce. Bind
   the listener to loopback or a firewall-protected interface today; a
   `HandlerToken`-style gate is the later fix if the posture changes. (Mirrors
   the per-IP rate-limit treatment the mailbox prekey pop got in AUDIT-E2's M1.)
2. **WIRE_SPEC §5 lists** `"404 not found"`, `"400 bad cid"`, and
   `"500 cid mismatch"` — but not the two error strings this surface now
   emits: `"400 bad frame"` (oversized/malformed request frame) and
   `"410 gone"` (expired body). The spec owes those two lines.
3. **Long-lived serving nodes should run a periodic `Reap`**: expired bodies
   linger on disk until a `Reap` runs, and the serve path reaps only on access
   to the expired CID. The demo in `cmd/spore/main.go` reaps explicitly; a
   serving daemon needs the same on a ticker or cron.

---

## Remediation

All three findings were fixed in commit `c0be97d`
(*fix(peerstore): cap serve request frames; tolerate transient accept errors*)
with regression tests in `internal/peerstore/sporepeer_hardening_test.go`:
`TestServeRejectsOversizedRequest`, `TestServeSurvivesHostileThenServesValid`,
and `TestServeExpiredBodyReports410OnWire`.

Review performed 2026-09-16 against the tree containing `8d31f44`; the backend
under review was introduced in `25206a2`. This document's own commit citations
are verified by CI via the doc-refs action (`docs/refs.yml`).
