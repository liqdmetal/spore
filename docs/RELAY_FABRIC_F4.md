# Relay fabric F4 — transports, cover traffic, and onion publish

*Design addendum to [`RELAY_FABRIC.md`](RELAY_FABRIC.md). F1–F3 shipped the
pointer-forwarding fabric on the spore-peer socket: verbs, registry, queue
caps, drain-union, jitter, operator knobs, and the hash-pinned audit
([`AUDIT-RELAYFABRIC.md`](../AUDIT-RELAYFABRIC.md)). F4 is the slice that
attacks the metadata the threat model honestly declared unmitigated in v1:
timing correlation and the sender→relay linkage. This document is the design
of record for F4; nothing here is built yet, and the slice plan at the end is
the build order. Same law as always: vectors first, audit on landing.*

---

## What F1–F3 actually leak (the baseline this slice improves)

Restating precisely, because F4's value is measured against it:

| Observer | Sees today | Consequence |
|---|---|---|
| First-hop relay | sender IP, handle, publish times, constant 74-byte size | Can correlate *this sender* with *this handle* and fingerprint the sender's send cadence (timezone, waking hours, burst patterns) |
| Every relay on the publish path | same, per relay | N relays = N independent copies of the linkage; any one of them can be hostile |
| Relay the recipient drains | recipient IP, handle, drain times | Recipient is linkable to the handle permanently, at every drain |
| Rotation window (n and n−1 both live) | two handles co-drained / co-published | Cross-epoch linkage is *inferable* — declared in RELAY_FABRIC open question 1 |
| Global passive adversary | traffic across relays | Fully out of scope — see the honest limits section |

What already helps and must not be regressed: the pointer is constant-size
and content-free; the drain loop is always-on and jittered (an empty drain is
byte-identical to a real one — the shipped cadence is *already* drain-side
cover); handles are epoch-salted; the ratchet is the filter.

The asymmetric truth F4 must state up front: **publish-side anonymity is
improvable inside the current architecture; recipient-side anonymity is not**
— the recipient still dials relays from a stable IP (design law 5), and
fixing that needs a network-level anonymity layer on the *dial* side, which
is its own slice (F5 candidate, sketched at the end). F4 protects senders;
it leaves recipients exactly at today's posture, no better and no worse.

## 1. FabricTransport — the adapter seam

### Problem

The wire is JSON verbs on a TCP socket. Waku/Iroh/libp2p transports want to
carry the same verbs without re-speccing them, and the CBOR/rpc2 variants
(`Peer.FabricPut/Pop`, deferred since F1) are the same problem in miniature:
a different encoding over the same semantic verbs.

### The seam

One interface, in Go first (the client lives there; the Go side of
`internal/peerstore` already serves the same verbs as the reference relay),
modeled on the codebase's existing pluggable-transport pattern
(`internal/rendezvous`: interface + in-memory proof implementation before any
network adapter):

```go
// FabricTransport moves fabric request/response pairs to a relay.
// Implementations carry EXACTLY the verb semantics of the TCP socket —
// same 0x00/NNN framing of outcomes, same token checks server-side —
// and add nothing else. A transport that interprets, caches, retries
// differently, or reorders across handles is wrong.
type FabricTransport interface {
    // RoundTrip sends one fabric request (verb + payload) to the relay
    // and returns the outcome. No pipelining, no multiplexing across
    // handles: one logical request in, one outcome out. The pointer and
    // token bytes are opaque payload.
    RoundTrip(ctx context.Context, req Request) (Outcome, error)
    io.Closer
}
```

`TCPTransport` is the trivial first implementation (what F1–F3 do inline).
`MemTransport` proves the client state machine transport-agnostic in unit
tests, exactly as `rendezvous.MemTransport` does for the body path.

### Why the Rust relay core does not grow adapters

spore-peer is deliberately near-stdlib (its only platform dep is the Win32
call for graceful shutdown). Pulling iroh or libp2p into the relay binary
would import thousands of crates into the audited hostile-frame surface.
Instead:

**Adapters are sidecars.** A transport adapter runs as a separate process
beside the relay or client and speaks the existing JSON socket locally. The
Rust relay keeps serving exactly one transport (TCP) forever if it wants; an
Iroh-relay deployment is `spore-peer serve … -fabric` (untouched, TCP,
loopback firewalled) plus an `spore-iroh-bridge` sidecar that accepts Iroh
conns and replays them onto the loopback socket. The audited crypto-and-parse
surface of the Rust core does not move; the adapter is a new, separately
audited artifact that cannot escalate — it sees only what a remote client
sees.

This is the honest cost of the zero-dep ethos: one extra process per exotic
transport. It buys a frozen audit surface. Declared trade, not an accident.

### The CBOR/rpc2 variants fold into the same seam

`Peer.FabricPut/Pop` (rpc2/CBOR, for sync/push-style callers) is just a
second encoding behind the same `Request/Outcome` round trip, with the same
server-side checks and the same `fabric_v1` vectors extended with CBOR
conformance cases. It is slice F4d, not an independent design — no new
semantics, therefore no new threat model.

## 2. Cover traffic

### Attacks it addresses — and the ones it must not pretend to

**A. Publish fingerprinting (the real target).** A first-hop relay sees the
sender's fput times. A sender who transmits three times a day publishes a
behavioral fingerprint per handle; every real fput is a high-information
event. Cover traffic inserts *decoy fputs* so the relay's view of the handle
is a stream whose dense part hides the sparse real sends.

Design:

- **Cover pointers go to the REAL handle.** A decoy handle is a beacon (it
  exists only for cover and is observable as such); cover must be
  indistinguishable from real at the relay, so it reuses the same handle,
  same verb, same size.
- **The decoy pointer is a real pointer to a real body the sender holds** —
  a per-cover-pointer blob of random bytes stored with a short TTL. The CID
  must NOT be a global constant: a well-known "decoy CID" repeated across
  every spore user's stream would be the single most recognizable byte
  pattern in the network. The sender mints fresh decoy bodies; the *only*
  entity that can distinguish cover from real is the recipient, because the
  recipient's ratchet fails the decoy closed. That failure is the covert
  channel, and it is free: the shipped pipeline already fails foreign
  pointers closed and the drain-union prevents reprocessing.
- **Recipient cost is one failed decrypt per cover pointer.** No body fetch
  occurs unless the ratchet accepts (fetch happens only for pointers that
  decrypt to a session-bound route), so the cost is a decrypt and a
  bookkeeping entry — microseconds, against a cover rate of order 1/hour.
  Declared so nobody discovers it as a surprise.
- **Rate shape: Poisson, not periodic.** Cover on the same ±jittered timer
  as drains would be periodicity wearing a wig. Cover events are drawn
  from an exponential distribution (mean = 1/rate) independent of the send
  path, the jitter timer, and the drain timer — three independent clocks,
  because clock *correlation* is itself a fingerprint.
- **Knob: `-fabric-cover-rph` (covers per hour, default 0).** Default off,
  deliberately: cover traffic changes a node's public request profile, and
  operators on metered or monitored IPs should choose that consciously.
  PEER_SETUP will carry a recommendation (2/hour for personal handles;
  note that a cover rate wildly mismatched to real send volume is its own
  signal — cover must roughly dominate, not sprinkle).
- **Burst folding.** A real send during a cover-heavy hour should not stand
  out as a spike; conversely the publish planner may *fold* a real send into
  the next scheduled cover slot when `-fabric-cover-rph` is high enough that
  the added latency (mean half the cover interval) is acceptable. This is a
  sender-side latency/anonymity trade knob (`-fabric-cover-fold`, default
  off), stated honestly: folding hides the send time *within the cover
  distribution* at the price of up to a full cover interval of latency.

**B. What cover traffic does NOT do** (the fence):
- It does not hide the sender IP — cover fputs come from the same IP. That
  is fine: the goal is unlinking *sends* from *meaning*, not hiding the
  actor. IP-level hiding is onion publish (§3) and its limits are stated
  there.
- It does not protect against a relay that also drains the handle (it
  cannot — token-gated) or against queue-depth side channels (none exist:
  fpop results are token-gated and delete-on-read).
- It does not help the recipient at all; drain-side cover is already the
  always-on jittered cadence shipped in F2/F3. Cover knobs apply to the
  publish path only.

### Cost accounting

74 bytes/cover + one stored decoy body (sender-side, short TTL) + one failed
decrypt (recipient-side). At 2/hour that is ~3.5 KB/day of relay traffic and
48 decrypts/day of recipient CPU. The honest statement: the traffic cost is
trivial; the *design* cost (three independent clocks, per-pointer decoy
bodies, the fold knob) is where the complexity lives, and that is where the
audit will look.

## 3. Multi-hop onion publish

### What problem is actually solved

Today every relay on the publish path learns (sender IP, handle). With N
relays there are N complete linkage records; a single hostile relay is
sufficient to correlate. Onion publish's deliverable, stated exactly:

> **No single relay sees both the sender's IP and the recipient's handle.**
> The first hop sees the sender but a wrapped payload; the final hop sees
> the handle but an onion (or, with §2 cover, a stream of onions). Each
> intermediate hop sees only its predecessor and successor in the chain.

It does NOT hide the sender from the first hop, the recipient from the final
hop, or anyone from a global passive observer. It is Tor's exact threat
position, and the design borrows Tor's discipline accordingly.

### The wire: a v2 envelope is forced, and here is why

`fput` validates `pointer_b64` as exactly 74 bytes — that shape check is a
shipped hostile-frame defense. Onion layers (32-byte ephemeral key + AEAD
overhead per hop) cannot fit in 74 bytes; two hops already exceed it.
Therefore F4 adds **`fput2`**, keeping `fput` byte-frozen:

```
fput2 {handle, onion_b64, deadline}   → 0x00 | 413 caps | 429 rate | 410 late
      onion_b64 = layered envelope; each layer decrypts (with the
      receiving relay's forward key) to either
        {next: {addr, onion_b64}}     — forward: relay re-publishes
      or
        {pointer: 74 bytes}           — terminal: relay queues under
                                        its freg'd handle
      Same dedupe, quota, rate, horizon, compost rules as fput, applied
      to the WRAPPED object's handle and deadline.
```

Relays peel exactly one layer — the one addressed to them — and never see
the stack's origin or depth beyond next-hop. This is a scoped amendment to
design law 4 ("relays validate shape and interpret nothing"): the onion's
*content* remains inert (law 4 unchanged for pointers); the *routing
wrapper* is new crypto that the audit must treat as the fresh primitive it
is. Everything downstream — quota keyed on the handle field, horizon on the
deadline field, dedupe on the wrapped object's CID — is inherited, which is
the point of keeping the verb family.

### Relay forward identity

A relay that accepts `fput2` publishes a **route descriptor**:

```
{addr, forward_pubkey (X25519), forward_handles: [...]}
```

`forward_handles` are self-registered handles (freg with the relay's own
token — open registration already permits this, per the F1 audit's finding
10 discussion). The onion's forward layers are addressed to forward handles;
the terminal layer to the real recipient handle. Key lifecycle follows the
contact-card epoch mechanics: descriptor rotation = new epoch, old keys
honored only for in-flight deadlines (bounded by the horizon cap, like
everything else).

Route descriptors ride the same out-of-band channel as relays do today
(RELAY_FABRIC open question 2 stays closed: still no discovery protocol, and
deliberately so — a gossip endpoint for descriptors would be a chaining
oracle).

### Chain construction (sender side)

1. Pick k relays from the contact card (default 2: one entry, one terminal;
   k is a knob, `-fabric-hops`, default 2, max 3 — each hop adds latency and
   a 32-byte layer; the marginal protection per hop decays fast and the
   analysis says say so).
2. Build innermost-first: `L_k = Enc(pk_k, {pointer: p})` addressed to the
   recipient handle at relay k; `L_{i} = Enc(pk_i, {next: addr_{i+1}, L_{i+1}})`.
3. Publish `fput2(handle=fwd_handle_1, onion=L_1)` — over the transport seam,
   so TCP and Iroh publishers are the same code.

Forwarding is best-effort per hop exactly like top-level fput: a hop that
cannot reach its successor drops the layer silently (the recipient sees
nothing; N-relay redundancy at the chain level remains the availability
story, and the honest-limit note from F2 applies to chains too).

### Drain stays as shipped — and that is the honest headline

The recipient drains the terminal relay directly. The terminal relay still
sees recipient IP + handle + drain cadence; onion publish protects the
*sender's* linkage only. This is called out rather than buried because the
 temptation to market F4 as "recipient anonymity" would be a lie: the
recipient-facing improvement in F4 is zero, and the drain-side problem
(a stable IP dialing the same handle forever) is the F5 candidate.

## 4. The timing analysis (quantified, not vibes)

Threat: a relay (or colluding relays) performing statistical correlation on
observed event times.

**Events and their distributions, post-F4:**

| Event stream | Distribution | Residual leak |
|---|---|---|
| Drains (any handle) | fixed cadence ±20% jitter, always-on, empty drains identical to real | Recipient-online oracle only: "the process is running." Unfixable without drain-side anonymity (F5). |
| Publishes to a handle with cover OFF | real sends only — sender cadence | Full fingerprint. Cover OFF is a choice; docs must not bury it. |
| Publishes with cover ON (rate λ) | Poisson(λ) + folded real sends | Real sends indistinguishable up to rate mismatch. If real rate ≳ cover rate, the excess reveals volume (not content timing) — recommend cover ≥ 2× expected real rate. |
| Rotation-window dual-publish | two handles co-live for bounded window | Linkage inferable (declared in F1's epoch decision). F4 ships the mitigations RELAY_FABRIC already names as defaults: **asymmetric dual-publish** (n−1 only on relays still inside the window) and the bounded-window cap. This is a publish-planner behavior, not new crypto. |
| Onion layer timing across hops | hop-to-hop forwarding delay (milliseconds; attacker-controlled at hostile hops) | A hostile hop can delay-and-correlate: hold each layer, watch for matching egress. Latency correlation across a hostile middle hop is **possible in principle and not defended** — same as Tor's confirmation attack; the defense is honest relay choice (k-of-N from the contact card), not crypto. |

**What jitter actually buys** (since F3 shipped it, worth stating its exact
power): it defeats *naive periodic matching* — an attacker aligning two
streams by their tick phase. It does NOT defeat aggregation: with enough
observed drains, the ±20% uniform widens the distribution but the underlying
cadence is still estimable. Jitter is hygiene; cover and onion are structure.

**The unpatchable core, stated once plainly:** message volume itself is a
signal. If a sender communicates 0 times for a week and then 5 times in an
hour, every defense above preserves that shape except cover-fold (which
smears sends into cover at latency cost). Metadata minimization has a floor,
and the floor is the traffic pattern itself. Any design claiming otherwise
is lying; this one doesn't.

## 5. What F4 is NOT (fences, in the house style)

- **Not recipient anonymity.** Drain dials are unchanged; F5 candidate.
- **Not a global-adversary defense.** No cover set size defends traffic
  confirmation by a global observer. Nobody honest builds that on volunteer
  relays.
- **Not new trust assumptions.** Relays remain honest-curiosity adversaries
  with denial-of-service capability; onion layers assume relay keys are
  per-deployment secrets, and key compromise fails closed to today's posture
  (a hostile relay with keys is still just a relay: it sees its hop).
- **Not post-quantum.** X25519+AEAD per layer, same as the body path; PQ is
  a cross-cutting future slice for all of spore, not an F4 special.
- **Not incentivized.** Chain relaying costs volunteers bandwidth; the
  sustainability stance is unchanged and unstinting.

## 6. Slice plan (each gated, vectors-first, audited on landing)

| Slice | Delivers | Gate |
|---|---|---|
| **F4a — transport seam: SHIPPED** | `FabricTransport` + `TCPTransport` + `MemTransport`; client state machine proven transport-agnostic (scripted-relay tests over the seam); the rpc2 method family (`Peer.FabricReg/FabricPut/FabricPop`) on the Rust relay behind the same cores as the JSON verbs, byte-exact frames pinned in `fabric_v1.rpc2_*` vectors, Go `CBORTransport` + `NewCBORClient` conformant, cross-binary Go-CBOR-client → Rust-relay test drives all three verbs over the second encoding | vectors extended first (the generator itself was caught pinning `false` for CBOR `true` — the Rust conformance test refused it); Go + Rust byte-exact conformance; cross-binary CBOR roundtrip green |
| **F4b — cover traffic** | Poisson cover scheduler, per-pointer decoy bodies, `-fabric-cover-rph` / `-fabric-cover-fold`, independent-clock property pinned by tests | distribution-shape tests (no periodicity), drain-union interplay, recipient-cost bound |
| **F4c — onion publish** | `fput2` verb (Rust + Go conformance), route descriptors, chain builder, asymmetric dual-publish defaults | hostile-layer tests (wrong-length, wrong-key, depth abuse, replay), vectors for layer construction, AUDIT-RELAYFABRIC F4 section |
| **F4d — Iroh sidecar** | `spore-iroh-bridge` adapter process (client and relay flavors) behind the seam | adapter audit: sidecar sees client-visible surface only; loopback firewalling documented |

Kill criteria, honestly: if F4b's recipient-side cost turns out to matter at
real cover rates (it should not, at one failed decrypt per cover), or if F4c's
layer crypto cannot reuse the body path's primitives without new code (it
should, X25519+AEAD exist), the slice shrinks rather than grows. The fabric's
availability story — N-relay redundancy — is never traded for metadata
improvements; features that reduce redundancy are rejected by definition.
