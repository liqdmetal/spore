# Spore Wire Specification v1

*Source of truth for the canonical payload, envelope, pointer, and spore-peer
transport formats. Golden test vectors: [`interop-vectors.json`](interop-vectors.json)
(regenerate: `go test ./internal/secure/ -run TestGenerateWireSpecVectors`).
Conformance tests: Go `internal/secure` `TestSpec*`; Rust `spore_peer.rs`
`spec_*`. Byte-order note: canonical length prefixes are BIG-endian; the
spore-peer transport length prefix is LITTLE-endian (historical).*

Implementers MUST read this document together with `interop-vectors.json` —
every algorithm below has a vector.

---

## 1. Canonical payload (chain-agnostic, inside every envelope)

    byte 0        kind: 0x01 = text, 0x02 = pointer
    bytes 1..2    payload length, uint16 BIG-endian
    bytes 3..     payload:
                    text     = UTF-8 bytes (length = the uint16)
                    pointer  = eph_pub(32) || body_cid(32), uint16 must be 64

Vector: `"meet me at the garden gate"` →
`01001a6d656574206d65206174207468652067617264656e2067617465`
(see `canonical.encode_text_hex`; pointer vectors under `canonical.*`).

## 2. Envelope v2 (kind 0xE1) — signed, E2E-encrypted

    kind(1) || sig_pub(32) || eph_pub(32) || nonce(24) || sig(64) || ciphertext

Algorithms, in order:

    eph_pub   = X25519(eph_priv)                      eph_priv fresh per message
    secret    = X25519(eph_priv, recipient_pub)
    aead_key  = HKDF-SHA256(secret,
                             info = "spore/e2e/v1/key" || eph_pub || recipient_pub,
                             L = 32)
    nonce     = 24 random bytes (in-band, need not be secret)
    ct        = XChaCha20-Poly1305(aead_key, nonce, canonical_payload)
    sig_priv  = Ed25519 seed = SHA-256("spore/sig/v1/seed" || sender_x25519_priv)
    sig_pub   = Ed25519 pubkey of sig_priv
    sig       = Ed25519.Sign(sig_priv,
                    "spore/env/v2" || sig_pub || eph_pub || nonce
                                   || recipient_pub || SHA-256(ct))

The signature binds the sender key, ephemeral, nonce, RECIPIENT prekey, and
ciphertext: no forgery, no ciphertext swap, no cross-recipient replay.

Legacy v1 (kind `0xE0`, `eph_pub || nonce || ct`, unsigned, unbound HKDF) is
decryptable for migration only; strict receivers refuse it.

## 3. Receiver verification order (normative)

1. Parse the kind byte. Unknown → reject.
2. v2: Ed25519-verify `sig` over the transcript (recipient_pub = own pubkey
   derived from own scalar). Failure → reject BEFORE any ECDH/AEAD work
   matters.
3. ECDH + HKDF + XChaCha20 open. Failure → reject.
4. Strict mode additionally rejects kind 0xE0 and any non-envelope payload.
5. If the receiver pins sender keys, `sig_pub` must be pinned (after step 2).

## 4. CID

    CID = SHA-256(ciphertext bytes)

Double duty: off-chain retrieval key (mailbox `/put/{cid}`, spore-peer serve)
and on-chain pointer commitment. Verified on push, pull, relay, and pre-decrypt.

## 5. spore-peer transport frame (Rust)

    frame = uint32 LE length || payload        (length capped at 64 MiB)
    request payload  = JSON {"cid": "<64 hex chars>"}
    ok    payload    = 0x00 || body            (sha256(body) MUST == cid)
    error payload    = 0x01 || ASCII error     ("404 not found", "400 bad cid",
                                                "500 cid mismatch", "400 bad frame",
                                                "410 gone")

Clients decide by the STATUS BYTE only — never by content sniffing (audit H4:
the old client treated bodies starting with ASCII '4'/'5' as errors, rejecting
~1.6% of random ciphertexts). Old servers (raw body, no status byte) are
accepted only if `SHA-256(whole frame) == cid`.

Vectors under `spore_peer_frame`:
`070000000034343434abcd` (ok, body `34343434abcd` — deliberately starts with
ASCII '4') and `0e00000001343034206e6f7420666f756e64` (error, "404 not found").
The hardened server's two additional error strings (audit: the serve surface):
`0e0000000134303020626164206672616d65` ("400 bad frame" — request frame was
malformed or over the 64 KiB request cap) and `090000000134313020676f6e65`
("410 gone" — body existed but its burn deadline has passed; never served,
ever reshaped into a 404).

## 6. Vector file contract

`interop-vectors.json` fields:

- `fixed_scalars` — the X25519 scalars and nonce every vector is built from.
- `derived_keys` — intermediate values for stage-by-stage verification
  (`aead_key`, `alice_sig_pub`, pubkeys).
- `canonical` — text and pointer encodings.
- `envelope_v2_text` / `envelope_v2_pointer` — full deterministic envelopes
  (`expected_payload_hex`) built via `EncryptDeterministic`.
- `spore_peer_frame` — transport frames computed from the layout above,
  including the hardened server's `400 bad frame` and `410 gone` error
  strings (`expected_bad_frame*`, `expected_gone*`).
- `fabric_v1` — relay-fabric derivations and codec (§8): handles, reg
  tokens, envelope, plus negative vectors (`handle_negative_epoch8_hex`,
  `reg_token_negative_other_nonce_hex`, `envelope_negative_bad_version_hex`,
  `pointer_negative_len73_hex`) that a conformant implementation MUST
  fail against.

A new implementation is conformant when, given `fixed_scalars`, it reproduces
every `expected_*` byte-for-byte, and when its receiver accepts the committed
v2 envelopes while rejecting tampered, cross-recipient, and unsigned variants.
For `fabric_v1`, conformance additionally means failing on every
`*_negative_*` vector.

## 7. Appendix: the spore-peer hold layout (DiskStore)

`spore-peer serve --dir` and `spore serve -dir` hold bodies in a plain
directory. Implementations serving or manipulating the same layout must honor
this contract; the reference Go implementation is `internal/store/diskstore.go`
and its sub-second regression tests live beside it.

    <cid hex>.body   raw ciphertext (sha256(body) MUST equal the cid bytes)
    <cid hex>.exp    unix-seconds deadline as decimal text — the floor of the
                     true deadline; the record every version reads
    <cid hex>.expms  unix-millis deadline as decimal text — optional
                     refinement written by current versions

Semantics:

- **Content addressing.** The file name is the hex CID, and a server
  re-verifies `sha256(body) == cid` before every `0x00` answer (§5).
- **Never-expires and crash ordering.** A deadline of `0`, or a missing
  `.exp`, means the body never expires — deliberately. The store writes the
  expiry record BEFORE the body (each via temp+rename), so a crash
  mid-write can only leave a dangling expiry file with no body (harmless:
  the body reads as not-found and reap cleans it up), never a body whose
  expiry is unknown — a body that could never be reaped would break the
  compost guarantee the whole store exists to provide.
- **Deadline resolution.** `.expms`, when present and parseable, is
  authoritative; otherwise the seconds floor applies. The ms record exists
  so mid-second deadlines are enforced at read time and reaped on the
  first pass that crosses them, not on the second rollover. Read-time
  enforcement and reaping MUST resolve through the same rule: a body is
  never served past its deadline while its bytes remain on disk, and never
  reaped while it would still be served.
- **Downward compatibility.** An implementation that does not know
  `.expms` ignores it and works off the seconds floor — which errs toward
  treating a body as expired EARLY, never serving longer than the true
  deadline allows. A missing or malformed `.expms` likewise falls back to
  the floor.
- **Enforcement vs composting.** Expiry is enforced at READ time on every
  access (`410 gone`, §5); background reaping (`spore serve
  -reap-every`) only changes WHEN expired bytes leave the holder's disk,
  never whether they are served.
- **Hygiene.** Files carry `0600` permissions in a `0700` directory (the
  privacy posture). Delete removes the body and both expiry records; reap
  is best-effort glob-read-remove — removal errors are ignored and the
  next pass retries.

## 8. Relay-fabric verbs (freg/fput/fpop) — slice F1

The fabric rides the §5 frame and socket unchanged (one socket, three verbs;
RELAY_FABRIC.md design law 1). Verbs are JSON objects dispatched per-frame,
served ONLY on nodes started with `-fabric`; others answer
`0x01 + "501 fabric disabled"`. Requests carry `"verb"` — a `§5` `{"cid":…}`
request never does, so the paths are disjoint.

**rpc2/CBOR method family (F4a — same semantics, second encoding):** the
same three verbs are ALSO served as `Peer.FabricReg` / `Peer.FabricPut` /
`Peer.FabricPop` over the §5 frame with the rpc2 encoding — a CBOR header
map `{"M": method, "S": seq, "E": ""}` (always 3 pairs, text keys) followed
by one CBOR payload item; refusals put the legacy `NNN text` string in `E`
with no payload. Dispatch shares the rpc2/JSON disjointness rule (a JSON
frame never decodes as a CBOR header map). Payload keys and semantics are
the legacy verbs' verbatim (`handle`/`token`/`nonce`/`lease`,
`handle`/`pointer_hex`/`deadline`, `handle`/`token`/`max`); map key order in
requests is canonical — the order the golden vectors pin — so the Go and
Rust encoders are byte-identical. All frames are pinned byte-exact in
`interop-vectors.json` `fabric_v1.rpc2_*`; a decoder refusing reserved or
indefinite CBOR heads, non-text map keys, or over-deep nesting is part of
the contract (the hostile-frame posture of the rpc2 sync subset).
**FabricHandle derivation (the decided handle-epoch scheme):**

    FabricHandle = HKDF-SHA256-Expand(HKDF-SHA256-Extract(zero-salt, seed),
                                      "spore/fabric/v1/handle" || epoch_be || sid, 32)

- `seed` — 32 random bytes per contact, riding the contact card.
- `epoch` — u32 big-endian, incremented on prekey-batch rotation.
- `sid` — the ratchet session id. The POINTER's Route stays `RouteKey(sid)`
  (§2 pointer plane untouched); the fabric handle is the lookup key only.
  HKDF is one-way: relays index by handle and never learn sid.
- The zero-salt Extract is load-bearing: Go's `hkdf.New(sha256.New, ikm, nil,
  info)` zero-fills the salt block (RFC 5869 default); a salted Rust Extract
  would derive different handles than every Go peer. Pinned by vector.

**Possession token (no signatures, on purpose):**

    token = hex(HMAC-SHA256(seed, "spore/fabric/v1/reg" || handle || server_nonce))

Computed by the recipient (the only seed holder); the relay stores and
echoes it. A signature scheme would hand relays a cross-relay identity key —
the exact linkage epochs exist to break (RELAY_FABRIC.md hijacker row).

**Envelope v1 (the queued-pointer object, persisted as `<sha256(envelope)>.fenv`):**

    version u8 = 1 | handle 32 | pointer 74 | received_at u64 LE   (116 bytes)

`pointer` is the 74-byte PointerPayload verbatim (`01 00 | Route 32 | CID 32
| BurnDeadline u64 LE`). Envelopes are content-addressed into the hold with
the §7 contract: temp+rename writes, rebuilt into the index on restart,
compost-on-read at fpop.

**Verbs (frame payload = JSON request; response = §5 status-prefixed):**

    freg {handle, token, prev_token?, nonce?, lease}  → 0x00 {"token":…,"expires":…}
        Register/refresh a handle. Lease capped at min(requested, max-lease;
        default 7d). Adversarial gates (F1 review):
        - Chained refresh: overwriting a LIVE registration requires
          prev_token == current token (403 otherwise). The handle is
          public; possession is the only proof — without this, anyone who
          learns the handle could re-register it and drain the victim's
          queue. An EXPIRED registration is fair game again (it is a fresh
          squatter target, by design).
        - Budget: max live registrations (default 50,000). Full budget →
          503; expired slots are swept by the next freg. New registrations
          never evict others' — freg is unauthenticated, so the cap, not
          eviction, is the DoS answer.
        - Token shape: 16..=128 bytes (400 otherwise). The floor closes an
          auth bypass — fpop defaults a missing token to "", so an
          empty/1-char token would make the queue drainable by anyone; the
          ceiling bounds registry memory per entry.
        - Handles are normalized to lowercase hex: case is not identity.
    fput {handle, pointer_hex, deadline} → 0x00 {"queued":true}
        Checks in order: handle registered (404, lease expired 404), per-IP
        rate (429), pointer exactly 74 bytes with v1 header (400), nonzero
        deadline (400), deadline in future (410). Dedupe on (handle,
        pointer): re-publishing refreshes the deadline in place, never
        duplicates; if the refreshed envelope bytes differ (received_at
        moved), the superseded <cid>.fenv composts immediately — otherwise
        (byte-identical) the file IS the queue entry's only copy and is
        left alone. Over the per-handle cap (default 32): evict oldest —
        compost, don't hoard.
    fpop {handle, token, max}            → 0x00 {"pointers":["<74B hex>"…]}
        Drain oldest-first, max capped at 64, deleting on read. Wrong/
        missing token → 403 (constant-time compare); unknown handle → 404;
        shares fput's per-IP rate window (both are unauthenticated parser
        paths; neither is cheaper to flood). Entries whose burn deadline
        passed while queued compost instead of delivering.

**Reap story (no ticker, on purpose in F1):** past-deadline envelopes
compost at the next fpop drain of their handle or at the next open()
rebuild after a restart; fput also composts already-burned entries in the
handle's queue it is touching. Worst case on a crash-hard, never-drained
handle: max_per_handle expired envelopes on disk, all bounded by the cap,
all gone at the next touch of that handle.

**Knobs:** `-fabric`, `--fabric-per-handle N` (queue cap, default 32),
`--fabric-fput-rate N` (per-IP/s, default 60), `--fabric-max-regs N`
(registry budget, default 50,000), `--fabric-max-lease SEC` (lease cap,
default 7d).

Conformance: the `fabric_v1` vector section pins every derivation and the
envelope codec byte-for-byte across Go (internal/fabric) and Rust
(spore-peer fabric mod), including the negative vectors.

**Client face (shipped with the cross-binary interop):**
`spore-peer fabric --addr host:port --sub reg|put|pop --handle <hex>`
exercises the verbs from the CLI: `reg --token t [--nonce n] [--lease s]`,
`put --pointer <74-byte hex>`, `pop --token t [--max n]`. Pop prints drained
pointers to stdout, one 74-byte hex line each — exactly the E2-ingestion
feed — and exits non-zero with the relay's verbatim error string on any
refusal. The seed-derived handle/token plumbing rides the contact card in
F2 proper; the CLI takes explicit values so the cross-binary interop test
(spore `internal/peerstore/fabric_smoke_interop_test.go` + spore-peer
`tests/fabric_smoke.rs`) can pin the wire behavior in both directions:
Go publishes → Rust drains, Rust publishes → Go drains, with takeover and
wrong-token refusals verified verbatim across implementations.

### Client face (F2): `spore fabric subscribe` and `-route-fabric`

The Go client (`internal/fabric`) speaks the same §5 frames and verbs, with
three behaviors an implementer must replicate:

1. **Registration discipline.** The client keeps its `nonce` and re-uses it,
   deriving `token = HMAC(seed, "spore/fabric/v1/reg" || handle || nonce)`;
   `EnsureRegistered` re-fregs only within 5 minutes of lease expiry. A 403
   or 404 on drain triggers exactly ONE re-register + retry — the lease may
   have lapsed server-side between renewals. Chained refresh (prev_token) is
   what makes renewal non-takeover: a live handle re-registers only with the
   token it already holds.
2. **Drain identity.** Subscribe enumerates the durable session table and
   drains `FabricHandle(seed, e, sid)` for e ∈ {n, n−1} (the DECIDED
   dual-publish window; never underflows below epoch 1). Unknown sessions
   are never derived — bootstrap cannot ride the fabric, and a FrameInit
   seen on the fabric path is REFUSED before any prekey state is touched
   (the e2Ingestor fence; also the anti-replay answer for real chain-visible
   init pointers replayed at fabric handles).
3. **Publish roles.** Only the recipient registers. The sender's
   `-route-fabric` derives the recipient's handle from the CONTACT CARD seed
   (no registration, no token) and fput-dual-publishes to n and n−1 after
   the chain post succeeds; ≥1 accepted relay means the fabric route worked,
   zero accepted only warns — the chain pointer is the delivery of record.
   Dedupe on (handle, CID) makes re-publishing a refresh, not a duplicate.

Cross-binary (F2): the real Rust relay + the real `spore fabric subscribe`
binary prove the full loop — recipient registers by drain, sender publishes
(polling past the relay's honest 404 for a not-yet-live handle), the pointer
decrypts through the shared E2 pipeline and lands in maildb
(`cmd/spore/fabric_cross_binary_test.go`); Go drains Rust-published pointers
in `internal/peerstore/fabric_smoke_interop_test.go`.

## 9. Fuzzing, corpus, and coverage — the wire contract under continuous attack

Every parser this spec defines has a libFuzzer target in
`internal/wirefuzz` (harness: `wirefuzz_test.go`, committed seeds:
`testdata/fuzz/seedcorpus/`, regenerable via `SPORE_GEN_SEED_CORPUS=1`):

| target | wire surface |
|---|---|
| `frameparse_fuzzer` | §2 SPR2 frames (Go receive path) |
| `handshakeunmarshal_fuzzer` | X3DH bundle unmarshal (SENDER_AUTH.md) |
| `messageunmarshal_fuzzer` | ratchet message envelope + header |
| `fabricrpc2frame_fuzzer` | §8 rpc2/CBOR fabric verbs (relay-facing) |

**Continuous (retired):** the ClusterFuzzLite pipelines that ran a
code-change fuzz on fuzzed-code PRs and a daily batch + prune on main were
removed together with the repository's GitHub Actions workflows, so the
`cfl-corpus` and `gh-pages` branches they fed are now static history and no
coverage dashboard is published.

**Cross-binary:** spore-peer's Rust decoder (`src/p2p.rs`) is the second
implementation of §5 and is fuzzed the same way on its side — its
dashboard lives at
<https://liqdmetal.github.io/spore-peer/coverage/latest/report/linux/index.html>,
its workflow/contribution notes in spore-peer's `CONTRIBUTING.md` §Fuzzing.
Both decoders are pinned to the shared vectors in `docs/interop-vectors.json`,
so neither can drift from this spec or from each other. The Rust cargo-fuzz
target's corpus is seeded from those same vectors.

**Local (now the only runner):** the pre-push gate (`scripts/gates.sh`)
calls `scripts/fuzz-smoke.sh`, which drives every `wirefuzz` and
`ratchetwire` target for a few seconds each, so a regression in any of them
fails before it can be pushed. For a release pre-flight the same script takes
`--deep` — 60 seconds per target, about nine minutes — which the pre-push gate
deliberately never invokes. The OSS-Fuzz-shaped build recipe this whole
pipeline descends from is preserved in the `projects/spore` integration of the
oss-fuzz fork.

**Corpus:** Go's fuzzer accumulates every input it finds interesting in
`$GOCACHE/fuzz/…`, which compounds on one machine but dies with the build cache
and is invisible to review. `scripts/fuzz-corpus.sh` is the durable store: it
harvests that cache into each package's `testdata/fuzz/<Target>/`, which Go
loads as seed corpus on the next run, so a saved corpus survives a cache wipe
and travels with the clone. Entries are named after the sha256 of their bytes,
so a save is additive, exact, and never rewrites one, and
`TestFuzzCorpusEntriesAreContentAddressed` fails if a checkout ever rewrites
them. `scripts/fuzz-smoke.sh` prints a one-line nudge when a run has found
inputs that are not saved yet.

A store that only grows stops being reviewable — the first harvest here added
515 files, 202 of them from one target — so a save also *minimizes*. The
harvester runs every entry alone against an instrumented test binary, records
the statement blocks that entry exercises (with hit-count buckets, so inputs
that differ only in how often they loop stay distinct), and greedily keeps the
entries covering the union: 89 of 515 here, including 65 of the 202. It drops
the rest from the repo *and* from the cache, so the next save does not copy
them straight back — git history still holds them. Coverage is preserved by
construction, and the pass refuses to delete anything it cannot prove is
redundant.

**Soak:** with the workflows gone nothing fuzzes on its own, so the deep pass
still depended on somebody remembering it. `scripts/fuzz-soak.sh` is what a
scheduler calls instead: one pass fuzzes every target for 60s (the deep
pre-flight), harvests and minimizes whatever it found, then reports what changed
since the previous pass — corpus size, covered blocks, and whether a target
crashed. Its state is machine-local and gitignored (`.fuzz-soak/`): an
append-only ledger, the last report, and the raw fuzz log behind it. A pass that
cannot measure coverage says why: the replay's own output is kept beside the
report, and the ledger's last column tells a reproducer in the corpus apart from
a failing test in the package, instead of recording both as the same `n/a`.
It takes a lock so two passes cannot overlap, keeps any entry that fails on its
own (a reproducer is never redundant), and exits non-zero when a target crashed
so a scheduler's mail carries the failure. `--print-schedule` prints the cron or
Task Scheduler incantation for the host; nothing installs it for you. Like
`--deep`, it is minutes long and no gate runs it.

A scheduler hands a task a minimal environment, not the one you are sitting in,
so the printed launcher sets `PATH` itself — without that, a box whose only Go is
a toolchain inside the module cache dies with `go not found on PATH` about a
second in, and the task reports the failure as a number nobody reads. On Windows
the scheduled command is a launcher file that lives in the state directory, so
wiping `.fuzz-soak/` also removes it and the task stops starting; the launcher
says how to regenerate it, and `--print-schedule` prints it again. A firing's
corpus changes are left in the working tree on purpose: committing what the
fuzzer found is a human's call, not the soak's.

An installed schedule is the one part of the soak nothing else watches — a task
that stops starting stays registered and leaves the ledger's last row standing,
so it reads as a quiet week instead of a break. `--doctor` asks whether it can
still run, in three checks that fail independently: the launcher exists and is
still byte for byte what `--print-schedule` prints (a moved checkout or a moved
toolchain makes it stale), the task is still registered and still points at that
file, and `go` resolves with only the launcher's directory on `PATH`, which is
how the first install here died. It prints a line per check, runs nothing,
installs nothing, and exits non-zero on a problem, so a break is caught the day
it happens rather than after a week of passes that never started.

A pass then used to end by leaving what it found in the working tree, where it
waited for somebody to notice. `--pr` is the other half: the corpus directories,
and nothing else, are committed and pushed, and review gets a pull request for
them, so a finding arrives where review already happens. There is one rolling
branch, `fuzz-soak/corpus`, that each haul adds a commit to, with its pull request
updated in place — review has a single place to look, the branch doubles as the
record of what each firing found, and a night whose corpus moves ahead of an
unmerged haul cannot open a second request beside it. The branch is appended to
and never rewritten, which is both the safe shape and the only one this repository
permits: its `protect-all-branches` ruleset refuses a non-fast-forward push (and a
deletion) on every branch, so the push is a fast-forward, and nothing anybody else
puts on that branch is ever lost. Commits are built in a throwaway git worktree,
so an unrelated edit in the tree the pass ran in is never swept in, the checkout is
never switched, and only the corpus paths are ever staged; the branch is left on
the remote rather than in the checkout, so a nightly cannot bury the branches you
work on. Corpus entries are named after their contents, so the set of names
fingerprints a haul exactly: an unchanged haul is proposed once, and a night that
finds nothing new adds no commit. The pull request goes through the GitHub API with
the credential git already pushes with (set `GITHUB_TOKEN` or `GH_TOKEN` to choose
one explicitly); a non-GitHub remote or an unusable credential still pushes the
branch and reports its compare URL. None of it can fail a pass — the haul is still
in the working tree either way — and `--propose` runs the same step by hand on the
corpus as it stands.

A single pass answers "did anything change since yesterday", not the question
that matters after a few weeks: is the fuzzer still finding anything at all?
A saturated corpus and a quietly broken harness look identical in one pass.
`scripts/fuzz-soak-trends.sh` reads the whole ledger and tells them apart —
`STALLED` when no pass has set a new coverage best in five passes, `FAILING`
when a pass did not end GREEN, `FELL` when measured coverage went backwards,
and `UNMEASURED` when the last pass could not measure coverage at all. Those two
reasons are opposite — a reproducer in the corpus, which is the corpus working as
intended, and a failing test in the package, which is the measurement itself
broken — so the reader quotes whichever one the ledger recorded rather than
assuming, and only the second is a flag. Each soak pass quotes the flags in its
own report; a stall is deliberately not a non-zero exit — the passes themselves
succeeded, and a saturated fuzzer is not a failure.

**Reading the coverage numbers fairly** (measured 2026-09-21): the Go
dashboard's coverage build exercises the inline seeds only — the stock
legacy flow cannot feed the downloaded corpus to the non-std-lib Go
harness. Replaying the full mined corpus through identical `-coverpkg`
builds moves the published figure just 2.3% → 2.7%, and the entire delta
is `fabric/rpc2` (26.8% → 37.5%), the only target whose corpus outgrew
its seeds; the other three prune to seed size because the seeds already
saturate their reachable parse paths. The published figure therefore
understates the corpus effect by ~0.4pt, not by much — and the honest
comparison lens for *parser hardening* is the decode-path subset
(`fabric/rpc2`, `ratchetwire/wire`, `ratchet/x3dh`, `ratchet`), which is
19.4% corpus-driven (16.4% seeds-only). The alternative fix — the v2
go-118-fuzz-build flow, whose testing-package overlay can receive corpus
parameters — was evaluated and declined for now: it buys the ~0.4pt at
the cost of coupling the build to exact Go stdlib layout, the fragility
the v1 import-rewrite flow exists to avoid. Revisit if `fabric/rpc2`
coverage itself becomes a review gate.
