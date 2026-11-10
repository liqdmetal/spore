# Spore releases

Release notes per tag, newest first. Binaries are stamped with
`git describe --tags --always` at build time (`spore version` prints it).

## v0.13.0 — a holder's vault catches up from the inbox (2026-11-10)

10 commits, 21 files, +2238/−17 vs `v0.12.0`. Continuity shipped as a file you
carried to holders by hand, so a copy that fell behind kept releasing on a
deadline the owner had already revoked. This release lets the owner's signed
check-ins travel over the thread they already use, and lets a holder adopt them
on arrival.

### A check-in a stale copy can adopt

`continuity check-in -emit ENVELOPE` writes the owner-signed chain, and
`continuity merge -vault V -checkins ENVELOPE` adopts it. The rules are the ones
the vault itself enforces: same vault and owner key, a strictly forward sequence
whose `prev` digest matches, a recomputed deadline, and every record's signature
re-verified. Merging needs no private key, is atomic, and is idempotent — a
replay reports "already current" and writes nothing, while a foreign vault, a
broken chain or a bad signature is refused with the file left byte-identical.

`continuity status -warn 6h -exit-code` turns staleness into an exit code a
monitor can branch on: 10 due soon, 11 releasable.

### The watcher adopts before it judges

`continuity watch -checkins A[,B]` merges arriving envelopes *before* deciding
whether the deadline passed, so a holder who receives the owner's proof while
preparing a release no longer reports a deadline the owner already revoked.
Adoption is forward-only and same-chain only, and a refused envelope does not
move the watch state — the next genuine check-in still lands.

### The envelope rides the thread

`spore msg checkin -to HOLDER -session SID -checkins ENVELOPE` sends an envelope
the owner already signed over an open ratchet session: no owner key, no new
transport, nothing extra for the carrier to learn. `spore msg recv-e2 …
-continuity-vault V` merges it as it arrives — one line, no file copying, no
manual `merge` — with the same checks as `merge` and an atomic write.

A message that claims the type but fails verification is reported as a refusal
and changes nothing: not adopted, not recorded as a chat body. Without the flag
the receiver still names the vault and sequence and says it did not adopt, so the
artifact is visible before a copy exists. No chain or ratchet wire-format change:
`spore/continuity-checkins/v1` rides inside the existing encrypted frame, and an
older peer shows it as a message instead of adopting it.

### Everything else in the range

- `docs/PAY_IN_XMR.md` — the buyer walkthrough behind the v0.11.0 Monero work:
one thread, one wallet payment, a dual-signed receipt, with the honest line first
(`msg pay` does not move XMR; it refuses rather than print PAID over a transfer
that never happened). It is anchored from ONBOARDING, and the `msg invoice`
example in `MONERO_SETTLEMENT.md` now shows the real `-to -session` shape.
- The provenance check v0.12.0's notes described landed just after that tag and now
runs in the gate suite: `scripts/release-provenance-verify.sh` verifies the assets
of the release the notes call current with `slsa-verifier`. A check that runs and
fails is a failure; an absent tool or an unpublished tag is a named skip.
- `scripts/rehearsal-continuity-checkin.sh` — the live rehearsal, with its own
loopback ports and workspace: a simulated carrier, a real mailbox relay, two CLI
identities and a running inbox.

### What was verified, and what was not

The continuity package tests cover the envelope parser, adoption, replay and
refusal byte-identity; an ingestor test drives a real ratchet session through the
same `ingest()` both transports call; the rehearsal ran green on Windows Git Bash
and on WSL2 Ubuntu, where the holder's copy went `checkins=1 → 2 → 3`, verified
and byte-identical to the owner's, with a foreign vault refused in between and
ordinary chat unaffected.

Honest limits: the rehearsal's carrier is the DERO wallet-RPC simulator, not the
network, so fee and block-timing behaviour is untested; its vault is sealed to a
throwaway recipient key because adoption needs no key, so release decryption is
covered only by the continuity tests. `watch` remains metadata-only, and adoption
proves the owner's chain forwarded — not that the owner is alive right now.

No wire-format change.

## v0.12.0 — a Tor probe you can run yourself, with fallbacks that name themselves (2026-11-09)

9 commits, 5 files, +803/−75 vs `v0.11.1`. The first release since v0.11.0 where the
product itself moved, and it moves in the direction the docs kept promising: a claim
you can test instead of one you have to trust.

### `spore doctor -tor`

`spore doctor -tor` dials every carrier row from ONBOARDING.md through a SOCKS5 proxy
(Tor's SocksPort by default) and prints the payload each one returned: `chainId 0x2105`,
`getHealth ok`, a real Tron block ID, an Esplora tip, Cosmos `node_info`, a TON
masterchain seqno, the relay page, and — with `-store` — the mailbox route.

- **Bodies, not status codes.** A 200 is often a Cloudflare challenge page, and
  TronGrid answers 403 while working fine direct. Each row must show evidence or fail.
- **The dialer is stdlib SOCKS5 CONNECT** — no new dependency — and there is no direct
  fallback, because a probe that silently bypassed the proxy would report a green table
  for traffic that never touched it.
- **The circuit names itself.** An exit check reports the IP, and a SOCKS proxy that is
  not Tor is labelled as such rather than presented as a Tor result.

### Fallbacks that name themselves

A carrier now lists its documented endpoint first and the public mirror behind it. The
first endpoint that returns real evidence passes the row, and the note names it *plus*
why the other failed: `fallback solana-rpc.publicnode.com answered: getHealth ok;
api.mainnet-beta.solana.com: Your IP or provider is blocked from this endpoint`.

Both alternatives were rejected on purpose. Hardcoding one endpoint made a working
carrier a permanent red row (the official Solana RPC refuses Tor exits). A quiet
fallback would have hidden that the documented endpoint stopped working. Measured on
two circuits: TronGrid 403'd every user-agent from one and answered normally from
another, which is why the row is a measurement and the table says so.

### What the live runs changed in the docs

Solana and Tron rows now name the `publicnode` endpoints and explain why. "What was
measured" records the circuits and the per-exit caveat. And one failure was the probe's
own: the Cosmos REST gateway returns `default_node_info`, which the check did not accept,
so a healthy carrier failed — fixed with the real body shape pinned in a test.

### A release that cannot half-land

v0.11.1 shipped its notes while three install pins still said v0.11.0. A new gate now
compares the newest RELEASES.md heading with the README release row, both README pins,
the slsa `--source-tag`, and the ONBOARDING `vTAG`, failing on any disagreement or a pin
that vanished. It runs pre-push and inside release-readiness.

No wire-format change.

### Assets verified after publication

All six binaries were downloaded from this release on 2026-11-09 and checked four ways:
against `SHA256SUMS`, against each asset's own `.sha256`, against the digests in
`multiple.intoto.jsonl` from the tag run, and against that attestation's signature.

| Asset | SHA-256 |
|---|---|
| spore-darwin-amd64 | `e89e4fbfec9d502e4b18dd78514cc49ae2cf0e908b74a237298d52bb688e1f3d` |
| spore-darwin-arm64 | `adb633d33eac1ec5df079963c68e8440db4c1f5371950a3125d2168986ab3661` |
| spore-linux-amd64 | `69cb5af2902018824c3563c308add9ab1675ad83072037553d12f5c61c8cf8e5` |
| spore-linux-arm64 | `616576ee8805adee20e49c2160f653228bceb6a043186490d15cbe22f3fcd2a1` |
| spore-windows-amd64.exe | `f770a1f4b6f86dfeae1205f324e0d627d379e79909615c64936a6f24589c72af` |
| spore-windows-arm64.exe | `6b666fcd5122c6ace9618b58a5e18da0720b5d7cc8ae3b9739629a88300fe739` |

Every `.sha256` file agreed with its asset, and every asset name appeared as a provenance
subject with the same digest. The signature itself was then checked, not only the payload
it covers: `slsa-verifier` v2.7.1 verified all six assets against `multiple.intoto.jsonl`
with `--source-uri github.com/liqdmetal/spore --source-tag v0.12.0`, and `--all` reported
each of them `ok`. The earlier digest comparison had decoded the DSSE payload, which shows
the payload agrees with `SHA256SUMS` but not that this repository's release workflow signed
it; the verifier run is what establishes that, so the gate suite now carries it
(`scripts/release-provenance-verify.sh`, run against the release these notes call current).
Where `slsa-verifier` is absent, the tag is unpublished, or GitHub is unreachable, that
gate prints its reason and a skip — never a pass it did not earn.



## v0.11.1 — Tails/Whonix onboarding, and Tor reachability measured (2026-11-09)

6 commits, 7 files, +237/−81 vs `v0.11.0`. No product code changed: the binaries
are built from the same source as v0.11.0, so behaviour is identical. What moved
is who the client is for, and what the docs are allowed to claim.

### An amnesic-client path

[ONBOARDING.md](ONBOARDING.md) now has a Tails/Whonix section: no-root install,
the `SPORE_HOME` choice between amnesia and Persistent Storage, the hosted-mailbox
recipe, an onion-service recipe for `spore serve`, and a carrier-by-carrier Tor
table. Every carrier has a Tor path except the UDP sidecars, which have none by
construction.

### Reachability that was measured, not guessed

The table is filled from probes through a real Tor circuit (2026-11-09, exit
`109.70.100.9`), sent with the client user-agent, checking response **bodies**:
Base (`0x2105`), Solana `getHealth`, TronGrid and `tron-rpc.publicnode.com`,
Blockstream Esplora, toncenter, Cosmos publicnode and the damus relay all
answered. Three traps are recorded because they mislead: `mainnet.base.org`
returns 200 with a Cloudflare challenge page, TronGrid 403s a bare `curl`
user-agent while accepting the Go one, and `mempool.space` fails direct as well,
so that one is not a Tor finding.

### The rehearsal that was forcing the docs to lie

The v0.9.0 release-day rehearsal applied its frozen patches to a moving `HEAD`, so
every later docs commit read as a broken freeze and the cure each time was to
re-derive the patch — the opposite of frozen. Worse, README and ONBOARDING could
only keep matching while they called the Base EVM deployment "pending". Both
rehearsal scripts now extract their tree from the patch base (`cb1e74c`,
overridable with `SPORE_RELEASE_REHEARSAL_BASE`) and take the current tooling, and
the original frozen patch is restored byte for byte.

The EVM row stays at "deployment pending" on purpose: `KnownMailboxDeployments`
ships empty until a Base deployment publishes its §3 receipt, and
`TestDocClaimsMatchRegistryState` refuses a doc that flips first. No wire-format
change.

## v0.11.0 — Monero settles end to end, and a job becomes a signed receipt (2026-11-09)

49 commits, 78 files, +13,951/−233 vs `v0.10.2`. This is the first release since
v0.10.0 where the product itself moved, and both features are optional by
design: a provider chooses whether a receipt exists at all, and Monero billing
is still behind `-xmr-unverified`.

### Monero settles through `bill watch`

- **XMR is a money asset** — `2.5xmr` is billable beside `25dero`, with
  piconero exactness: a sub-piconero amount is refused, not rounded.
- **Per-order subaddresses** — `spore bill address` issues one fresh
  subaddress per order, labels it, and records it in the ledger `bill watch`
  reads back. Attribution no longer depends on a hand-written map.
- **`bill watch -xmr-unverified`** — a confirmation floor, a hold on
  unattributed payments, and the five guards in
  [MONERO_SETTLEMENT.md](MONERO_SETTLEMENT.md) §5, with a mock-RPC test in the
  shape `internal/xmr` uses.
- **Digest, not Basic** — the wallet RPC refuses Basic outright. The poller
  authenticates the way `internal/xmr` does; the live run found this, not a
  mock.
- **`bill reconcile`, and drift at startup** — the issued-address ledger is
  diffed against the wallet's `get_address`, each proposal names the command
  that adopts an address only the wallet knows, and `bill watch` reports drift
  when it starts, so an unrecorded address is visible before a payment lands
  on it.
- **The live round trip is done** — one real payment carried through
  provisioning into a receipt on the Hetzner wallet (MONERO_SETTLEMENT §8
  step 5), recorded in [LIVE_NODES.md](LIVE_NODES.md).

DERO bill watch no longer loses a payment held for a missing batch: its
watermark pins the way the Monero branch does, instead of advancing past a
payment it could not attribute.

### Job receipts: a signed record of work

[JOB_RECEIPT_V1.md](JOB_RECEIPT_V1.md) fixes the canonical record, and
`spore sign receipt create|sign|verify` emits and verifies it with the role's
fixed statement enforced — a signature asserting something else is refused.
Two optional records ship beside it:

- **spend** — a provider-blind accounting record with a salted commitment, so
  a client can account for money spent without the provider's participation.
- **export / tally** — the §9 rows with per-row evidence and a fixed sort, and
  the §8 aggregation rules over a directory of job receipts; `tally -proofs`
  verifies the optional `tx_proof` block that `bill watch` now attaches at
  provisioning time.

A published fixture vector and a test reproduce the §6 sign-and-verify
sequence byte for byte. The gap is named in the doc rather than implied: there
is no chain client, so `tally` can check that a receipt cites a txid you
confirmed, never that the transaction exists.

### Tron as a cheap E2 pointer carrier

`internal/tron` carries an E2 pointer in a TRON memo on the cheap tier, and
[CLOSE-FREE-ROUTING.md](CLOSE-FREE-ROUTING.md) is the carrier assessment that
priced it against the alternatives.

### The store stops losing bodies, and the tests stop lying

- `spore store sweep` lists and reclaims `.body` files with no deadline
  record, behind an age guard — the one state reap can never repair, because
  reap discovers candidates by globbing `*.exp`. `WIRE_SPEC.md` now states the
  store's concurrency contract: `Put`, `Reap` and `Delete` are serialized
  against each other, which is what closed the window that produced those
  orphans.
- The reap ticker no longer drops expired bodies that arrive without an access
  marker, with a regression test.
- Golden-file generators write atomically and are opt-in
  (`SPORE_REGEN_VECTORS=1`), so `go test ./...` can no longer rewrite
  `interop-vectors.json` under a parallel run.
- The sub-second and approval-timing tests anchor their windows instead of
  racing their own setup, which is what made the full suite fail at random.

No wire-format change: the `WIRE_SPEC.md` edits are the store contract above.

### Arming a clone is one command, and a push cannot skip it

- `scripts/setup.sh` installs the hooks and the credential guard, verifies
  both, and exits non-zero naming the exact command to run; `--check` audits
  without changing anything.
- The pre-push shim fails closed: an empty diff range refuses instead of
  skipping, and a same-tree force push (a reword) is recognised as nothing to
  gate rather than reported as a bypass.
- A duplicated GitHub account in the credential store is refused fast at push
  time and reported at arm time — the ambiguity used to hang a push on a
  picker no terminal can answer.
- `--check` warns when `go`/`gofmt` are not on PATH, because the gates fail
  closed and a push otherwise dies at `go build ./...` in 30 ms.

### Gates that fail for real reasons

- Gate runs are serialized: a busy machine reports itself instead of reading
  as a slow gate, and the timings log keeps the history honest.
- `-race` finds a C toolchain itself on Windows instead of dying on a bare
  PATH, and the sepolia self-check names what failed instead of exiting in one
  silent second.
- The rehearsal cleanup trap can no longer fail an otherwise green run.
- `scripts/defender-exclusions.ps1` excludes the Go build paths from Defender
  real-time scanning: measured 58.5 → 21.4 Defender CPU-seconds per two `-race`
  runs, and 55.5 s → 41.5 s for the gate under contention.

### Artifacts

All six targets (linux/darwin/windows × amd64/arm64) build on GitHub Actions
from the tag, each with a `.sha256` sibling plus `SHA256SUMS`, and
`multiple.intoto.jsonl` from the SLSA generic generator pinned at `v2.1.0`:

```bash
slsa-verifier verify-artifact spore-linux-amd64 \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/liqdmetal/spore --source-tag v0.11.0
```

Attestation attaches on tag-push runs; a manual workflow-dispatch rebuild of an
existing tag skips it. As in v0.10.x this ships `cmd/spore` only — the in-repo
Go `cmd/spore-peer` is built from source when needed.

`spore version` reports `v0.11.0`.

## v0.10.2 — release notes come from the tag annotation (2026-10-25)

No messenger code changed since v0.10.1. One pipeline fix, proven end to end.

- `publish` no longer creates releases with `gh release create --notes-from-tag`.
  That flag reads the tag from the local checkout and silently falls back to the
  commit subject when the annotation is not there — which is why the v0.10.1
  release page showed a one-line body. The step now reads the tag object through
  the API (falling back to the commit message for a lightweight tag) and creates
  the release with `--notes-file`.
- The v0.10.1 release body was corrected in place to its tag annotation.

All six targets build on GitHub Actions from the tag, each with a `.sha256`
sibling plus `SHA256SUMS`, and `multiple.intoto.jsonl` from the SLSA generic
generator pinned at `v2.1.0`:

```bash
slsa-verifier verify-artifact spore-linux-amd64 \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/liqdmetal/spore --source-tag v0.10.2
```

Attestation attaches on tag-push runs; a manual workflow-dispatch rebuild of an existing tag skips it — check the release for `multiple.intoto.jsonl` before verifying.

`spore version` reports `v0.10.2`. Behaviour is identical to v0.10.1.

## v0.10.1 — first pipeline-built release, with SLSA provenance (2026-10-25)

No messenger code changed since v0.10.0. This tag ships the same source built
end to end by `.github/workflows/release.yml`, and it is the first release that
exists because of that pipeline rather than a local cross-compile.

- All six targets (linux/darwin/windows × amd64/arm64) build on GitHub Actions
  from the tag, each with a `.sha256` sibling plus `SHA256SUMS`.
- `multiple.intoto.jsonl` comes from the SLSA generic generator pinned at
  `v2.1.0` and covers all six digests:

  ```bash
  slsa-verifier verify-artifact spore-linux-amd64 \
    --provenance-path multiple.intoto.jsonl \
    --source-uri github.com/liqdmetal/spore --source-tag v0.10.1
  ```

- A dispatch rebuild or a re-pushed tag replaces the binaries and drops the
  previous attestation before uploading, so stale provenance can never sit
  next to new digests.

`spore version` reports `v0.10.1`. Behaviour is otherwise identical to
v0.10.0, which stays published without provenance.

## v0.10.0 — iroh E2 body store, peer transport, and E2-over-peer PUT (2026-10-25)

Bodies can live somewhere other than a relay: content-addressed storage with
portable BLAKE3 locators, fetched over disk, a peer, or an iroh sidecar.

- **Iroh E2 store** — `iroh://`, `disk://` and `peer://` schemes, a Rust
  `spore-iroh` sidecar, and **E2 Pointer V2** on the ratchet wire protocol
  carrying the locator. Peer discovery, the peerstore server and device
  approval moved with it.
- **Wired into production** — the iroh config moved out of the dead `e2Store`
  path into `newE2BodyStore`, the constructor the send path actually calls, so
  the schemes work outside tests.
- **iroh-blobs 0.103.1** — 0.100 through 0.103.0 are yanked from crates.io.
- **spore-peer PUT** — `{"put": {"cid": "<64 hex>", "body": "<hex body>"}}`
  stores a ciphertext on the peer with a 24-hour expiry and confirms receipt,
  so an encrypted body can travel to the peer directly, bypassing the relay.
  The transport is unauthenticated: trusted LAN or VPN only.

### Artifacts

Six statically linked Go binaries (`CGO_ENABLED=0`), one per target —
linux/darwin/windows × amd64/arm64 — each with a `.sha256` sibling plus
`SHA256SUMS`, built and attached by `.github/workflows/release.yml` when the
tag is pushed. The shipped linux/amd64 artifact was downloaded from the
release and run; the full `spore demo` lifecycle was exercised on Windows
amd64 and Linux amd64 on the same source.

Two gaps, named rather than implied: this release has **no SLSA provenance**
(v0.7.0–v0.8.6 shipped `multiple.intoto.jsonl`; this build is attested only by
its workflow run and checksums), and it carries **no `spore-peer` binaries** —
neither the in-repo Go `cmd/spore-peer` nor the historical Rust peer/sidecar are
built by that workflow (build `cmd/spore-peer` from source when needed).

It also settles the numbering: v0.10.0 supersedes `v0.9.0` (tagged, never
released) and `v0.5.1` (a stray tag with no assets), and is a minor bump
because the store and peer transport are features.

## v0.9.0 — fabric refusals counted, prekey health in status and doctor, and the mailbox ships (2026-10-16)

Operator-visible health for the encrypted E2 path, plus the work that
landed since v0.8.6.

- Fabric refusals are counted and persisted per state directory, and
  `status` reports the count. A refused fabric is now visible instead of
  silently dropped.
- `status` and `doctor` warn on prekey pool health, and `doctor -json`
  emits the `spore/doctor/v1` read-only report (no network, no store
  writes, no key material). `docs/status-v1.schema.json` pins the status
  shape, checked by `scripts/verify-status-schema.py`.
- The prekey pool gains validation, persistence, throttling, and
  count-failure handling, each covered by tests.
- `ONBOARDING.md` gains a section for the new health checks.
- Also in this release: the encrypted incident pager, private DAO review
  and work-order handoff protocols, persisted derosim wallet state across
  restarts, mailbox deploy units with the wallet RPC login kept out of
  argv, and a scheduled fuzz soak that keeps and reports what it finds.

**Superseded by v0.10.0.** This tag was never published with binaries, and the
work since has shipped as v0.10.0, the current production release.

## v0.8.6 — the station pages you: watch mode, Prometheus, and a daily drill (2026-10-05)

Ten commits that turn the always-on approver station into a fully
observable, gated, alerting service — plus one fix the new CI exercise
caught before it could bite.

- `station-health.sh` gains `-w`/`--watch`: a live tripwire that follows
  the heartbeat log and stops non-zero on the FIRST violation or malformed
  line. It follows with a pure-bash chunked reader — GNU tail block-buffers
  its stdout when piping, which stalled small-append delivery indefinitely
  (a violating heartbeat could sit untripped; found by the new sentinel and
  proven with a >4KB flush experiment) — and it follows copytruncate and
  rename rotation, exits 2 (never a silent pass) when the file vanishes or
  cannot be reopened, and exits 130 on Ctrl-C.
- `-prometheus`: `spore msg approval-metrics` renders the summary as the
  Prometheus text exposition format (`spore_approval_*` gauges: volumes,
  statuses, skip reasons, locks live/orphaned/oldest age, oldest-pending
  age, outbox latencies) for a scraper or the node_exporter textfile
  collector.
- Multi-queue scraping: repeated `-dir` puts several pipelines into ONE
  exposition, every series labeled `queue="..."`; `-dir path=name` gives a
  station a friendly label instead of a raw path. Zero or one plain `-dir`
  keeps the v0.8.5 output byte-identical (proven against a pre-refactor
  binary capture). Multi-queue refuses `-out-dir` and `-state-dir` — outbox
  and ledger latencies belong to one pipeline.
- `station-health-alert.sh`: an example alerting wrapper — runs the gate in
  `-w` mode and POSTs one JSON object (source, at, host, file, exit_code,
  text, detail) to a webhook on the first trip (posts as-is to Slack
  incoming webhooks), then resumes watching after a cooldown. `--dry-run`
  tests the whole path without a receiver; `--once` exits with the gate's
  code for cron/systemd supervision and 4 when delivery itself fails; the
  webhook can come from `STATION_HEALTH_WEBHOOK` so the secret stays out of
  argv.
- `approval-drill-watch.yml`: a daily sentinel in the pin-freshness pattern
  — the real-process double-sign drill, the watch self-metrics live smoke,
  and a live fire of the health gate in batch AND `-w` mode (healthy holds,
  an orphan trips, a vanish exits 2). Opens and updates one tracking issue
  on red, auto-closes on green. It earned its keep on day one: its watch
  exercise exposed the tail-buffering stall above.
- The three machine-readable renderings of `approval-metrics` (`-json`,
  `-envelope`, `-prometheus`) are mutually exclusive by validation, and the
  latency-family rendering is pinned byte-exact by test.

Runbook §3.2/§3.3 document the gate and the wrapper; §5 documents the
shared-textfile patterns.

## v0.8.5 — the heartbeat names its station, and the log gets a health gate (2026-10-05)

Everything an operator needs to scrape and gate an always-on approver
station from one JSONL file, on top of v0.8.4.

- `-metrics-json` heartbeat mode: `spore msg approve -watch -metrics-every 1m
  -metrics-json` emits each self-metrics report as **one compact JSON line**
  on stdout — the exact `approval-metrics -json` object per line, scrapeable
  by log dashboards.
- Every heartbeat carries `station`: the emitting station's hostname (the
  same tag its signing locks name as holder) and PID, so several stations
  teeing into one aggregated JSONL stream stay distinguishable. Pre-v0.8.5
  lines have no `station` object; parsers must tolerate its absence.
- `spore msg approval-metrics -envelope` emits the exact same compact
  heartbeat line, one shot with no `-watch`, so a cron scrape appends to the
  file the live station already writes. `-json` and `-envelope` are
  alternative output formats; passing both is refused with exit 2.
- `scripts/station-health.sh` turns the JSONL log into a pass/fail gate:
  non-zero exit on orphaned signing locks, lock ages at/over the 60 s
  stale-break line, pending requests at/over the 15-minute approval expiry,
  malformed heartbeat lines, or a log with no heartbeats at all. Wire it
  after the `tee` (runbook §3.2).
- The audited spore-peer contract pin advanced to `2918e2b62088` (spore-peer
  main; nine fuzzing-infrastructure commits, no wire-format change) after
  the contract suite ran green against it — release and interop artifacts
  build at that pin.

## v0.8.4 — idempotent batch approve (2026-10-05)

One fix that un-reddens the release pipeline: batch approve is idempotent
over its own output. A rerun that finds its own valid approval at the
output path (a race loser arriving just after the winner released the
lock, or a plain rerun) skips as `already signed` instead of failing on
exclusive-create; a foreign or corrupt file at that path keeps the loud
failure, so a rerun never overwrites one. This makes the Linux CI race
suite deterministic — and main green again.

## v0.8.3 — the station watches itself (2026-10-05)

Two items on top of v0.8.2: the queue watcher degrades gracefully through
filesystem races instead of crying failure, and an always-on station reports
its own pipeline health on a schedule.

- Watcher filesystem races are handled quietly: a request deleted between
  the directory scan and its read is skipped (`request vanished mid-scan`)
  instead of failed, and the metrics lock view flags orphaned locks — a lock
  whose guarded request file is gone — as `(request gone)` residue.
- A `-watch` approver station can self-report: `-metrics-every 10m` prints
  the full `approval-metrics` summary on stdout once per period (`0`
  disables), so an always-on station shows its own queue, ledger, locks, and
  outbox latencies without a second terminal.

## v0.8.2 — operator visibility for the approval pipeline (2026-10-04)

Four hardening-and-visibility items on top of v0.8.1: the approval pipeline
now shows its live contention, the replay guard is proven on every chain,
the TTL has teeth at its worst moment, and a closing window announces
itself.

- `approval-metrics` gains a live lock view: the `locks` section reports how
  many signing locks are live in the queue right now, with each holder
  (`host/pid`) and age — operator-visible contention and crash recovery, in
  both text and `-json`.
- The requester-side replay guard is now proven end-to-end in the two-device
  loops for every chain: DERO reruns the send with the same approval (refused,
  no second transfer), Solana retries after an ambiguous broadcast (refused,
  exactly one `sendTransaction` ever reached the node).
- The 15-minute TTL is proven at its worst moment: an approval that expires
  between signing and the send rerun is refused before the nonce burn and
  before any broadcast.
- The send rerun warns on stderr when an approval has under two minutes of
  TTL headroom left — it still broadcasts, but a stalled handoff announces
  itself before it becomes an expiry.

## v0.8.1 — second-device capability approvals, concurrent-station hardening (2026-10-04)

**One line:** a `spore` send no longer moves value on its own — the exact
chain, recipient, amount, and pointer must be countersigned by a second
device holding a different key, and the nonce can broadcast at most once.

29 commits, 31 files, +7,800/−159 vs `v0.8.0`.

### The model

`spore msg send-e2 -require-approval APPROVER_PUBLIC_KEY_HEX` does not
broadcast. It writes a signed *capability request* — an envelope pinning the
exact chain, sender, recipient, amount, E2 pointer, session, a 15-minute TTL,
and a random 16-byte nonce — and exits with instructions. A second device
reviews and signs the request; the requester reruns the *same* send with
`-approval-file SIGNED.json`. Before broadcasting, spore burns the nonce into
an exclusive-create replay ledger, so a retry after an ambiguous RPC result
can never double-send. Escrow/HTLC is refused on the capability path by
design.

### Multi-chain gates

| action | chain | payable |
|---|---|---|
| `dero.transfer-with-pointer` | dero | yes, `amount_atomic > 0` |
| `evm.deliver-with-pointer` | evm | no, `amount_atomic` must be 0 |
| `solana.deliver-with-pointer` | solana | no, `amount_atomic` must be 0 |

The EVM gate targets the MyceliumMailbox delivery path and refuses
`-amount` outright — never silently underpay. The Solana gate re-verifies the
inbox PDA pre-broadcast.

### Approver CLI toolbox

```bash
spore msg inspect-approval -file ENVELOPE.json [-state-dir D] [-json] [-require-approver HEX]
spore msg list-approvals -dir QUEUE -state-dir D        # one-line queue table
spore msg approve -request FILE -identity KEY -out FILE [-confirm]
spore msg approve (-request A,B | -request-dir DIR) -identity KEY -out-dir DIR [-confirm] [-json] [-state-dir D]
spore msg approve -request-dir QUEUE -identity KEY -out-dir DIR -watch [-every 30s]
spore msg approval-metrics [-dir QUEUE] [-out-dir OUTBOX] [-state-dir D] [-json]
```

- **Batch signing** aggregates per-request outcomes (`signed` / `skipped` /
  `failed` with a reason) instead of aborting at the first bad file; skips
  cover already-signed, invalid, expired, replay-spent, and other-approver
  envelopes. Without `-confirm` everything is a dry run.
- **`-watch`** turns the batch into an always-on approver station: it rescans
  the queue until SIGINT/SIGTERM and stays quiet about requests it has
  already reported.
- **`list-approvals`** prints the queue table and, on request, ready-to-run
  requester rerun commands — the handoff from approval to broadcast is a
  copy-paste.
- **`approval-metrics`** summarizes queue history, the signed-approval
  outbox, and the spent ledger — pending age, signed counts, approval→post
  latency — as text or JSON.

### Concurrent-station hardening

Multiple approver stations on the same queue are safe by construction:

- Every signing path takes a per-request sibling lock
  (`<request>.lock`, `O_CREATE|O_EXCL`, owner-stamped `<hostname> <pid>`).
- A live foreign holder is a quiet skip; the next scan re-classifies the
  request as already signed.
- Locks self-heal: a holder that crashes mid-sign is broken immediately when
  the lock provably names a dead process on the same host, otherwise once it
  ages past the 60 s TTL. Remote or unknown owners stay TTL-only — a PID from
  another host means nothing locally.
- Outputs are exclusive-create, so a rerun never overwrites an existing
  approval.

Proven by an 8-station in-process race test and a live two-process watch
station drill: two real OS processes race the real watch cycle over one
shared queue and outbox, and each request is signed exactly once.

### EVM deployment-day tooling

- `spore contract estimate` — the funding math as one command.
- `scripts/sepolia_rehearsal.sh` — hermetic Phase-A rehearsal: stub chain,
  no faucet, no live dependencies.
- Pre-staged shipped default-mailbox defaults.

### For operators

`docs/APPROVAL_RUNBOOK.md` is the end-to-end workflow: the model (§0),
requester and approver flows, watch stations, batch rules, metrics (§5), and
operating notes.

### Verification

189 tests in `cmd/spore`, including two-device end-to-end approval loops over
the real simulated DERO, EVM, and Solana surfaces, deterministic metrics
tests, the concurrency race suite, the two-process station drill, and
settlement outbox crash tests. All gates green at the tag.

### Artifacts

Release binaries (built from `71fcdbb`, stamped `v0.8.1`): linux amd64/arm64,
darwin amd64/arm64, windows amd64 — checksums in the release directory
(`SHA256SUMS`). Build from source:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o spore ./cmd/spore/
```
