# Spore releases

Release notes per tag, newest first. Binaries are stamped with
`git describe --tags --always` at build time (`spore version` prints it).

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
