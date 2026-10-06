# Capability approvals — operator runbook (second-device signing of exact sends)

*How a second device reviews and signs exactly one pointer/value action before
the sending device may broadcast it. One request = one envelope = one nonce =
at most one broadcast. Everything below uses the shipped `spore` binary.*

## 0. The model in one paragraph

A `spore msg send-e2` with `-require-approval` does **not** broadcast on its
own. It writes a *capability request* — a JSON envelope that pins the exact
chain, sender, recipient, amount, E2 pointer, session, creation/expiry
timestamps (TTL: 15 minutes), and a random 16-byte nonce — signs it with the
requester key, and exits with instructions. The **approver** (a second device
holding a different Ed25519 key) reviews the envelope and signs it only after
an explicit `-confirm`. The requester then reruns the *same* send with
`-approval-file SIGNED.json`; before broadcasting, spore burns the nonce into
`<state-dir>/approval-spent/<nonce>.spent` (exclusive-create, at-most-once), so
a retry after an ambiguous RPC result can never double-send. Solana envelopes
additionally get their inbox PDA re-verified pre-broadcast.

Supported actions today:

| action | chain | payable |
|---|---|---|
| `dero.transfer-with-pointer` | dero | yes, `amount_atomic > 0` |
| `evm.deliver-with-pointer` | evm | no, `amount_atomic` must be 0 |
| `solana.deliver-with-pointer` | solana | no, `amount_atomic` must be 0 |

Escrow/HTLC is refused on the capability path by design.

## 1. Requester side: create the request

```bash
# first run does NOT send; it writes the pending request and tells you what to do
spore msg send-e2 -to RECIPIENT -identity ~/keys/sender.key \
  -bundle ./approver-bundle.json -pinned-sig APPROVER_SIGNING_KEY_HEX \
  -require-approval APPROVER_PUBLIC_KEY_HEX \
  -store https://... -state-dir ~/state -state-key ~/state.key \
  -chain dero -amount 25dero -msg-file body.txt
# => second-device approval required; review ~/state/approval-<nonce>.json on the
#    approver device ... rerun this exact DERO send with -approval-file SIGNED.json
```

The request file lands in the requester's `-state-dir` as
`approval-<nonce>.json`. Get it to the approver device out-of-band (sync
folder, USB, whatever you trust); the envelope is public data — its security is
the signature chain, not secrecy.

The send rerun warns on stderr when the approval is inside its final two
minutes of TTL: it is still valid and still broadcasts, but a stalled handoff
will hit expiry instead of the chain — broadcast now, or re-request with a
fresh nonce.

## 2. Approver side: review the queue

```bash
# one-line table of everything in a queue directory
spore msg list-approvals -dir ~/approval-queue -state-dir ~/state
# STATUS     CHAIN    AMOUNT       SENDER        RECIPIENT      EXPIRES IN  FILE
# PENDING    dero     0.05 dero    dero1qy...    dero1qy...     14m35s      a_dero_5000.json
# SPENT      dero     0.07 dero    dero1qy...    dero1qy...     14m35s      b_dero_7000.json
# SIGNED     dero     0.09 dero    dero1qy...    dero1qy...     14m35s      c_dero_9000.signed.json

# full detail on one envelope: signatures, expiry, replay-ledger state
spore msg inspect-approval -file ~/approval-queue/a_dero_5000.json -state-dir ~/state
# machine-readable: add -json; pin the signer: -require-approver APPROVER_KEY_HEX
```

Statuses: `PENDING` (unsigned, valid, postable once signed), `SIGNED`
(signature verifies), `SPENT` (nonce burned — it already posted or was
consumed), `EXPIRED` (past `expires_at_unix`), `INVALID` (fails envelope
validation). Non-capability JSON files in the directory are ignored.

## 3. Approver side: sign (single or batch)

```bash
# single request: review the printed action, then confirm
spore msg approve -request ~/approval-queue/a_dero_5000.json \
  -identity ~/keys/approver.key -out ~/approval-queue/a_dero_5000.signed.json -confirm

# batch: every pending request in a queue directory, one <name>.signed.json each
spore msg approve -request-dir ~/approval-queue \
  -identity ~/keys/approver.key -out-dir ~/outbox -state-dir ~/state -confirm

# batch over an explicit list (comma-separated); same rules apply
spore msg approve -request a.json,b.json -identity ~/keys/approver.key -out-dir ~/outbox -confirm
```

Batch rules:

- Without `-confirm` the run is a **dry run**: actions are printed to stderr,
  nothing is signed, every candidate is reported as skipped with
  `confirmation required; rerun with -confirm to sign`.
- Per-request outcomes are aggregated instead of aborting at the first bad
  file. Each result is `signed`, `skipped`, or `failed` with a reason:
  - `already signed` — the envelope carries a signature
  - `nonce already consumed; replay refused` — the nonce is burned in the
    `-state-dir` ledger (it already posted; signing again would be dead weight)
  - `approval envelope: expired` (or any other validation error)
  - `named for a different approver key` — a mixed-device queue; this device
    only takes requests addressed to its key
  - `approval file: create ...: file exists` — the output path holds a file
    that is NOT this request's approval (a name collision or corrupt file);
    outputs are exclusive-create, so a rerun never overwrites one. Its own
    valid approval skips as `already signed` instead — the batch is
    idempotent over its own output.
  - `signing lock held by another approver (pid N)` — a second station on the
    same queue reached the request first; it is a skip, and the next scan
    re-classifies the request as `already signed`
  - `request vanished mid-scan; re-check on the next scan` — the file was
    deleted between the directory scan and its read (cleanup racing a watch
    station); filesystem housekeeping, not an approval problem
- Signing takes a per-request sibling lock (`<request>.lock`) — batch and
  one-shot `approve -request` alike — so two approver stations racing the same
  queue can never double-sign one nonce, no matter how their `-out-dir`s differ.
- Locks self-heal: a station that crashes mid-sign leaves its lock, and the
  next scanner breaks it and signs the request itself — immediately when the
  lock provably names a dead process on the same host, otherwise once it is
  older than 60 s (`approvalLockTTL`). No manual cleanup unless you cannot
  wait a minute.
- Exit code is 0 when nothing *failed*; skips are normal queue hygiene.
- `-json` emits a self-contained report for driving the next step:

```json
{
  "signed": 1, "skipped": 1, "failed": 0,
  "results": [
    { "request": "d_dero_3000.json", "output": "d_dero_3000.signed.json",
      "nonce": "1baa167c280b24f9c4976e01b88c9d09",
      "chain": "dero", "action": "dero.transfer-with-pointer",
      "recipient": "dero1qy...", "amount_atomic": 3000,
      "status": "signed" }
  ]
}
```

The text report prints a `next:` hint per signed envelope naming the recipient
and the `-approval-file` to rerun the send with.

### 3.1 Always-on approver station: `-watch`

For an approver device on duty, run batch approve as a long-lived station that
picks up new requests as they land in the queue:

```bash
spore msg approve -request-dir ~/approval-queue \
  -identity ~/keys/approver.key -out-dir ~/outbox -state-dir ~/state \
  -watch -every 30s
```

- Requires `-confirm` (the station signs automatically), `-request-dir`, and a
  positive `-every` (default 30s); `-json` is refused — the signed files in
  `-out-dir` are the artifacts. Stops cleanly on SIGINT/SIGTERM.
- The same batch rules apply, and steady-state cycles stay quiet: requests
  whose signed output already exists are left out of the rescan, and unchanged
  statuses are not re-printed. Only new signatures, new skips, and failures
  appear, each with the usual `next:` handoff. A queue directory that
  disappears briefly is logged and retried on the next tick.
- A request consumed by the requester's send still resurfaces as
  `nonce already consumed; replay refused` unless you pass `-state-dir` — pass
  it; the ledger is what keeps a re-scanned queue from re-signing.
- `-metrics-every 10m` makes the station print its own `approval-metrics`
  summary on stdout once per period (`0` disables) — queue volumes, ledger,
  locks, and outbox latencies from the station's own artifacts, so an
  always-on station shows its pipeline health without a second terminal.
  The first report lands after one full period.
- Add `-metrics-json` to emit each heartbeat as **one compact JSON line** on
  stdout instead of the human summary, for log dashboards:

```bash
spore msg approve -request-dir ~/approval-queue \
  -identity ~/keys/approver.key -out-dir ~/outbox -state-dir ~/state \
  -watch -every 30s -metrics-every 1m -metrics-json | tee -a station.jsonl
```

  Each line parses standalone:

```json
{"at":"2026-10-05T12:00:00Z","station":{"host":"station-a","pid":4242},"metrics":{"queue_dir":"...","requests":3,"status_counts":{"PENDING":1,"SIGNED":2},"skip_reasons":{},"chains":{"dero":3},"actions":{},"spent_nonces":2,"locks":{"live":0,"oldest_age_seconds":0},"outbox":{"signed_outputs":2,"signed_unspent":0}}}
```

  `at` is RFC3339 UTC and `metrics` is the exact object
  `spore msg approval-metrics -json` emits (same field names), so a
  dashboard can reuse one parser for both. The JSON line is written only
  when the whole object encodes, so a failed encode never leaves a torn
  line in the stream; heartbeat errors still go to stderr. Note the
  station's startup line and cycle log lines go to stderr (Go `log`), so a
  stdout pipeline sees nothing but JSON heartbeat lines. Requires
  `-metrics-every > 0`; refused otherwise.

  Each line also carries `station`: the emitting station's hostname (the
  same tag its signing locks name as holder) and PID — so several stations
  teeing into one aggregated JSONL stream stay distinguishable, and a
  dashboard can correlate a heartbeat with the locks it reports holding.
  Heartbeats from spore < v0.8.5 have no `station` object; parsers written
  for the new shape must tolerate its absence.

  The one-shot summary can emit the exact same heartbeat line, so a cron
  scrape appends to the same file the live station writes:

```bash
spore msg approval-metrics -dir ~/approval-queue -state-dir ~/state -envelope >> station.jsonl
```

  `-envelope` and `-json` are alternative output formats; passing both is
  refused (exit 2).

### 3.2 Health-gating the log

`scripts/station-health.sh` turns the JSONL log into a pass/fail gate for a
cron job or the last stage of the pipeline — non-zero exit when the station
is not healthy:

```bash
spore msg approve ... -watch -every 30s -metrics-every 1m -metrics-json | tee -a station.jsonl
bash scripts/station-health.sh -f station.jsonl
```

It fails on: orphaned signing locks (guarded request file gone), lock ages
at/over the 60 s TTL stale-break line (default `--max-lock-age 60`), pending
requests at/over the 15-minute approval expiry (default `--max-pending-age
900` — past it the request can never be signed), malformed heartbeat lines,
or a log with no heartbeat lines at all. Exit codes: `0` healthy, `1`
health violation, `2` malformed input, `3` empty log. Thresholds are flags;
see the script header.

`-w`/`--watch` is the live tripwire form: it follows the log and stops with a
non-zero exit on the FIRST violation or malformed line instead of waiting for
the next cron pass, so a wrapper loop can alert immediately:

```bash
while bash scripts/station-health.sh -w -f station.jsonl; do sleep 2; done
```

Batch mode stays the historical gate (every violation, exit codes 0/1/2/3);
watch mode follows only new heartbeats. A tail failure in watch mode (file
vanished, permissions) also exits `2` — never a silent pass.

### 3.3 Alerting on the tripwire

`scripts/station-health-alert.sh` is the ready-made wrapper: it runs the
gate in `-w` mode and POSTs a JSON notification to a webhook on the first
violation (or malformed line, or tail failure), then resumes watching after
a cooldown so a persistent condition pages once per cooldown, not once per
heartbeat:

```bash
STATION_HEALTH_WEBHOOK=https://hooks.slack.com/services/... \
  bash scripts/station-health-alert.sh -f ~/station.jsonl
```

The payload is one JSON object — `source`, `at` (RFC3339 UTC), `host`,
`file`, `exit_code`, `text` (a Slack-friendly one-liner carrying the first
failure), and `detail` (the gate's full output) — so it posts as-is to a
Slack incoming webhook or any custom receiver:

```json
{"source":"spore-station-health","at":"2026-10-05T23:59:59Z","host":"station-a","file":"/home/ops/station.jsonl","exit_code":1,"text":"spore station health: /home/ops/station.jsonl tripped (exit 1): station-health: FAIL: 2026-10-05T23:59:00Z: 1 orphaned signing lock(s) ...","detail":"station-health: FAIL: ..."}
```

- `--dry-run` prints the payload instead of POSTing, so the whole path is
  testable without a receiver. `--once` alerts and exits with the gate's
  code (`1` violation, `2` malformed) for cron or systemd supervision, and
  exits `4` when the alert itself could not be delivered.
- Take the webhook from `STATION_HEALTH_WEBHOOK` so the secret stays out of
  argv/`ps` output; the URL is never logged.
- Gate thresholds pass through: `--max-pending-age`, `--max-lock-age`,
  `--max-pending`.

## 4. Requester side: post and verify

```bash
# rerun the EXACT original send, adding only -approval-file
spore msg send-e2 ... -require-approval APPROVER_KEY_HEX -approval-file ~/outbox/d_dero_3000.signed.json
# => approved DERO capability posted txid ...

# third parties can verify any signed envelope offline:
spore msg inspect-approval -file ~/outbox/d_dero_3000.signed.json \
  -state-dir ~/state -require-approver APPROVER_KEY_HEX
```

To see exactly what is ready to post without sending anything, list the
approvals and print one ready-to-run command per SIGNED envelope:

```bash
spore msg list-approvals -dir ~/outbox -state-dir ~/state -print-commands \
  -identity ~/keys/requester.key -pinned-sig REQUESTER_PINNED_HEX
# spore msg send-e2 -chain dero -to dero1qy... -amount 0.03 dero \
#   -require-approval APPROVER_KEY_HEX -approval-file ... \
#   -identity ... -pinned-sig ...
# (non-ready envelopes are summarized as comment counts, never commands)
```

The requester-only secrets (`-identity`, `-pinned-sig`) are printed as
`IDENTITY`/`PINNED_SIG` placeholders when the flags are omitted — printing
beats silently half-sending, because posting a capability burns its nonce.

The post re-checks everything on the sending device: approver signature,
requester binding, chain/recipient/amount match, current sender address,
Solana inbox PDA, and the unspent nonce. Any mismatch refuses before broadcast.
Once posted, the nonce is burned; re-scanning the queue with `-state-dir` will
show the request as spent.

## 5. Operator metrics

For queue health and SLA questions, summarize the pipeline's artifacts without
touching anything:

```bash
spore msg approval-metrics -dir ~/approval-queue -out-dir ~/outbox -state-dir ~/state
# approval metrics (queue ~/approval-queue; outbox ~/outbox; ledger ~/state)
#   queue: 12 request(s), 1 ignored file(s)
#   status: EXPIRED=1 PENDING=2 SIGNED=1 SPENT=8
#   skip reasons (why requests are not signable now):
#     8 x nonce already consumed; replay refused
#     1 x approval envelope: expired
#   ledger: 8 spent nonce(s)
#   locks: 1 live
#     d_dero_3000.json: held by approver-station/4242 for 3s
#   outbox: 8 signed output(s), 0 signed-but-unspent
#   approval latency (request -> signed), 8 matched: min 12s  p50 1m5s  p95 9m30s  max 13m40s  mean 2m1s
#   post latency (signed -> spent), 8 matched: min 5s  p50 40s  p95 3m0s  max 4m10s  mean 55s
```

- Reads only files the workflow already produces (queue, outbox,
  `approval-spent` ledger), so it needs no new state and always agrees with
  what `approve` would do next. `-json` carries the same numbers for
  dashboards; `-envelope` instead emits one compact watch heartbeat line for
  the same JSONL file a live station writes (§3.2).
- Gate the JSONL log with `bash scripts/station-health.sh -f station.jsonl`:
  non-zero exit on orphaned locks, stale-break-aged locks, requests past the
  approval TTL, malformed lines, or an empty log. See §3.2.
- For a Prometheus scraper or the node_exporter textfile collector, emit the
  same summary as the text exposition format:

```bash
spore msg approval-metrics -dir ~/approval-queue -out-dir ~/outbox -state-dir ~/state \
  -prometheus > ~/node_exporter/spore_approval.prom
```

  The `spore_approval_*` gauges cover queue volumes, statuses, skip reasons,
  locks (live / orphaned / oldest age), oldest-pending age, and the outbox
  latencies — the same numbers as the summary, sorted and diffable across
  scrapes.
- Several queues on one host can share one textfile: repeat `-dir` (with
  `-prometheus` only) and every series is labeled with its queue, so
  dashboards stay attributable per station. Give a station a friendly name
  with `-dir ~/station-a-queue=station-a` — the name replaces the raw path
  in every series (friendly labels require `-prometheus`). Write to a temp
  file and rename so the scraper never reads a half-written textfile:

```bash
spore msg approval-metrics -dir ~/station-a-queue -dir ~/station-b-queue \
  -prometheus > ~/node_exporter/spore_approval.prom.tmp \
  && mv ~/node_exporter/spore_approval.prom.tmp ~/node_exporter/spore_approval.prom
```

  Multi-queue mode refuses `-out-dir` and `-state-dir`: outbox and ledger
  latencies belong to one pipeline, so run one invocation per pipeline for
  those (into a per-pipeline file).
- Approval latency (request created -> approval signed) is bounded by the
  15-minute TTL; post latency (approval signed -> nonce burned) is the
  requester's remaining window. p95 creeping toward 15m means requests are
  expiring on the approver's desk — scale the `-watch` station or shorten the
  requester's polling.
- `signed-but-unspent` approvals in the outbox are waiting on the requester's
  send; a growing count with a rising post latency means the handoff (not the
  approval) is the bottleneck.
- The `locks` section is the live contention view: every `<request>.lock`
  currently in the queue, with its holder and age. Ages of a few seconds are
  stations mid-sign; an age creeping toward the 60 s TTL is a crashed holder
  that the next scan will break. Live locks are never counted as hygiene
  noise — `ignored file(s)` only picks up stale-break residue.

## 6. Operating notes

- **TTL is 15 minutes.** Expired requests are skipped, not signed. Re-request
  if the queue stalls; the nonce is fresh each time.
- **Two keys, two devices.** The requester key and approver key must differ;
  an envelope naming your own key is refused.
- **The spent ledger is the replay boundary.** It is exclusive-create in the
  requester's `-state-dir`; do not share one state dir across independent
  senders for the same chain.
- **`-confirm` is the human gate.** There is no batch flag that bypasses it;
  dry runs exist so you can see what *would* be signed first. `-watch` also
  requires it, because the station signs without a human watching each action.
- **Plaintext never on argv.** Bodies stay in `-msg-file`; the envelope only
  ever carries the opaque E2 pointer hash.
