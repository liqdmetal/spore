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
  - `approval file: create ...: file exists` — outputs are exclusive-create, so
    a rerun never overwrites an existing approval
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

## 5. Operating notes

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
