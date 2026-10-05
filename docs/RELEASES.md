# Spore releases

Release notes per tag, newest first. Binaries are stamped with
`git describe --tags --always` at build time (`spore version` prints it).

## v0.8.1 — second-device capability approvals, concurrent-station hardening (2026-10-04)

**One line:** a `spore` send no longer moves value on its own — the exact
chain, recipient, amount, and pointer must be countersigned by a second
device holding a different key, and the nonce can broadcast at most once.

30 commits, 31 files, +7,800/−159 vs `v0.8.0`.

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
