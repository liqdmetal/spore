# Spore docs — the map

Every document in `docs/`, grouped by what you are trying to do. The README is
the front door; this page is the signposting behind it. If a doc is missing
here, it is a bug in this file, not a hidden document.

## Start here

- [`ONBOARDING.md`](ONBOARDING.md) — zero to first forward-private message:
  install, `spore init`, bundle exchange, mailboxes, and Tails/Whonix.
- [`FRIENDS.md`](FRIENDS.md) — the shortest path to one conversation with one
  friend, and nothing else.
- [`USER_GUIDE.md`](USER_GUIDE.md) — the DERO path command by command, for
  someone who wants the long version.
- [`FULL_PICTURE.md`](FULL_PICTURE.md) — the deployment shapes (serverless,
  home node, hosted) and why the parts fit together.
- [`USE_CASES.md`](USE_CASES.md) — what these properties are actually good for,
  written from the architecture rather than from the pitch.

## Carriers, money, and what is verified

- [`CARRIER_MATRIX.md`](CARRIER_MATRIX.md) — every carrier: pointer transport,
  compost behaviour, body stores, and the honest limits of each.
- [`LIVE_NODES.md`](LIVE_NODES.md) — what has been run against real EVM,
  Solana and XMR endpoints, and what has not.
- [`PEER_SETUP.md`](PEER_SETUP.md) — running the direct-body `spore-peer`
  transport between two people.
- [`MONERO_SETTLEMENT.md`](MONERO_SETTLEMENT.md) — XMR as the money rail, end
  to end, including the parts that refuse rather than pretend.
- [`PAY_IN_XMR.md`](PAY_IN_XMR.md) — the buyer's walkthrough: one thread, one
  payment, two signatures.
- [`JOB_RECEIPT_V1.md`](JOB_RECEIPT_V1.md) — a job as a signed, portable
  receipt rather than a screenshot.
- [`CLOSE-FREE-ROUTING.md`](CLOSE-FREE-ROUTING.md) — Tron fee economics as an
  assessment and plan (2026-11), not a shipped feature list.

## Continuity and multiple devices

- [`CONTINUITY.md`](CONTINUITY.md) — the dead-man vault: owner check-ins,
  holders, watchers, quorum release, and the explicit no-automatic-transfers
  model.
- [`MULTIDEVICE.md`](MULTIDEVICE.md) — syncing ratchet state across devices,
  and the key-reuse hazard that makes "sync before you send" a rule.

## Hosting and operations

- [`HOME_NODE.md`](HOME_NODE.md) — your own always-on node as the privacy
  default.
- [`MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md) — the hosted blind-courier
  service for phones and low-power devices.
- [`MODEL_B_RUNBOOK.md`](MODEL_B_RUNBOOK.md) — the operator steps that stand
  that service up.
- [`NOTIFICATIONS.md`](NOTIFICATIONS.md) — arrival alerts, both paths, and
  what each one leaks.
- [`NTFY_BETA.md`](NTFY_BETA.md) — the hosted beta's private ntfy deployment,
  as it actually runs.
- [`INCIDENT_PAGER.md`](INCIDENT_PAGER.md) — asking pinned contacts to
  acknowledge an incident, with its limits stated up front.
- [`APPROVAL_RUNBOOK.md`](APPROVAL_RUNBOOK.md) — second-device signing of one
  exact pointer/value action, requester and approver flows.

## Working with other people and systems

- [`PRIVATE_HANDOFF.md`](PRIVATE_HANDOFF.md) — RelayOS objective → private
  brief → deliverable, with a human accept/reject in the middle.
- [`DAO_REVIEW.md`](DAO_REVIEW.md) — private gatekeeper review with an
  offline-verifiable approval certificate.
- [`HOOKED_INTEGRATION.md`](HOOKED_INTEGRATION.md) — what an integrator may
  store, what never leaves spore, and the command behind each.
- [`RELAY_WORK_ORDER.md`](RELAY_WORK_ORDER.md) — the RelayOS integration
  boundary as first shipped.
- [`PAID_WORK_ORDER_PROTOCOL_V1.md`](PAID_WORK_ORDER_PROTOCOL_V1.md) —
  proposed contract. Design only: not implemented and not deployed.

## Protocol internals

- [`WIRE_SPEC.md`](WIRE_SPEC.md) — the canonical payload, envelope, pointer
  and peer bytes. Source of truth for the formats.
- [`RATCHET.md`](RATCHET.md) — X3DH + Double Ratchet as implemented.
- [`MESSAGE_DATAFLOW.md`](MESSAGE_DATAFLOW.md) — byte-level walk of where a
  message is encrypted, decrypted and reaped, with the code that does it.
- [`SENDER_AUTH.md`](SENDER_AUTH.md) — sender-authentication threat model and
  design.
- [`RELAY_FABRIC.md`](RELAY_FABRIC.md) — pointer forwarding across the fabric
  (F1 shipped, later slices design).
- [`RELAY_FABRIC_F4.md`](RELAY_FABRIC_F4.md) — transports, cover traffic and
  onion publish: the design addendum to the above.

## Releases and project history

- [`RELEASES.md`](RELEASES.md) — release notes per tag, newest first, with
  verified asset digests for the recent ones.
- [`../ROADMAP.md`](../ROADMAP.md) — what shipped and what is next.
- [`../ROADMAP-PRODUCTION.md`](../ROADMAP-PRODUCTION.md) — the production
  readiness tracks and their invariants.
- [`../VISION.md`](../VISION.md) — the long form of why this exists.
- [`BUSINESS.md`](BUSINESS.md) — sustainability without a token or a VC.
- [`SOLANA_AND_USECASES.md`](SOLANA_AND_USECASES.md) — the 2026-09-05 Solana
  decision note. Kept as history: it says what was decided then.
- [`../AUDIT-SPOREPEER.md`](../AUDIT-SPOREPEER.md) — audit of the historical
  Rust `spore-peer` transport.
- [`../AUDIT-RELAYFABRIC.md`](../AUDIT-RELAYFABRIC.md) — audit of the relay
  fabric slices.

## Reference data

- [`interop-vectors.json`](interop-vectors.json), [`ratchet-vectors.json`](ratchet-vectors.json),
  [`job-receipt-v1.vector.json`](job-receipt-v1.vector.json) — conformance
  vectors consumed by independent implementations.
- [`status-v1.schema.json`](status-v1.schema.json) — the `spore status -json`
  schema.
- [`refs.yml`](refs.yml) — docs whose commit-hash citations CI verifies.

Adding a document? Add its line here in the same commit, or it is reachable
only by people who already know it exists.
