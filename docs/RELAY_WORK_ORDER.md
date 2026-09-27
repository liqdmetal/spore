# Spore ↔ RelayOS work-order boundary

This note records the **first supported integration slice**, not a claim that a
paid task marketplace is already connected. The RelayOS evidence used here is
the read-only RC84 source snapshot in `_review_tmp`; it is not a Git checkout and
was not modified.

## Supported operation: register a committed objective

The inspected `RelayOSService` exposes one network mutation route:
`POST /v1/commands`. Its handler decodes an `AuthorizedCommand` and calls
`HardenedCommandIngress.execute`; RelayOS's configured `AuthorityCode` validates
the issuer grant, actor signature, grant subject/resource/scope, time window,
revocation, and replay before dispatching a registered action.

This Spore slice accepts only `objectives.register`, whose RelayOS handler takes
these fields:

```json
{
  "actor": {"actor_id": "did:relay:...", "public_key": "..."},
  "scope": "objectives.register",
  "command": {
    "action": "objectives.register",
    "resource_id": "objective-id",
    "payload": {
      "objective_id": "objective-id",
      "owner_pseudonym": "actor:...",
      "description_commitment": "...",
      "policy_hash": "..."
    }
  },
  "grant": {
    "issuer_id": "did:relay:...",
    "subject_id": "did:relay:...",
    "resource_id": "objective-id",
    "scopes": ["objectives.register"],
    "not_before": "...",
    "expires_at": "...",
    "nonce": "...",
    "signature": "..."
  },
  "signature": "..."
}
```

RelayOS replies with HTTP 200 and an envelope containing the registered
`ObjectiveRecord`:

```json
{"ok": true, "result": {
  "objective_id": "objective-id",
  "owner_pseudonym": "actor:...",
  "description_commitment": "...",
  "policy_hash": "..."
}}
```

Spore rejects HTTP errors, RelayOS `{ok:false}`, missing/malformed results, or a
record that differs from the submitted commitments. An optional bearer token
(`SPORE_RELAY_API_TOKEN`) is only for a reverse proxy; it is not command
authority. Remote URLs must use HTTPS (plain HTTP is allowed only for
loopback development) so a network intermediary cannot forge the registration
response. **Spore does not sign or verify RelayOS grants**:
the CLI accepts a pre-authorized envelope and forwards its actor, grant,
command, scope, and signature unchanged. RelayOS remains the authorization
authority. Focused local HTTP tests use deterministic Ed25519 fixture keys and
RelayOS's canonical JSON rules to exercise issuer/actor signature validity,
reject tampered signed fields, and verify field-preserving forwarding and
fail-closed responses. They establish adapter behavior against local fixtures,
not trust in a live RelayOS authority or issuer key; no live RelayOS service
was available for this pass.

Example:

```text
spore work-order register -command authorized-registration.json \
  [-relay-url http://127.0.0.1:8720]
```

The file should be created by an authorized RelayOS-side tool/person and kept
private if its signed metadata is sensitive. `SPORE_RELAY_URL` supplies the
service base URL when `-relay-url` is omitted, and `SPORE_RELAY_API_TOKEN` can
supply an optional reverse-proxy token. The CLI output says **registered**
and explicitly says execution is unsupported and settlement was not performed.

## Boundaries and state ownership

- `internal/sporrelay/workorder.go` owns the small wire types, work-order
  commitment validation, Relay identity/grant field binding, and registration
  result comparison. It generates an opaque objective ID only; it does not
  derive or conflate Spore keys, Relay actor keys, or chain addresses.
- `internal/sporrelay/client.go` owns HTTP transport, `/v1/commands`, strict
  request/response decoding, and registration result validation. RelayOS owns
  grants, revocation/replay state, objective state, execution, and settlement.
- `internal/sporrelay/cli/cli.go` owns command/file parsing and routes only
  `register` to the adapter. `execute` fails as unsupported; `verify`,
  `assurance`, and `complete` fail as unverified. The process wrapper injects
  stdout/stderr rather than mutating global process streams. Rendering never
  upgrades a registration into completion.
- `cmd/spore/workordercmd.go` is the thin process/usage boundary. Data flows
  command file → local shape checks → `POST /v1/commands` → exact registration
  record check → registration-only output. No task result or payment state is
  synthesized locally.

The old `spore settle discover|execute|assurance` surface used
`/api/v1/objectives/...`, which does not match the inspected RelayOS service;
it is retired. In particular, Spore must not treat a discover candidate as a
completed or assured objective.

## Not implemented: full paid job loop

The inspected RelayOS HTTP service does not expose the old Spore client's
`discover`, `execute`, `status`, or `assure` routes, nor does its objective
registration response return an execution plan. The local RC78 procurement
demo uses an internal deterministic rail; it is not a real on-chain payment.
Relay's `/v1/commands` mutation grant also does not itself express a work-order
budget or a provider spend capability.

So this slice **does not** select a provider, dispatch a task, bind a Spore
contact to a Relay actor and wallet, issue a per-order spend cap, carry a result
through an E2 session, independently validate that result, create escrow,
release/refund funds, or verify chain finality. It makes no escrow, atomic
settlement, or on-chain-payment claim. The full paid-loop blocker is a
versioned, signed RelayOS work-order/offer/accept/execute/result contract with
explicit scoped budget capability and an independently verifiable acceptance
receipt, plus a configured real-chain settlement rail. Until that exists and is
exercised with two independently operated parties, registration is the only
supported Relay integration outcome.
