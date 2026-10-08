# Private E2 incident pager

The incident pager is a local, encrypted workflow for asking pinned E2 contacts to acknowledge or decline an incident. It is not an emergency-services channel or an availability guarantee. It sends no plaintext to a public service: signed incident messages travel inside already-established E2 sessions and the chain sees only the normal opaque E2 pointer.

## Requirements

- Initialize Spore and keep the E2 identity, state key, and state directory backed up and private.
- Maintain a mail address book with a signed-invite-derived prekey bundle and a pinned signing key for every responder (`spore msg mail add -invite TOKEN`).
- Establish a normal E2 session with each responder before inviting them. The incident command never opens a fresh X3DH session and refuses to infer peer identity from a chain sender field.
- Configure a carrier and body store using the same E2 flags as `spore msg send-e2` / `recv-e2`.

## Create and invite

Select responders and create a local record:

```sh
spore incident create -identity identity.key -incident-address YOUR_CHAIN_ADDRESS \
  -state-dir state -state-key state.key -maildb mail.json \
  -summary "Primary site unreachable" -details-file private-details.txt \
  -deadline 15m -expires 24h -quorum 2 -to oncall -to network
```

`-to` is repeatable and resolves exact nicknames or addresses from the local maildb. Every selected responder must have a verified pinned contact and an established authenticated E2 session. The quorum must not exceed the selected responder count. The record and details are written only to the encrypted incident store at `state/incidents.enc`.

Then send the signed per-responder invitations:

```sh
spore incident invite -id INCIDENT_ID -to oncall -to network \
  -identity identity.key -incident-address YOUR_CHAIN_ADDRESS \
  -state-dir state -state-key state.key -maildb mail.json \
  -store https://your-body-store -chain dero -rpc http://127.0.0.1:10102/json_rpc
```

The invitation is signed by the creator identity and binds the incident ID, event ID, recipient address and pin, summary, details, deadline, expiry, and quorum. Each invitation goes to one responder, so the responder roster is not disclosed to peers. The local outbox stores intent before ratchet transmission and persists an exact prepared pointer for retry. Re-run `spore incident flush` after transient carrier failures; do not regenerate or manually repost an outbox pointer. If the process stops during pointer preparation before that pointer is saved, the event is deliberately blocked rather than re-encrypted at a later ratchet position; preserve the state and coordinate a fresh incident/session instead of trying to clear or replay the old event.

## Respond and inspect

A responder runs `spore msg recv-e2` with the configured identity and `-incident-address` to receive an invitation. Review the details, then explicitly respond:

```sh
spore incident reply -id INCIDENT_ID -ack \
  -identity identity.key -incident-address YOUR_CHAIN_ADDRESS \
  -state-dir state -state-key state.key -maildb mail.json \
  -store https://your-body-store -chain dero -rpc http://127.0.0.1:10102/json_rpc
```

Use `-decline` instead of `-ack` to decline. A reply is signed by the responder's pinned identity and tied to the invited session; event IDs make exact retries idempotent. The creator receives it through `msg recv-e2`, and the local record records the response and quorum event. Reaching quorum does not resolve the incident automatically.

```sh
spore incident list ...
spore incident show -id INCIDENT_ID ...
spore incident resolve -id INCIDENT_ID ...
```

Only the creator identity may resolve an incident. Responses stop at the response deadline; the record expires at its later expiry. Expired/resolved incidents cannot be reopened. Store contents are encrypted at rest with the same 32-byte state key, authenticated, and written atomically with private file permissions.

## Safety and operational notes

- There is no plaintext or fallback carrier mode. Signed E2 application messages are rejected unless the session's authenticated X3DH identity matches the pinned mail contact and the signed message names the intended local identity.
- Incidents require an existing E2 session. If a peer key, session, or contact mapping is ambiguous or missing, establish a new normal E2 conversation and correct the pin/bundle; do not bypass the check.
- Quorum means the configured number of invited responders acknowledged before the deadline. It is a local coordination signal, not proof of remediation or independent confirmation.
- The encrypted incident file includes responder choices, private details, event history, signed payloads, and pending pointers. Treat the state key and backups as sensitive.
- A transport success is not a human acknowledgement. Verify with `incident show` and an explicit responder event.
