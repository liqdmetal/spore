# Private work handoff v1

Spore connects a RelayOS objective registration to a private, human-reviewed
exchange: **brief → deliverable → accept or reject**. RelayOS remains the
registration authority; Spore carries the brief, policy, and result inside an
already-established authenticated E2 session. This is **not** a paid-work
protocol implementation, remote execution API, independent verifier, or payment
instruction. No funds move, no escrow is created, and no new RelayOS server
handler is assumed.

## Scope and trust

- One buyer, one distinct provider, one deliverable, one final decision. No
  automatic dispatch, revisions, milestones, discovery, or delegated spending.
- Signing uses the pinned Spore E2 identity, **not** the Relay actor key. A
  Relay actor, messaging identity, and wallet remain separate principals.
- `work-order register -out` exports a **local observation** only after the
  existing adapter receives an exact matching successful registration response.
  It is not a server-signed receipt. A recipient can verify the buyer's handoff
  signature and commitment bindings, but cannot independently establish RelayOS
  registration, actor ownership, revocation, or current remote state from it.
  An observation file can be fabricated by its holder; treat the registration
  link as sender-asserted metadata, not an authority or spend capability.
- `accept` records the buyer's explicit decision on the exact result bytes.
  Neither transport delivery nor a provider signature establishes correctness.
  Acceptance does not create RelayOS completion, assurance, or settlement state.
- Chain metadata can still reveal timing/addresses. Only the usual opaque E2
  pointer is posted; private artifacts and signatures stay off-chain.

## Prerequisites

Initialize Spore on each endpoint, exchange signed invites and pin the contact,
and establish a normal E2 conversation first. Both sides need their private
identity, state key, state directory, maildb, and a reachable body store.
Unsupported, blocked, missing, or changed contacts/sessions fail closed; handoff
commands never bootstrap a fresh conversation or downgrade the carrier.

Examples below assume each endpoint has a config file containing `identity`,
`spk`, `state_dir`, `state_key`, `maildb`, `address`, and the existing store and
carrier settings. The `address` must be the exact address in the other party's
pinned contact. Without a configured address, supply `-handoff-address ADDR` on
state commands and `msg recv-e2`. Explicit flags override config defaults.

## 1. Commit and register the brief

On the buyer endpoint, create a private brief and a human acceptance policy.
Hashes cover the **exact file bytes**, including newlines. Keep the files and
all exported copies private.

```sh
spore work-order handoff commitments \
  -brief-file brief.txt -policy-file acceptance.txt
```

The JSON output contains `description_commitment` and `policy_hash`, each
`sha256:` plus 64 lowercase hex characters. Use those exact values with the
existing preparation command:

```sh
spore work-order prepare \
  -actor-key /private/relay-actor.key \
  -issuer /private/trusted-issuer.json -grant /private/relayos-grant.json \
  -objective-id objective:example -owner-pseudonym actor:buyer \
  -description-commitment sha256:BRIEF_DIGEST \
  -policy-hash sha256:POLICY_DIGEST \
  -out authorized-registration.json

# Explicit persistent remote mutation; use an authorized target and fresh grant.
spore work-order register -command authorized-registration.json \
  -relay-url https://YOUR_RELAYOS -out registration-observation.json
```

The observation path is reserved exclusively **before** submission, so an
existing output cannot cause a duplicate remote mutation. On failure no valid
observation is exported. If registration succeeds but observation export fails,
the error explicitly says not to resubmit; reconcile the registration with the
RelayOS operator instead of replaying a consumed grant. As with the existing
registration API, a network timeout may leave the remote outcome uncertain.
Do not assume a timeout means no registration happened.

Existing `register` callers without `-out` retain their behavior. Observation
export requires actual SHA-256 commitments; the older registration boundary
alone continues accepting the server's existing opaque commitment strings.

## 2. Queue and send the private brief

```sh
spore work-order handoff brief -config buyer.json \
  -registration registration-observation.json -to provider \
  -brief-file brief.txt -policy-file acceptance.txt -expires 168h

# Save the printed handoff ID. Queueing alone does not contact the carrier.
spore work-order handoff flush -config buyer.json
```

The brief is rejected if either file differs from the registered commitments.
Queueing writes the signed event and intent together to the encrypted store.
`flush` rechecks the pinned contact, block/allowlist, exact session identity,
and multi-device send restrictions before preparation or reposting.

On the provider endpoint, receive through the existing pipeline:

```sh
spore msg recv-e2 -config provider.json
spore work-order handoff list -config provider.json
spore work-order handoff show -config provider.json -id HANDOFF_ID

# Optional explicit plaintext exports for a human/editor/tool to inspect.
spore work-order handoff export -config provider.json -id HANDOFF_ID \
  -artifact brief -out review-brief.txt
spore work-order handoff export -config provider.json -id HANDOFF_ID \
  -artifact policy -out review-policy.txt
```

`show` prints the signed record as JSON; binary content and policy use base64
JSON encoding. It is an intentional disclosure to stdout. `export` writes the
exact selected bytes to an exclusively created mode-0600 file; it never
executes the content or overwrites an existing path. Protect/delete plaintext
exports yourself. They are outside encrypted-store expiry.

## 3. Deliver and decide

Provider:

```sh
spore work-order handoff deliver -config provider.json -id HANDOFF_ID \
  -result-file report.txt
spore work-order handoff flush -config provider.json
```

Buyer (after `msg recv-e2` has received the deliverable):

```sh
spore work-order handoff export -config buyer.json -id HANDOFF_ID \
  -artifact result -out review-report.txt

# Review the exact result against the original policy, then choose ONE:
spore work-order handoff decide -config buyer.json -id HANDOFF_ID -accept
# spore work-order handoff decide -config buyer.json -id HANDOFF_ID -reject
spore work-order handoff flush -config buyer.json
```

The provider receives the decision with `msg recv-e2`. Decision signatures bind
both the exact previous deliverable event and its result hash. Only the buyer
may decide; neither party may replace the result, change terms/session, or
reopen a final decision. Start a fresh handoff for revised work. Local status
reflects a queued signed transition, not proof it reached the other endpoint;
inspect `outbox[].sent` separately. Carrier success is not human acceptance.

## Protocol and storage

Signing domain: `spore/private-handoff/v1`. Ed25519 signs the domain, a NUL
separator, and Go's deterministic typed JSON encoding of the validated message.
The outer envelope is `{domain,message,signature}`. Signatures use lowercase
hex. Binary content/policy use base64 JSON strings. An event hash is `sha256:`
plus the SHA-256 of the typed envelope JSON. This is a Spore-local v1 protocol,
not the proposed paid-work-order wire protocol or a claim of cross-language
RelayOS signing interoperability.

All messages bind version, random handoff/event IDs, registration observation,
buyer/provider addresses and pins, expiry, sequence, previous-event hash, and
kind. The only legal sequences are `brief` (1), `deliver` (2), and `accept` or
`reject` (3). Identical events are idempotent while retained; conflicting event
IDs, signatures, terms, sessions, previous hashes, and result commitments are
rejected. Incoming events must also match the authenticated session peer and
intended local identity; a chain's sender field is not identity evidence.

Bounds:

- Brief or deliverable: **16 KiB** exact bytes each; policy: **8 KiB**.
- Signed envelope: 96 KiB parser ceiling; emitted brief plus E2 framing fits
  the existing 64 KiB HTTP body store at the maximum artifact sizes.
- Up to 128 handoffs and an 8 MiB encrypted store. Three work events, three
  persistence receipts, and three outbound items maximum per handoff (work
  events plus receipts). Oversize writes fail without replacing state.
- Expiry: positive, at most **720 hours / 30 days**; default **168 hours**.
  Incoming events cannot extend this limit. Expired events cannot be reimported.
- Strict JSON rejects duplicate/case-aliased keys, unknown fields, nulls,
  trailing values, and nesting beyond 32 levels.

State lives at **`<state-dir>/handoffs.enc`**, encrypted/authenticated using the
existing state protector and 32-byte state key, with a distinct handoff storage
binding. Writes use a private encrypted temp file, sync, and atomic rename.
Each transaction reloads disk state under an exclusive lock, preventing stale
handoff handles from silently clobbering one another. This is not a hardware
anti-rollback guarantee; restoring the entire directory/key can restore history.

Expired records and pending pointers are removed on successful state access or
explicitly with:

```sh
spore work-order handoff prune -config buyer.json
```

There is no background pruning when Spore is stopped. Pruning removes active
records, not backups, plaintext exports, filesystem remnants, or permanent
chain pointer scraps. `spore panic -state-dir DIR -confirm` covers the handoff
store along with the rest of that directory; external exports are separate.
Private handoff payloads bypass the normal mail snippet index, attachment
output, notifications, and auto-ack path. They are not automatically executed.

## Delivery and recovery limits

- Re-run `handoff flush` after a transient carrier failure. A successful pointer
  preparation is persisted and reused **byte-for-byte** after restart. Device
  send accounting is idempotent. Carrier retries can post duplicate pointer
  transactions (and incur postage); there is no exactly-once carrier promise.
- A durable preparation marker is saved **before** advancing the ratchet. If
  the process stops before the pointer is saved, that event blocks. Do not
  clear the marker, reconstruct a pointer, or reencrypt the old event. Preserve
  state and coordinate a fresh handoff/session. This favors confidentiality
  over automatic recovery from an ambiguous ratchet transition.
- Exclusive `handoffs.enc.lock` and `handoffs.enc.send-lock` files refuse
  competing writers/flushers rather than timing out live holders. A crash may
  leave a stale lock. Confirm the recorded process is gone and no writer is
  using the directory before removing only that stale lock. Locks are never
  auto-broken by age.
- Use **one sending process per ratchet state directory**, as for the existing
  E2 commands. Handoff locking does not serialize unrelated normal E2 sends,
  incident flushes, device imports, or other processes manipulating sessions.
- Configure the receiver identity/address/store before receiving. Handoff
  continuation events and persistence receipts use the encrypted receive journal
  described below. A failed application write remains recoverable after restart,
  even without the original body. Invalid/configuration-blocked payloads remain
  pending rather than receiving a false success receipt. Initial handshake
  frames carrying handoffs are refused: establish a normal E2 conversation first.
- The journal closes the **decrypt-to-application** crash window, not every
  delivery window. A crash before journal durability still needs carrier/body
  redelivery. The existing chain watcher may already have burned its inbox
  pointer; no exactly-once carrier promise is added. No receipt means persistence
  is unconfirmed, not proof of loss. Same-directory independent processes or
  device imports still must not manipulate the ratchet concurrently.

## Signed persistence receipts and actionable status

A receiver atomically stores the incoming event **and** a deterministic signed
`persisted` receipt plus its outbound delivery intent in `handoffs.enc`. The
receipt binds handoff ID, event ID/hash, terms hash, sequence, both exact pinned
participants, E2 session ID, expiry, and `status: "persisted"`. Signing domain:
`spore/private-handoff-receipt/v1`; encoding and strict decoding follow the same
rules as work events, with an 8 KiB receipt parser limit.

Receipt signatures are verified against the authenticated E2 peer and exact
locally sent event/session. A receipt for another event, policy, participant,
session, or expired handoff cannot confirm delivery. Receipt messages do **not**
advance the brief/deliver/decision history and do **not** generate receipts of
their own. Upgrade both endpoints to use this receipt protocol; older binaries
do not understand or generate application persistence receipts.

Receive queues receipts locally; **it never spends postage automatically**:

```sh
spore work-order handoff status -config provider.json
spore work-order handoff flush -config provider.json
# Buyer receives the signed receipt using msg recv-e2, then inspects:
spore work-order handoff status -config buyer.json
```

`status` reports the next human/operator action and each outbound item's state:

- `queued`: explicitly flush the pending work or receipt;
- `blocked`: pointer preparation was interrupted; preserve state;
- `posted; awaiting signed persistence receipt`: carrier success only;
- `peer-persisted`: exact event acknowledged by its recipient's pinned key;
- `persistence receipt posted; no acknowledgement required`: no receipt loop.

`show` includes signed `receipts[]` and `outbox[].application_received`. These
are separate from `outbox[].sent`: a receipt can arrive even if a previous
carrier response was lost. Verified peer persistence suppresses unnecessary
reposts; it never changes the human decision. A final decision without a peer
receipt is highlighted as unconfirmed, not silently presented as delivered.
A peer-persisted brief still awaits a result; a peer-persisted deliverable still
awaits explicit buyer review. No receipt means read, accept, verify, or pay.

## Crash-safe receive journal and recovery

`<state-dir>/receive-pending.enc` is one encrypted/authenticated, bounded
**512 KiB** journal using a distinct storage binding and the existing state key.
It holds the exact incoming payload, CID, session/deadline, original head digest,
and exact next encrypted ratchet head. These include sensitive key material:
protect the state directory and key; never print or share the journal plaintext.

For selected handoff continuations the ordering is:

1. Decrypt on a disposable session clone; live/disk state is unchanged.
2. Atomically write and sync the encrypted receive journal.
3. Commit the exact next keystore sequence log and head, then replace live state.
4. Atomically persist the event/receipt and any signed receipt delivery intent.
5. Delete the receive journal **last**.

A journal write failure does not advance the live or durable ratchet. Startup
finishes the exact journaled head **before** normal anti-rollback restoration
or session expiry, then replays the application write idempotently. Recovery
handles a full or partial log append before head replacement and an application
commit before journal deletion. It requires the original head or the exact next
head/log; a newer/conflicting state refuses recovery instead of rolling back.
Successful recovery never needs the original ciphertext or re-decrypts it.

An unfinished receive blocks later durable sends/receives and expiry on that
endpoint, avoiding a later transition overtaking recovery. Existing ordinary
mail is not retained in this journal. The shared chain/fabric receiver attempts
recovery on startup and before another frame. Explicit local recovery is:

```sh
spore work-order handoff status -config provider.json
spore work-order handoff recover -config provider.json
# Repair any reported contact/config/store problem, then retry recovery.
spore work-order handoff flush -config provider.json
```

`status` decrypts local state internally but prints only the pending CID/session
and status metadata, never the pending artifact or ratchet keys to stdout. `recover` uses the configured local identity and authenticated contact
checks. It uses the configured body-store setup but does not fetch the old body
or contact the chain. Restore both journal and session state together; copying
only the ratchet or deleting the journal destroys this recovery guarantee.

Invalid signatures, blocked contacts, mismatched local identity, expired work,
or a full/unwritable application store remain pending with **no success
receipt**. Fix the cause and retry. If the inspected packet must deliberately
be abandoned, use the exact CID reported by status:

```sh
spore work-order handoff recover -config provider.json \
  -discard-pending-cid EXACT_64_CHARACTER_CID
```

Discard commits/retains the ratchet transition, deletes only that pending
application payload, and issues no receipt. It does not undo any application
write that might already have committed before a crash. It is explicit loss,
not recovery success. Never delete the journal manually or bypass a conflicting
state check. The journal is retained even past expiry until recovery/discard;
`panic -state-dir DIR -confirm` includes it. File sync/atomic rename and these
tests cover process interruption, not storage hardware losing acknowledged
writes or unrestricted attackers restoring an entire directory. Stale handoff
transaction locks still require the ownership check described above.

## DAO human-gatekeeper use

This is a useful building block for a DAO's private evidence handoff: public
objective/policy commitments, private evidence to a named pinned human, a signed
persistence acknowledgement, and an explicit decision on the exact result. It
can answer **which key persisted which packet** without publishing the private
packet on-chain or handing a relay the decryption keys.

It is not yet a DAO voting or quorum protocol. A safe next slice would bind
independent gatekeeper decisions to one immutable proposal/policy/epoch, show
missing decisions, and export a verifiable quorum certificate for a separately
authorized execution gate. RelayOS authority grants, Spore evidence delivery,
and chain treasury enforcement must remain separate. No handoff receipt alone
may authorize a vote, change membership, release funds, or impersonate a DAO.
Self-hosted operation needs no new paid service, but infrastructure and chain
postage are not guaranteed free. This composition is the advantage; the
individual encryption/signature capabilities are not unique to Spore.

## Verification coverage and remaining evidence

Local tests exercise both decisions, forged/conflicting/out-of-order events,
strict parsing, commitment and session binding, expiry/pruning, encrypted state,
wrong-key/tamper rejection, locks/stale handles, maximum transport sizes, and
interrupted preparation, receive-journal/log/head/application crash windows,
signed receipt forgery/replay/binding, exact receipt pointer retries, explicit
CID discard, a real subprocess exit after application commit, and no
acknowledgement loops. A real compiled CLI test prepares
and registers with a local RelayOS HTTP fixture, queues a brief, fails and
retries a local carrier, injects an application-write failure, recovers using
the public CLI, receives through the shared E2 pipeline, delivers binary result
bytes, explicitly exports for review, and exchanges all three persistence
receipts including the final acceptance decision. The carrier
fixture observes only canonical 74-byte pointers and the mail index stays empty.

These tests are **local evidence**, not a live RelayOS integration, funded-chain
test, independent-recipient deployment, independent cryptographic review, or
verification of result quality. The RelayOS checkout available for this work was
a read-only snapshot and was not changed.
