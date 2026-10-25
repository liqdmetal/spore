# Hooked ↔ Spore — integration contract v1

*What Hooked may store, what never leaves spore, and the command behind each
step. A contract for an integrator, in the same spirit as
[`PAID_WORK_ORDER_PROTOCOL_V1.md`](PAID_WORK_ORDER_PROTOCOL_V1.md): it describes
a boundary between two systems, not a capability spore already ships end to end.*

**Status:** design contract. Hooked's own materials already list "ephemeral chat
(Spore)" as a feature; this is the document that makes that claim implementable
and defines when it is truthful. Nothing here is deployed.

**Split of responsibility.** Hooked is the marketplace: bookings, accounts,
pricing, commission, ratings, fiat. Spore is the channel: encrypted bodies,
ratchets, settlement notes, signatures. Neither side is a superset of the other,
and the contract is mostly about resisting the temptation to make one be.

---

## 1. The one rule

> Nothing Hooked stores may decrypt a message, now or later.

Every column in Hooked's database must be marketplace metadata, a public
identifier, or a signed artifact whose plaintext was never in Hooked's
possession. If a field would need a key prepared "for support", it belongs on
the device or it does not exist.

Two corollaries that shape the rest of this document:

- **Custody is a product decision, not a default.** A server that holds a user's
  spore identity can read that user's threads. Shape A (below) never does;
  Shape B does, and must say so in the UI.
- **The courier is blind by construction.** Hooked hosting a mailbox means
  storing TTL-bound ciphertext and serving prekeys — the same role
  [`MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md) describes for a phone user's always-on node.

---

## 2. Data boundary

| Datum | Lives in | Mechanism | Why not the other side |
|---|---|---|---|
| Booking id, service, price, currency, status, timestamps | Hooked | ordinary tables | marketplace state |
| Account identity, login, billing email | Hooked | ordinary tables | Hooked's own auth |
| Client ↔ provider spore fingerprint (Ed25519 pubkey + pinned sig) | both | `spore invite` token; public values | needed to bind a thread to a booking |
| Invite token (signed introduction) | both | `spore invite issue` / `verify` | public, short-lived, replay-checked |
| E2 session id for the booking | both | opaque hex from `msg send-e2` | the join key between systems; useless alone |
| Message bodies: text, photos, files | spore only | X3DH + Double Ratchet ciphertext | the entire point |
| Addresses, gate codes, unit numbers, arrival notes | spore only | message body | keeping them out is cheaper than encrypting them in |
| Invoice id, amount, due date | both | `msg invoice` on the ratchet; amount also as metadata | Hooked needs it for commission |
| Payment txid / receipt | both | chain; `msg pay`, `msg escrow claim` | public chain data |
| Completion statement + both signatures | both | `sign doc` + `sign sheet` | evidence, not conversation |
| Dispute evidence packet + quorum certificate | both | `dao-review` artifacts | verifiable without Hooked |
| Ratings, reviews, badges | Hooked only | ordinary tables | explicitly not a spore artifact |
| Notification route (ntfy URL, email, SMS) | Hooked only | `spore provision -notify-file` output | metadata-only arrival pings |
| Keys, ratchet state, maildb | device only | `-state-dir`, `-state-key`, `-maildb` | never server-side under Shape A |

The rows marked "spore only" are the reason a database dump of Hooked is boring.
Keep that true: a support engineer must never be able to paste a client's gate
code into a ticket, because it was never there.

---

## 3. Deployment shapes

**Shape A — device-held keys (the contract's default).** The client runs the
spore side (native wrapper, `spore web`, or a local daemon). Hooked mints
invites, records fingerprints and session ids, hosts the mailbox, and never sees
a private key. End-to-end encryption means what it says: Hooked is a party to
the booking, not to the conversation.

**Shape B — custodial fast path (opt-in, labelled).** Hooked operates spore
identities on behalf of users who will not install anything. Every guarantee in
§6 changes: Hooked can decrypt, so the UI must not claim E2E against Hooked. Use
it for the browser-only fallback and a `spore web` room, not as the default.

Every claim in the marketing pages has to name which shape it describes.

---

## 4. Lifecycle, step by step

Each step names the command and says what Hooked records. Commands are the
shipped CLI surface; flags shown are the load-bearing ones, not the full set.

**0. Provisioning (Hooked operator, once per user).**

```
spore provision -users DIR -name USER -tokens FILE -batch PUBLIC_BATCH.json \
                [-notify-file FILE] [-email ADDRESS] [-sms E164] [-mailbox-url URL]
spore prekeybatch gen -out BATCH.json -n 50        # rotate single-use bundles
spore prekeybatch push -in BATCH.json -mailbox URL [-token SECRET]
spore mailbox host -users DIR [-listen :ADDR] [-tokens FILE] [-interval 3s]
```

Hooked records: mailbox URL, mailbox name, token, notification route. Not the
keys, not the batch privates.

**1. Introduction.** The provider's app shows an invite; the client verifies it
before any message exists.

```
spore invite issue  -identity FILE -spk FILE -address ADDR [-name NAME]
spore invite verify -invite TOKEN [-expect FINGERPRINT]
```

The hosted mailbox serves the same invite as a QR (`/u/<name>/qr`). Hooked
records: the fingerprint, the booking id, the issue time.

**2. Opening the thread.** The first message creates the ratchet session.

```
spore msg send-e2 -to ADDR -identity F -bundle-url URL -pinned-sig HEX \
                  -store URL -state-dir D -state-key F -msg-file F
```

Hooked records: the returned session id against the booking id, nothing else.
A booking with no message yet has no session — do not pre-create one.

**3. Receiving, including while the client is away.**

```
spore msg recv-e2 -identity F -spk F [-opk-pool F] -store URL \
                  -state-dir D -state-key F [-auto-ack] [-maildb F] \
                  [-ntfy URL] [-notify-email ADDRESS | -notify-sms E164]
```

Hooked's mailbox holds ciphertext until the device drains it. `-ntfy`,
`-notify-email`, `-notify-sms` carry *arrival metadata only* — the notification
says something arrived, never what it says.

**4. Replies.** `spore msg reply-e2 -to ADDR -session HEX -state-dir D -state-key F`.
Threads are per booking, not per pair: a repeat client gets a new session for a
new booking, so a dispute over one job cannot re-read the last one.

**5. Money.**

```
spore msg invoice -to ADDR -session HEX -amount 25dero [-for TEXT] [-due 72h]
spore msg pay     -to ADDR -session HEX -amount 25dero [-invoice ID]
```

`msg pay` settles money and proof in one atomic transaction. For job-sized
amounts with a completion condition, fund an HTLC and settle in-thread:

```
spore msg send -escrow htlc ...          # funds the HTLC
spore msg escrow claim  -hash HEX -preimage HEX -to ADDR -session HEX ...
spore msg escrow refund -hash HEX -to ADDR -session HEX ...
```

Commission has two shapes that keep Hooked out of the key path: a rail-level
split at payment time, or prepaid credits —
`spore credit request`, `credit issue`, `credit redeem`, `credit revenue` — which
sell access without a per-user meter. Recurring maintenance relationships fit
`spore sub paid` (roster + crypto-paid entitlement, no account, no invoice).

**6. Completion.** Both parties sign the same statement; Hooked archives the
sheet, and may anchor it.

```
spore sign doc   -identity FILE -file STATEMENT -statement "I agree" -out A.sig
spore sign sheet -file STATEMENT -sigs A.sig,B.sig [-required PUBKEY,PUBKEY]
spore sign anchor -sig A.sig
```

`sign sheet` reports who signed and who has not, which is the only completion
signal Hooked should trust. An anchored signature is a public timestamp; do not
anchor anything that names the parties unless the user asks.

**7. Dispute, when it gets that far.** Same shape as a DAO gatekeeper review:

```
spore dao-review create      -dao HOOKED -proposal BOOKING_ID -epoch N -to MEDIATOR ...
spore dao-review decide      -id HANDOFF_ID -expect-review-hash HASH -approve|-reject
spore dao-review certificate -expect-review-hash HASH -out CERT
spore dao-review verify      -certificate CERT -expect-review-hash HASH
```

The certificate verifies offline, so a mediator's decision survives Hooked's
own outage — or Hooked's own shutdown.

**8. Two-key spend control (provider accounts with staff).** One device proposes,
another approves, and the nonce is burned at broadcast so a retry cannot
double-pay:

```
spore msg send-e2 ... -require-approval APPROVER_PUBKEY -approval-request REQ.json
spore msg approve -request REQ.json -identity APPROVER -out SIGNED.json -confirm
spore msg send-e2 ... -approval-file SIGNED.json
spore msg list-approvals [-status pending|signed|spent|expired] [-json]
```

**9. Retention and deletion.** Bodies compost on their TTL. Account deletion is
`spore panic -confirm`: a verifiable local wipe. Hooked must state plainly that
it cannot restore what a panic wipe removed, because it held no copy.

---

## 5. What Hooked's backend actually implements

| Hooked endpoint | Runs | Records | Fails how |
|---|---|---|---|
| `POST /admin/spore/provision` | `spore provision` | mailbox URL, name, token | 502; booking cannot open a thread |
| `POST /bookings/:id/invite` | `spore invite issue` | token hash, fingerprint, expiry | 409 if a live invite exists |
| `GET  /bookings/:id/invite/qr` | static from mailbox | — | 404 after expiry |
| `POST /bookings/:id/thread` | device holds the keys; the app runs `spore msg send-e2` and posts back the session id | session id | 422 if no verified invite |
| `GET  /bookings/:id/messages` | `spore msg recv-e2` + `msg mail -db F` | nothing (renders from device) | empty is normal |
| `POST /bookings/:id/invoice` | `spore msg invoice` | invoice id, amount, due | 409 on duplicate id |
| `POST /bookings/:id/complete` | `spore sign sheet` | signed sheet blob | 409 until both signatures present |
| `POST /disputes/:id/panel` | `spore dao-review create` | review hash, roster | 403 if roster unset |

The backend's job is ids, tokens and blobs. If an endpoint needs a private key
to run, it belongs in Shape B and the UI has to say so.

---

## 6. What Hooked may and may not claim

**Safe to say:** "Messages between you and your provider are end-to-end
encrypted; we relay ciphertext we cannot read." "Messages rot on the schedule
you choose." "We cannot recover a message you deleted or wiped."

**Not safe to say:** "We can recover your chat history." "Your messages are
anonymous." "Delivery is guaranteed." "Nobody can tell you talked to this
provider" — timing, mailbox names and on-chain transactions are all visible to
someone.

Known leaks, stated once: Hooked's mailbox sees arrival timing and body sizes
(padded to a fixed 1 KiB bucket); public chains show the transaction, not the
note; a payment that cites a booking id links the two, so cite it only when the
user chooses to.

---

## 7. Acceptance tests before the feature ships

1. **Canary.** Send a unique string through a booking thread, dump every table
   Hooked owns, `grep` for it: zero hits.
2. **Offline delivery.** Stop the mailbox, send, restart, receive: exactly one
   delivery, no duplicate plaintext.
3. **Replay.** Re-present a used invite and a used approval envelope: both
   refused, exits non-zero, nothing broadcast.
4. **Wrong peer.** Verify an invite with the wrong expected fingerprint: refused.
5. **Completion gating.** `sign sheet` with one signature reports the missing
   party; Hooked must not mark the booking complete.
6. **Dispute portability.** Export a certificate, verify it on a machine that has
   never talked to Hooked.
7. **Deletion.** `spore panic -confirm` removes local state; Hooked's UI shows
   the thread as unrecoverable rather than empty with a retry button.
8. **Chain variance.** The same booking thread over DERO and over an EVM carrier
   behaves the same except for public visibility.

---

## 8. Open items

- **Group threads.** Spore has channel rooms (`spore channel`, `spore chat
  -channel`, `spore web`) and pairwise sessions, not an E2 group key. Looping
  Hooked support into a booking is a second session and explicit forwarding.
- **Paid work orders** are design-only; RelayOS integration today is
  `objectives.register`. Do not build commission accounting on it.
- **Fiat** stays entirely in Hooked; spore sees crypto rails only.
- **Ratings** stay in Hooked; there is no reputation primitive here to abuse.
- **Costs.** A hosted mailbox is real disk and bandwidth; price it before
  promising free "always-on" chat.
