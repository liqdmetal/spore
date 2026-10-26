# Job receipts v1 — a signed record of work, portable by design

**Status: design.** No command emits a receipt today. What exists is everything a
receipt is built from: `spore sign doc` produces a detached Ed25519 attestation
over a file ([signcmd.go](../cmd/spore/signcmd.go), `internal/attest`), `spore sign
sheet` verifies a set of them and reports who is missing, `spore sign anchor`
publishes a digest for a timestamp, and `spore archive put` keeps the bytes. This
document fixes the *record*, so that two implementations sign the same bytes
instead of two plausible formats.

Bounded by the same rule as [HOOKED_INTEGRATION.md](HOOKED_INTEGRATION.md): nothing
here hands a platform the ability to decrypt a message. A receipt is about a job,
not a conversation.

## 1. Why there are two kinds, and why both are optional

A receipt is a service the provider performs for the client, not a tax on either
of them. Two consequences, stated as requirements rather than intentions:

1. **The provider chooses.** Default is no receipt. A provider may offer one on
   request, or commit to always issuing one, and that policy must be visible
   *before* a job is booked. A provider who declines gets no artifact, no
   "declined" marker, and no trace of the decline — an artifact recording a
   refusal would be a record they never consented to.
2. **The client can still account for the money without the provider.** A spend
   receipt is unilateral: the client signs alone, no provider participation, no
   provider name, no provider key. It documents funds out for bookkeeping,
   invoicing and tax. It is not, and must never become, a reputation signal —
   see §8.

The two kinds are independent. A job can produce both, either, or neither. The
attested receipt is what a future client can rely on; the spend receipt is what
an accountant needs.

## 2. The document, and why its bytes are the format

`spore sign doc` signs a *file*: the transcript is built from the SHA-256 and
length of the exact bytes plus the statement (`internal/attest`,
domain `spore/attest/v1`). There is no JSON canonicalization inside the
signature, on purpose — so a receipt is only meaningful if both parties sign
byte-identical files. That makes canonical form part of the protocol:

- UTF-8, no BOM, `\n` line endings, exactly one trailing newline.
- Object keys sorted ascending by byte value at every depth. No duplicate keys.
- Two-space indent, `": "` after keys, `,` separators, no other whitespace.
  (Readable *and* deterministic; a printer and a verifier must agree.)
- No floating-point values anywhere. Money is a decimal string of non-negative
  integer atomic units. A parser that turns a money field into a float is
  non-conforming.
- No `null`. An absent optional field is omitted.
- Timestamps are RFC 3339 in UTC with a literal `Z` and no fractional seconds.
- Arrays keep the order given; any array whose order is not meaningful is
  defined as sorted by the stated key.
- Digests are lowercase hex SHA-256, prefixed `sha256:`.
- Unknown fields are rejected in a v1 reader (a v1 record with an extra field is
  not a v1 record), and the whole record is rejected if `protocol` or `version`
  disagree.

The record's identity is not a field: `receipt_id = sha256:` over the canonical
bytes. A verifier computes it; a signer must not be trusted to report it.

## 3. Kind A — attested job receipt

```json
{
  "protocol": "spore.job-receipt",
  "version": 1,
  "kind": "attested",
  "service": {
    "category": "plumbing.emergency",
    "summary": "Replace failed shutoff valve, kitchen line"
  },
  "parties": {
    "provider_pub": "hex ed25519 public key, the pinned-sig value",
    "client_pub": "hex ed25519 public key"
  },
  "work": {
    "started_at": "2026-10-24T15:02:11Z",
    "finished_at": "2026-10-24T16:41:52Z"
  },
  "settlement": [
    {
      "rail": "dero",
      "network": "dero-mainnet",
      "asset": "dero",
      "amount_atomic": "2500000000000",
      "txid": "hex chain transaction id",
      "settled_at": "2026-10-24T16:44:03Z"
    }
  ],
  "deliverables": [
    {
      "label": "before",
      "digest": "sha256:…",
      "bytes": 184223
    },
    {
      "label": "after",
      "digest": "sha256:…",
      "bytes": 201774
    }
  ],
  "client_verdict": {
    "accepted": true,
    "rating": 5,
    "note": "arrived inside the hour, cleaned up"
  },
  "links": {
    "work_order_id": "optional id of the order both sides agreed",
    "thread_session": "optional hex session id of the spore thread"
  },
  "supersedes": "optional sha256:… of an earlier record for this job"
}
```

Rules that make this usable rather than decorative:

- **Both keys sign the same file.** `provider_pub` and `client_pub` are the same
  Ed25519 halves peers already exchange out of band as `-pinned-sig`. No CA, no
  account, no platform key.
- **Statements are constants**, because the statement is inside the signed
  transcript. A verifier rejects an envelope whose statement is not the role's
  constant, otherwise the signature means something other than what is claimed:

  | Role | Statement |
  |---|---|
  | client | `spore.job-receipt/v1 client acceptance` |
  | provider | `spore.job-receipt/v1 provider attestation` |

  `spore sign sheet` does **not** make this comparison: it verifies each envelope
  against the statement that envelope carries, so a revised wording still counts
  as a valid signature by the right key. The check is the verifier's, and a
  verifier that skips it is trusting a sentence the signer chose.

- **A provider signature alone is not an attested receipt.** One key is a claim,
  two keys are a record. A record with only the provider's envelope may exist
  locally as `kind: attested, coverage: provider-only`, but no verifier may count
  it toward reputation and no UI may present it as one. A one-signer record
  therefore carries `"coverage": "provider-only"` and omits `client_pub` and
  `client_verdict`; a dual-signed record omits `coverage` entirely, since absence
  is the only spelling of "both parties signed". A strict v1 reader rejects any
  other combination.
- **`client_verdict` is omitted when the client declines to rate.** Silence is
  not a bad rating; a verifier must not treat an absent verdict as negative.
- **Deliverables are hashes, not payloads.** The photos never enter the record;
  the record says which photos were meant. Matching them back is the client's
  local job (`archive put`, their own disk).
- **Amounts are never converted.** One line per settlement, in that rail's own
  atomic unit. Fiat valuation belongs to the accounting export (§9), not to the
  signed record.

## 4. Kind B — spend receipt (provider-blind)

```json
{
  "protocol": "spore.spend-receipt",
  "version": 1,
  "kind": "spend",
  "client_pub": "hex ed25519 public key",
  "period": {
    "from": "2026-10-01T00:00:00Z",
    "to": "2026-10-31T23:59:59Z"
  },
  "service": {
    "category": "plumbing.emergency",
    "summary": "Replace failed shutoff valve, kitchen line"
  },
  "settlement": [
    {
      "rail": "dero",
      "network": "dero-mainnet",
      "asset": "dero",
      "amount_atomic": "2500000000000",
      "txid": "hex chain transaction id",
      "settled_at": "2026-10-24T16:44:03Z"
    }
  ],
  "evidence": "chain-backed",
  "provider_commitment": {
    "scheme": "spore/provider-commitment/v1",
    "value": "sha256:…"
  }
}
```

- **Statement:** `spore.spend-receipt/v1 client declaration`.
- **No provider key, name, address or fingerprint.** `provider_commitment` is
  `sha256("spore/provider-commitment/v1" ‖ provider_pub_bytes ‖ salt)` with a
  fresh 32-byte `salt` the client keeps. It lets the client later prove *which*
  provider a row refers to — in a dispute, or an audit — without publishing the
  link, and it stops the same provider appearing twice under two ids in an
  aggregate. Omit the whole block for a purely private bookkeeping row.
- **`evidence`** is `chain-backed` when every settlement line carries a `txid`,
  `self-declared` otherwise. An export must print this per row. A receipt with
  no txid is a bookkeeping entry: it records what the client says they paid, and
  nothing more.
- **Settlement lines are shared with Kind A on purpose.** A spend receipt and an
  attested receipt for one job must cite identical `txid`/`amount_atomic`, so an
  auditor can join them without either document naming the other.

Spend receipts are usually period documents (one per month) rather than one per
job, because that is what an accountant asks for. Both are valid; `period` is
then the span the lines fall in.

## 5. Provider policy — how "optional" is enforced

A provider publishes one of three policies wherever they can be booked:

| Policy | Behaviour |
|---|---|
| `off` | No attested receipt is ever produced. Requests are refused with a plain "this provider does not issue receipts". |
| `on-request` | The client asks on the job record; the provider accepts or declines before work starts. |
| `always` | The provider commits to issuing one; the client may still decline to sign, which yields `coverage: provider-only` and no reputation entry. |

The policy must be shown before booking, not negotiated after — a provider who
discovers at completion that a receipt exists has had their option taken from
them. Hooked (or any front end) may store the *policy*, the `receipt_id` and the
record digest; it must not require the record itself (§2 of
[HOOKED_INTEGRATION.md](HOOKED_INTEGRATION.md)).

Nothing in this section obliges the client to accept a receipt, and nothing
obliges the provider to issue one. A booking with `off` is a complete booking.

## 6. Producing and verifying one

Attested receipt, provider side:

```
spore sign doc -identity provider.key -file job.json \
  -statement "spore.job-receipt/v1 provider attestation" -out provider.sig
```

Client side, same bytes, different statement:

```
spore sign doc -identity client.key -file job.json \
  -statement "spore.job-receipt/v1 client acceptance" -out client.sig
```

Verification by someone who was never in the conversation, holding only the two
public keys and the file:

```
spore sign sheet -file job.json -sigs client.sig,provider.sig \
  -required <client_pub_hex>,<provider_pub_hex>
```

A sheet that fills both slots is a complete receipt. A sheet reporting a missing
signer is not a receipt yet, and must not be rendered as one. Optional real
timestamp: `spore sign anchor -sig client.sig` (chain commitment; costs a fee,
needs no recipient cooperation).

Durability: `spore archive put -file job.json` for the record and one for each
signature, since the mirror set is what survives a lost disk. Keep them together
— a signature whose document is gone is unverifiable.

A worked vector lives in [job-receipt-v1.vector.json](job-receipt-v1.vector.json):
a canonical record whose `receipt_id` is the SHA-256 of the file
(`07d6d54b8afb6c98de4f6e5aac2225320e9ef603d685ac8710a0ca30c30d76d5`). Every step
above is exercised against it end to end by `cmd/spore/jobreceipt_test.go`, which
also pins the gap just described: it signs with a paraphrased statement and shows
`sign sheet` still reporting a complete receipt. The settlement `txid` in the
vector is synthetic — it exists to be the right shape, and nothing verifies it
on-chain.

## 7. What each artifact proves

| Claim | Attested receipt | Spend receipt |
|---|---|---|
| These exact bytes existed and were signed by this key | yes | yes |
| The provider agreed this work happened, for this price | yes | no |
| The client accepted the work | yes, unless verdict omitted | no |
| The money moved | only as far as the cited txid verifies on-chain | only as far as the cited txid verifies on-chain |
| When it was signed | only with `sign anchor` | only with `sign anchor` |
| Who the parties legally are | no — that is the out-of-band pin | no |
| A rating is fair | no | no |

Two honesty notes that belong in any UI built on this. First, dual-signed means
the *pair* agreed; a confident liar with two keys and a real payment still
produces a valid receipt, so receipts raise the cost of faking a history rather
than making it impossible. Second, a receipt is not a contract: it records what
happened, and it does not by itself settle a dispute — that is
[DAO_REVIEW.md](DAO_REVIEW.md)'s job, with the receipt as evidence.

## 8. Aggregation rules for a portable reputation view

Anyone can sum receipts, so the rules that stop a sum from lying must be
published with it:

1. Count **dual-signed** records only, one per `(provider_pub, client_pub)` pair —
   the tenth job for the same client does not move the number.
2. Require at least one settlement line whose `txid` the viewer can verify.
3. Weight by nothing. No decay, no recency fudge, no "verified" tier a platform
   sells — every knob is a lever to sell placement.
4. Show the **count of distinct clients** next to the mean score, and show the
   **oldest and newest** record. A mean over three records is not a reputation.
5. Never merge spend receipts into it. They are client-side declarations with no
   provider co-signature; using one as a rating is exactly the forgery this
   split exists to prevent.
6. Sybil resistance is partial and must be described as such: each counted pair
   costs a real payment and a distinct client key, which is a price, not a
   proof.

## 9. Accounting export

A spend receipt is the row an export prints. Minimum columns:

```
period_start, period_end, category, summary, rail, network, asset,
amount_atomic, txid, settlement_time, evidence, receipt_id
```

`amount_atomic` stays an integer string — conversion to a reporting currency
happens in the accounting tool, at a rate it chooses and can defend, never
inside spore and never as a float. `evidence` travels with every row so a
`self-declared` entry can never be mistaken for a chain-checked one. Rows sort by
`settlement_time`, then `txid`, so two exports of the same month are identical
byte for byte.

## 10. Supersede, correction, and deletion

- A correction is a new record with `supersedes` set to the old `receipt_id`,
  dual-signed again. The old record still verifies — that is the point of
  signatures — but an aggregator follows the chain and counts the head.
- A provider cannot revoke a receipt the client holds. Neither can the client
  revoke the provider's copy. This is a feature; it is why the record is worth
  keeping.
- `spore panic -confirm` removes local copies. It cannot reach a copy the other
  party kept, and no honest UI may imply otherwise.
- Nothing here is written on-chain except an optional digest anchor. A receipt
  with an anchor is public as a hash, which is enough to prove it existed by a
  time and not enough to read it.

## 11. Acceptance tests before this ships

1. **Round trip, no state.** Two signatures verify with `spore sign sheet` on a
   machine holding only the file, the signatures and the two public keys.
2. **Byte stability.** Ten thousand re-serializations of one record in shuffled
   key order produce one byte sequence and one `receipt_id`.
3. **Float refusal.** `"amount_atomic": 0.25` is rejected by the parser, not
   coerced.
4. **Statement binding.** An envelope signed with a paraphrased statement is
   rejected even though the key and document match.
5. **Provider `off`.** No receipt file is created, and a grep of every front-end
   table for the job id finds no receipt row or digest.
6. **Spend receipt blindness.** A spend receipt verifies with the client key
   alone; grepping it for the provider's key, hostname or display name finds
   nothing.
7. **Commitment opening.** The kept salt opens `provider_commitment` to the
   provider key; a wrong salt or a different provider does not.
8. **Tamper.** Changing one digit of `amount_atomic` invalidates both
   signatures.
9. **One-sided.** A provider-only record is reported as `coverage: provider-only`
   and is refused by an aggregator that counts attested receipts.
10. **Supersede.** A corrected record counts once, at its head, and the earlier
    record still verifies.

## 12. Open items

- **Fiat valuation is deliberately absent.** Any exchange rate inside a signed
  record is a number someone must defend years later; it belongs to the export.
- **No currency conversion, no totals across rails.** A record may carry several
  settlement lines in different assets; summing them is the consumer's problem.
- **Group or multi-provider jobs** need a `contributors` array and a rule for
  which keys must sign; not in v1.
- **Partial acceptance and change orders** are expected to arrive as separate
  records joined by `links.work_order_id`, but the paid work order protocol is
  itself design-stage ([PAID_WORK_ORDER_PROTOCOL_V1.md](PAID_WORK_ORDER_PROTOCOL_V1.md)),
  so that join is not yet testable.
- **One vector exists** ([job-receipt-v1.vector.json](job-receipt-v1.vector.json),
  exercised by `cmd/spore/jobreceipt_test.go`). A cross-language set — the same
  record printed by a second implementation, plus its receipt id — must exist
  before that implementation claims conformance, the same demand
  [WIRE_SPEC.md](WIRE_SPEC.md) makes of the wire format.
