# Paid Work-Order Protocol v1 (proposal)

**Status: design only — not implemented or deployed.** This is a target contract
for Spore and RelayOS interoperability, not a description of currently available
RelayOS endpoints. The current Spore integration supports only the
`objectives.register` command at `POST /v1/commands`; it does not discover
providers, dispatch work, verify results, or settle a work order. See
[`RELAY_WORK_ORDER.md`](RELAY_WORK_ORDER.md) for the implemented boundary and
current blocker.

Protocol identifier: `spore.paid-work-order`, major version `1`.

## 1. Goals and v1 limits

V1 defines a complete, auditable path from a buyer's bounded request through a
provider's offer, funded award, evidence-based acceptance, and chain-verified
payout or refund. RelayOS coordinates authenticated state transitions; it is
not a wallet, custodian, or truth oracle. Spore carries private task details,
results, and evidence between the parties over an authenticated E2 session.

To keep the first implementation narrow, v1 supports one buyer, one awarded
provider, one settlement network and asset, one fixed maximum price, and one or
more explicitly priced milestones. Offers are fixed-price, denominated in
integer atomic units; no floating point, FX conversion, variable-rate billing,
subcontracting, or delegated provider spending. A work order is not paid merely
because a provider says it is done or because RelayOS records a state change.

A future implementation must add the required RelayOS command handlers and
query views. It must not infer that this proposal is already supported by the
existing `objectives.register` action or by RelayOS's local procurement demos.

## 2. Principals and identity separation

A work order names Relay actor IDs for authorization and audit. A Relay actor ID
must be bound to its Ed25519 public key using RelayOS's identity derivation.
Mutating transitions use RelayOS `AuthorizedCommand` envelopes: RelayOS
validates the trusted issuer grant, actor signature, exact subject/resource/
scope, time window, revocation, and replay. The envelope authorizes a protocol
command; it does not itself authorize a wallet debit or escrow release.

Three identities stay distinct:

1. **Relay actor identity** authorizes RelayOS commands and signs offers,
   decisions, and evidence attestations.
2. **Spore E2 identity/session** authenticates and encrypts private task
   descriptions, deliverables, and evidence packages. A Relay actor ID is not
   an E2 contact key.
3. **Settlement address/key** identifies the chain account that funds escrow
   or receives a payout/refund. A pseudonym or Relay actor ID is not a wallet
   address. Any claimed actor-to-wallet link requires an explicit,
   chain-specific, challenge-bound control proof and the party's consent; do
   not infer a link from matching names or metadata.

Offers, policies, and evidence must state which principal signed them. Key
rotation requires an explicit, verifiable authorization from the old key or a
separately documented recovery rule; changing a display name is not key
rotation.

## 3. Serialization, commitments, and authorization

Every protocol object carries `protocol: "spore.paid-work-order"` and
`version: 1`. Signatures and digests are domain-separated by protocol, version,
object kind, and object body. RelayOS command envelopes retain the deployed
RelayOS canonical-signing rules; implementations must ship cross-language
golden vectors (including Unicode/escaping cases) before they claim
interoperability. Reject duplicate JSON keys, unknown mandatory fields,
unsupported major versions, malformed digests, and non-canonical monetary
values. Monetary quantities are canonical decimal strings representing
non-negative integer atomic units; a currency descriptor includes network and
asset ID. Never parse a budget through a floating-point type.

Each state transition is an append-only event containing at least
`work_order_id`, `event_id`/nonce, monotonically increasing `sequence`,
`previous_event_hash`, actor identity, action, timestamp, and protocol version.
RelayOS must reject a stale sequence, wrong previous hash, reused nonce, or
replayed command. Identical retries return the original event/result rather
than applying the transition twice. Event hashes do not replace the underlying
actor signatures or chain verification.

Candidate command actions below are **proposed names**, not claims about
registered actions in the inspected service. Each action must have a
least-authority Relay grant scoped to its precise resource and operation; no
wildcard resource or broad settlement scope. Sensitive reads should be
role-scoped, and public discovery should expose only explicitly published
listing fields.

## 4. Protocol objects

### 4.1 Work order and immutable terms

The buyer creates a `WorkOrderV1` bound to the existing objective commitment:

```json
{
  "protocol": "spore.paid-work-order",
  "version": 1,
  "work_order_id": "objective-id",
  "buyer_actor_id": "did:relay:…",
  "description_commitment": "sha256:…",
  "policy_hash": "sha256:…",
  "settlement": {
    "network": "chain-specific-network-id",
    "asset_id": "chain-specific-asset-id",
    "price_cap_atomic": "2500000",
    "fee_cap_atomic": "50000",
    "escrow_refund_after": "2030-01-02T00:00:00Z"
  },
  "deadlines": {
    "offer_close": "2030-01-01T00:00:00Z",
    "work_due": "2030-01-02T00:00:00Z",
    "review_due": "2030-01-03T00:00:00Z"
  },
  "milestones": [
    {"milestone_id": "m1", "price_atomic": "1500000", "acceptance_policy_hash": "sha256:…"},
    {"milestone_id": "m2", "price_atomic": "1000000", "acceptance_policy_hash": "sha256:…"}
  ],
  "terms_hash": "sha256:…"
}
```

This is illustrative. The canonical `terms_hash` covers all immutable terms,
including the total price cap, fee cap, settlement network/asset, deadlines,
milestone prices, and acceptance policy hashes. The sum of milestone prices
must equal `price_cap_atomic` (or be less only when the unallocated remainder is
explicitly marked refundable). `policy_hash` commits to the full acceptance,
dispute, and timeout policy. A change to any committed term creates a new
signed version/offer round; it must not silently mutate the registered
objective.

The order may publish a short description, category, cap, and deadlines for
discovery, while keeping detailed instructions, personal data, and acceptance
fixtures encrypted for selected parties. Commitments do not hide fields that
are deliberately made public or revealed by the settlement chain.

### 4.2 Provider offer

A provider submits a signed `ProviderOfferV1` referencing the exact
`work_order_id` and `terms_hash`. It contains:

- unique `offer_id`, provider Relay actor ID, creation and expiry times;
- exact network/asset and total price, no greater than the buyer cap;
- milestone mapping and deliverable commitments, if milestones are used;
- provider's proposed completion dates and required buyer inputs;
- the acceptance-policy hash it agrees to (must equal the order's policy);
- provider payout destination or a commitment to reveal it only for funding;
- provider's E2 delivery key/contact binding, established out-of-band or by a
  challenge over the authenticated E2 session;
- any verifier identity/key required by the acceptance policy.

A changed price, deliverable, deadline, asset, or policy creates a new offer
hash and requires a new buyer award. An offer signature is not an acceptance,
funding proof, or payment instruction.

### 4.3 Award and spend mandate

The buyer awards exactly one offer by signing an `AwardV1` that includes the
order ID, `terms_hash`, offer ID/hash, provider actor ID, exact milestone
schedule, `price_cap_atomic`, `fee_cap_atomic`, settlement network/asset,
refund deadline, and a unique escrow/budget ID. The awarded amounts cannot
exceed the original terms. Provider and buyer must both be bound to this exact
award; a provider's different offer cannot be substituted afterward.

The award includes a separate, buyer-authorized `SpendMandateV1`, bound to the
award hash and actual escrow contract/account. It caps the amount the escrow
may release, the asset/network, recipient, milestone IDs and per-milestone
amounts, and expiry. RelayOS AuthorityGrant scopes are not spend mandates.
Only the buyer's wallet-controlled funding action may lock the budget; neither
RelayOS nor Spore receives the buyer's wallet private key. Any network fee is
bounded separately by `fee_cap_atomic`, and a fee-cap overrun must fail closed.

Before execution starts, the settlement adapter independently verifies that
escrow contains the exact awarded asset and at least the awarded amount, and
that the lock/refund conditions match the mandate. The provider cannot draw
against an unfunded award. An increase to the cap requires a new buyer-signed
award amendment and additional finalized funding. No Relay command can raise a
cap, change an asset, add a recipient, or authorize a transfer on its own.

### 4.4 Result and acceptance evidence

A provider submits `ResultEvidenceV1` with the order, award, offer, milestone,
terms and acceptance-policy hashes; a commitment to the delivered result; an
E2-protected artifact locator or delivery reference; evidence-package hash;
producer identity; and a provider signature. The result bytes and sensitive
test data are delivered to the buyer over E2, not made public by a Relay event.
The provider's claim proves who submitted a result, not that it meets the
acceptance policy.

An `AcceptanceReceiptV1` is issued only by the authority named in the immutable
acceptance policy: the buyer, a named independent verifier, or a named
threshold of verifiers. It binds the exact result and evidence hashes, order,
offer, award, milestone, policy version, decision, and amount eligible for
release. The receipt contains signed verifier findings and enough references or
proofs for the settlement adapter to check the policy's required predicates.
A verifier must be distinct from the provider for independent-verification
policies. The provider may submit evidence but cannot issue its own acceptance
receipt.

The policy must define verifiable predicates, required evidence types, trusted
verifier keys, response/dispute deadlines, and the timeout disposition before
an offer is awarded. Subjective work may use explicit buyer approval or a
preselected adjudicator; it must not be relabeled as an objective machine proof.
No missing result, unreachable verifier, malformed proof, silence, expired
receipt, or RelayOS `{ok: true}` response counts as acceptance. In v1, silence
never implies acceptance.

### 4.5 Funding and settlement receipts

A chain-specific adapter produces a `FundingReceiptV1` only after checking the
funding transaction/event, escrow ID, asset, amount, destination, lock deadline,
and configured confirmation/finality policy against the chain. A user-supplied
transaction ID or RelayOS assertion alone is insufficient. The receipt records
network, transaction ID, block hash/height, amount, confirmation threshold,
verification time, and a proof/reference sufficient for independent re-check.

After a valid acceptance receipt, the adapter may release only the accepted
milestone amount, to the award's fixed provider destination, under the mandate.
A `SettlementReceiptV1` records `release` or `refund`, order/award/escrow and
milestone IDs, exact asset/amount/recipient, transaction and block reference,
fees, finality rule, and verified finality status. It is not final merely
because a transaction was submitted or RelayOS returned success. Consumers
must distinguish `accepted` from `settled`; the latter requires independently
verified chain finality at the configured depth/observer policy.

The escrow/adapter must enforce all of these invariants:

```text
sum(finalized provider releases) <= funded amount
sum(finalized refunds) + sum(finalized provider releases) <= funded amount
release(milestone) requires a valid, unexpired AcceptanceReceipt for that milestone
release recipient and asset == the awarded provider destination and asset
refund recipient == the buyer funding destination
one milestone allocation is consumed at most once
```

A release and refund are mutually exclusive uses of the same locked units. A
reorg returns a receipt to a non-final/pending state until the chain policy is
satisfied again; it must not be shown as paid/settled. If a chain cannot enforce
the award's cap, timeout, and release/refund conditions, the protocol must use
explicit buyer-controlled signing or a suitable escrow contract, and must say
that the settlement is not trustless/automatic. RelayOS alone cannot promise
atomic settlement. The RC78 deterministic procurement rail is not a real-chain
receipt.

## 5. State machine and failure policy

Maintain separate work and money states; never compress them into a single
`complete` boolean.

- **Work:** `open → awarded → funded → in_progress → result_submitted →
  accepted | rejected | disputed | expired`.
- **Funds:** `unfunded → locked → partially_released | released | refund_pending
  → refunded`, with `pending`/`reorged` chain observations represented
  explicitly.

Allowed transitions require the relevant signed actor command, policy
verification, or chain observation. The successful path for one milestone is
`result_submitted → accepted` (valid acceptance receipt) and separately
`locked → released` (valid release plus final chain finality). For a multi-
milestone order, one accepted/released milestone does not mark the whole order
complete while any required milestone is outstanding.

The policy names exact deadlines and one timeout disposition: refund
unaccepted funds to the buyer, or move to a preselected adjudicator whose
signed decision is required. The system never treats timeout or missing
verification as acceptance. Rejected work may be disputed before the stated
deadline; a dispute pauses affected releases. Resolution requires the
preauthorized adjudicator/threshold, and can only allocate the still-locked
balance within the original cap. After the refund deadline, any unallocated
balance follows the order's precommitted refund path. No operator may rewrite
this disposition after award.

Commands must be idempotent, persist their event before responding, and make
ambiguous outcomes queryable by event/transaction ID. A client timeout after
broadcast is not a reason to submit a second payment; query the same ID and
verify chain state. Fail closed on state gaps, mismatched hashes, authority
failure, unavailable evidence, ambiguous chain results, or finality regression.

## 6. Proposed RelayOS surface and Spore responsibilities

RelayOS should expose read-only views for published order listings, authorized
offers, current order state, evidence/acceptance receipts, escrow state, and
final settlement receipts. All mutations remain `POST /v1/commands` and pass
through the existing authenticated command-ingress boundary. Candidate actions
include `work_orders.open`, `work_offers.submit`, `work_orders.award`,
`work_orders.start`, `work_results.submit`, `work_acceptance.issue`,
`work_disputes.open`, `work_disputes.resolve`, and
`work_settlement.observe`. Names and payloads require RelayOS review before
implementation; they are not current routes.

RelayOS owns the authoritative event sequence, grants/replay/revocation state,
order/offer/award records, and command authorization. It may check the
structure and signatures of party-supplied evidence, but the configured
acceptance verifier and chain adapter own the relevant independent checks. The
chain adapter owns funding/finality observations. The escrow/chain contract
owns enforceable locked balances. Spore owns the E2 conversation and transport
of private work/result artifacts; its CLI must never synthesize acceptance,
payment, or finality from local status text.

## 7. Minimum acceptance tests before calling v1 implemented

An implementation is not complete until automated tests cover at least:

- golden signing/hash vectors shared by Go and RelayOS; wrong version, actor,
  resource, scope, key binding, signature, nonce, and event sequence rejection;
- competing offers, expired offers, offer substitution, altered terms, and
  concurrent awards (exactly one winning award);
- unfunded work cannot start; asset/amount/destination mismatch is refused;
- every budget boundary, extra fee, milestone sum, duplicate release, double
  refund, and attempted cap escalation fails closed;
- provider-signed results alone never pass acceptance; missing, malformed,
  stale, wrong-policy, or wrong-verifier evidence never releases funds;
- explicit buyer/verifier approval, rejection, dispute, adjudication, deadline
  and refund paths; silence never becomes acceptance;
- partial milestones, command retries/timeouts, crash recovery, chain reorgs,
  finality thresholds, and independently rechecked settlement receipts;
- an end-to-end run with independently operated buyer and provider identities,
  separate E2 sessions, and a configured real test-chain escrow/settlement
  adapter. Simulators and RelayOS's internal deterministic rail are useful
  unit-test tools, not proof of deployed paid-loop behavior.

Until these contracts, adapters, and cross-party tests exist, Spore supports
registration only. This proposal describes the target; it does not remove the
current implementation blocker or authorize users to treat a registered
objective as a paid, executed, accepted, or settled job.
