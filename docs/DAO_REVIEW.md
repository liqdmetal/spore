# Private DAO gatekeeper review v1

Spore's `dao-review` workflow distributes one immutable evidence packet to an
explicit human-reviewer roster, collects signed approve/reject decisions, and
exports a quorum certificate that can be verified offline. The evidence stays
inside existing authenticated E2 sessions and encrypted local handoff state.

**This is review evidence, not a DAO consensus engine or treasury capability.**
Review creation, decision signing, certification, and verification make no wallet
calls. No automatic voting, treasury transfers, escrow, contract execution,
RelayOS command submission, or on-chain membership discovery are performed.
Explicit transport `flush` can incur ordinary carrier transaction/postage costs.

## What this adds

- One coordinator signs a manifest committing to DAO namespace, proposal ID,
  epoch, exact evidence and policy hashes, explicit reviewer addresses/pins,
  strict-majority threshold, creation time, response deadline, and expiry.
- Each reviewer receives the same manifest and private artifacts in an
  individually signed E2 handoff. Roster-wide queueing is one local encrypted
  transaction; a bad contact/session or write failure cannot queue half a roster.
- A selected reviewer explicitly signs one `approve` or `reject` bound to the
  exact manifest hash and their original invitation. Generic handoff
  deliver/accept/reject commands cannot substitute for a DAO decision.
- The coordinator sees missing decisions, rejects, approval quorum, impossible
  quorum, deadline closure, and each item's independent delivery/receipt state.
- An exported certificate contains the signed manifest and distinct approval
  signatures. It omits private evidence and policy bytes. Verification needs no
  identity key, state directory, body store, wallet, or network access.

## Authority and explicit membership

A manifest's reviewer list is an **explicit roster for this exact review**. It
is not evidence that those keys are legal members of a real DAO. Before voting
or trusting a certificate, authenticate the full manifest and its exact review
hash through the DAO's existing governance channel. Check the coordinator key,
DAO/proposal identifiers, epoch, reviewers, evidence/policy commitments, dates,
and threshold against the authorized membership snapshot.

Both `decide` and `verify` require `-expect-review-hash sha256:...`. Obtain it
**independently**; copying it from an untrusted certificate defeats this trust
boundary. The exact signed-manifest hash pins the whole roster and policy,
not merely a coordinator name. A changed roster, epoch, threshold, evidence,
policy, or deadline requires a new manifest and a new authenticated hash.
There is no wildcard pin or automatic acceptance of a certificate's own roster.

DAO namespace and proposal ID are caller-defined labels, not globally resolved
names. Include your chain/network/contract context in the DAO label or private
policy when it matters. A Spore messaging pin is not a Relay actor ID or wallet
control proof. The coordinator is excluded from the reviewer roster; distinct
reviewers must have distinct signing pins **and** distinct addresses. Distinct
keys are not proof of distinct humans (Sybil resistance is outside this tool).

## Requirements and limits

Each endpoint needs a normal Spore config (`identity`, `spk`, `state_dir`,
`state_key`, `maildb`, `store`, `address`, and applicable carrier options).
Exchange signed invites, independently pin contacts, and establish normal E2
sessions between coordinator and every reviewer first. Review commands never
bootstrap sessions, silently change pins, or downgrade encryption. Blocked,
missing, invalid, or changed contact bundles/sessions fail closed.

Use `-address` or `-handoff-address` for the exact address the peer has pinned.
Reviewers need only the coordinator as a contact, not one another.

Bounds and rules:

- **1–16 reviewers**, equal one-key/one-vote weight. Threshold must be a strict
  majority: `floor(N/2)+1 .. N`. No weighted votes, abstentions, delegations,
  veto rules, or coordinator self-review. A reject is a non-approval, not an
  automatic veto unless the configured threshold makes quorum impossible.
- **16 KiB evidence** maximum. The signed manifest **plus** base64-encoded
  private policy must fit the handoff's **8 KiB policy field**; the usable policy
  size shrinks with roster/address lengths. Oversize packets fail before queueing.
- Deadline is positive and before expiry. Default **48h deadline**, **168h
  expiry**, maximum **720h expiry**. No new decisions at/after the deadline.
  Previously signed decisions can arrive and form a certificate after the
  deadline, but before expiry. Expired certificates fail verification.
- Handled by the existing **8 MiB / 128-record** encrypted handoff store;
  **each reviewer consumes one record**. Certificate/manifest exports and parser
  input are capped at **64 KiB**. All artifacts reject unknown fields, duplicate
  keys (including case aliases), nulls, excessive nesting, and trailing values.
- One final decision per review/key in the retained local history. No edit,
  amendment, revocation, automatic reelection, or reopen; start a new review
  epoch/manifest for changed terms. There is no global monotonic epoch registry.

## Coordinator: create and distribute

Write the exact private proposal/evidence and review policy as local files.
Their SHA-256 commitments cover **all bytes**, including newlines. A short
packet can include commitments to larger supporting artifacts, but Spore does
not automatically fetch or verify those external artifacts: reviewers must
explicitly check what the policy requires.

```sh
spore dao-review create -config coordinator.json \
  -dao chain:network:dao-contract -proposal proposal:42 -epoch 7 \
  -to reviewer-a -to reviewer-b -to reviewer-c -threshold 2 \
  -evidence-file evidence.bin -policy-file review-policy.txt \
  -deadline 48h -expires 168h -out proposal-manifest.json
```

This **queues locally** and writes an exclusively created mode-0600 manifest
file. It prints the signed review hash. No proposal is posted publicly and no
RelayOS registration is claimed. Handoff registration metadata is explicitly
`source: "local-dao-review"` with no Relay URL/actor, not a fabricated server
observation. Existing RelayOS-backed handoffs retain their old behavior.

Authenticate/distribute the manifest hash through your DAO governance channel,
then explicitly post the encrypted invitations:

```sh
spore dao-review status -config coordinator.json
spore dao-review flush -config coordinator.json
```

Carrier flags/config work as for `work-order handoff flush`. Each reviewer
receives via `spore msg recv-e2 -config reviewer.json`. The shared fabric receive
pipeline also handles these same continuation messages; the usual initial-session
bootstrap fence remains. No new hosted service or API key is introduced.

The exported manifest file and encrypted queue are separate filesystem writes:
normal errors remove the newly created manifest if queueing fails, but a process
exit between them can leave a manifest with no queued invitations. A manifest
file alone is not proof of queueing or delivery—inspect `status`. Do not reset
ratchet state or hand-edit outbox markers to repair interrupted queue/delivery.

## Reviewer: inspect and explicitly decide

```sh
spore msg recv-e2 -config reviewer-a.json
spore dao-review status -config reviewer-a.json
spore dao-review show -config reviewer-a.json -id HANDOFF_ID

# Explicit plaintext exports for human inspection; no overwrite or execution.
spore dao-review export -config reviewer-a.json -id HANDOFF_ID \
  -artifact brief -out review-evidence.bin
spore dao-review export -config reviewer-a.json -id HANDOFF_ID \
  -artifact policy -out review-policy.txt

# Review the exact evidence AND policy, authenticate the expected hash, then:
spore dao-review decide -config reviewer-a.json -id HANDOFF_ID \
  -expect-review-hash sha256:INDEPENDENTLY_AUTHENTICATED_HASH -approve
# Or use -reject instead; exactly one choice is required.
spore dao-review flush -config reviewer-a.json
```

`status` labels reviewer tallies **reviewer-local-view**, never a DAO-wide
result. It prints the stable handoff ID for inspection/decision. `show` returns
the signed handoff record as JSON; byte fields are base64. The `brief` export
returns exact evidence bytes; `policy` returns the original human policy bytes,
not its enclosing signed packet; `result` exports the signed reviewer decision.
Protect/delete exports yourself: they are plaintext copies outside retention.

The decision is signed and queued, not sent until explicit `flush`. A reviewer
cannot sign another reviewer's invitation. An exact retry of an incoming event
is idempotent; a second/conflicting decision cannot replace the stored one.
The coordinator receives decisions with the same `msg recv-e2` command.

Private packets are not indexed into normal mail snippets, written as automatic
attachments, sent to notification providers, or executed. Persistence receipts
are queued atomically and show that a peer's key acknowledged storing the exact
packet. They do **not** mean a human read or approved it. Review decisions and
persistence receipts remain separate, with no acknowledgement loops.

## Coordinator: tally and export a certificate

```sh
spore dao-review status -config coordinator.json
spore dao-review flush -config coordinator.json   # send queued persistence receipts

spore dao-review certificate -config coordinator.json \
  -expect-review-hash sha256:INDEPENDENTLY_AUTHENTICATED_HASH \
  -out quorum-certificate.json
```

Status distinguishes `awaiting-decisions`, `approval-quorum-met`,
`approval-quorum-impossible` (too many rejects to reach the threshold), and
`deadline-closed-no-quorum`. Missing decisions are listed by the immutable
roster. Carrier-posted and peer-persisted statuses are shown independently.
A reviewer-local view does not claim knowledge of other reviewers' decisions.

Export fails without enough distinct approvals, on a conflicting/invalid local
decision, if expired, if the trusted hash differs, or if the destination already
exists. Rejections remain in encrypted local audit history but are **not**
counted as approvals or included in an approval certificate. Every certificate
approval is independently verified; the collector cannot fabricate a missing
signature. Quorum can be certified before the deadline once enough approvals
arrive: later honest rejections cannot subtract already-final approvals.

## Anyone with the authenticated hash: verify offline

```sh
spore dao-review verify -certificate quorum-certificate.json \
  -expect-review-hash sha256:INDEPENDENTLY_AUTHENTICATED_HASH
```

A successful result means: *these distinct selected signing keys approved this
exact signed manifest within its declared review window, and it has not expired
according to this machine's clock*. The verifier checks coordinator signature,
manifest constraints, exact trust pin, each reviewer's membership/signature,
invitation and review bindings, timestamps, canonical ordering, distinctness,
and threshold. Neither coordinator state nor evidence plaintext is required.

Certificate schema:

```json
{
  "domain": "spore/dao-review/certificate/v1",
  "version": 1,
  "review": {
    "domain": "spore/dao-review/manifest/v1",
    "manifest": {
      "version": 1,
      "id": "32-lowercase-hex",
      "dao": "chain:network:dao-contract",
      "proposal": "proposal:42",
      "epoch": 7,
      "coordinator": {"address": "...", "pinned_sig": "..."},
      "evidence_hash": "sha256:...",
      "policy_hash": "sha256:...",
      "reviewers": [{"address": "...", "pinned_sig": "..."}],
      "threshold": 2,
      "created_at": 1900000000,
      "deadline": 1900172800,
      "expires_at": 1900604800
    },
    "signature": "128-lowercase-hex"
  },
  "approvals": [{
    "domain": "spore/dao-review/decision/v1",
    "decision": {
      "version": 1,
      "review_hash": "sha256:...",
      "handoff_id": "32-lowercase-hex",
      "brief_hash": "sha256:...",
      "reviewer": {"address": "...", "pinned_sig": "..."},
      "choice": "approve",
      "at": 1900000060
    },
    "signature": "128-lowercase-hex"
  }]
}
```

This is a shape illustration, not a valid quorum fixture. Manifest and decision
signatures cover `domain + NUL + deterministic typed JSON(body)` using existing
identity-derived Ed25519 keys. Roster and certificate approvals are sorted by
lowercase signing pin. SHA-256 hashes are `sha256:` plus lowercase hex; the
review hash covers the whole signed manifest, including its signature. The
invitation ID is the first 16 bytes of SHA-256 of typed JSON containing the
review hash and reviewer identity, preventing a second invitation history for
one key/review from being silently substituted. Decision signatures bind that
ID and the original signed brief's hash. Certificate verification validates the
signed manifest commitments, not the private opening of evidence or policy;
those openings were checked by the reviewer-side protocol.

## Privacy, recovery, and honest limits

- The reviewer roster is intentionally disclosed **to all selected reviewers**
  and to anyone given a manifest/certificate. Certificates also expose which
  keys approved, proposal/epoch labels, commitments, and signature timestamps.
  They contain no evidence/policy bytes. Do not publish them accidentally.
- Hashes of low-entropy private artifacts can be guessed. Commitments are not
  zero-knowledge proofs or guaranteed hiding commitments; include unpredictable
  context in private artifacts when dictionary guessing matters.
- One key should approve at most once; honest local state enforces that, but a
  malicious reviewer can use copied/rolled-back state to equivocate. Duplicate
  keys/conflicts supplied to a collector are rejected. An offline certificate
  cannot prove absence of withheld conflicting votes. This is not BFT consensus,
  a distributed append-only ledger, a revocation service, or global uniqueness
  enforcement for DAO/proposal epochs. A strict majority prevents disjoint
  honest quorums; it does not repair compromised/equivocating keys.
- Decision timestamps are signer assertions. CLI signing rejects the deadline,
  and verification rejects timestamps outside the window or in its own future,
  but there is no chain timestamp, trusted-time attestation, or cryptographic
  proof that a malicious signer did not backdate. Keep clocks correct.
- Receipts show application persistence, not independent evidence validation.
  Certificate verification proves signatures and scoped quorum, not proposal
  truth, human identity, policy compliance, wallet ownership, or lawful authority.
- No on-chain commitment posting occurs. Publish/authenticate the manifest hash
  separately through the DAO's approved mechanism. **Nothing consumes this
  certificate to spend funds or mutate a contract/RelayOS state.** A future
  execution gate must revalidate the exact proposal, fresh authorized membership,
  expiry/revocation rules, and separately scoped spending capability.
- This uses existing `handoffs.enc`, encrypted `receive-pending.enc` crash
  recovery, exact-pointer send retry, and private state key. Use one owner per
  ratchet directory; do not run independent send/receive/import processes over
  stale shared ratchet snapshots. A pending recovery blocks new transitions.
  See [PRIVATE_HANDOFF.md](PRIVATE_HANDOFF.md) for crash windows, stale locks,
  explicit CID discard, pre-journal delivery limits, and `panic` semantics.
- `dao-review recover` and `dao-review flush` delegate to handoff recovery and
  transport and may process **other handoffs in that same local store**.
  `dao-review prune` removes all expired handoffs there. Successful store access
  prunes expired review histories; exported certificates/manifests and plaintext
  artifacts are separate copies and are not automatically erased. Older binaries
  do not understand `local-dao-review` registration metadata; upgrade all parties.
- Self-hosting introduces no new mandatory paid service. Infrastructure and
  on-chain postage can cost money. No delivery or availability guarantee exists.

## Conformance vectors for independent verifiers

The deterministic fixtures are language-neutral:

- [`dao-review-certificate-v1.json`](../internal/daoreview/testdata/conformance/dao-review-certificate-v1.json)
  has the review hash, canonical manifest JSON, exact manifest signing input in
  hex, and 22 certificate cases (3 accept, 19 reject). Each case provides a
  base64 certificate, trusted expected review hash, verification time, and
  `accept`/`reject` expectation; accepted cases state the approval count.
- [`dao-review-handoff-v1.json`](../internal/daoreview/testdata/conformance/dao-review-handoff-v1.json)
  has 14 cases for signed briefs, reviewer decisions, and brief/deliver record
  chains (3 accept, 11 reject). Envelopes and decisions are standard-base64 JSON.

Replay both files with the independent, standard-library-only Python verifier:

```sh
python3 scripts/verify-dao-review-vectors.py
python3 scripts/verify-dao-review-vectors.py --verbose
```

It prints a total and exits nonzero on disagreement. The verifier includes an
RFC 8032 Ed25519 known-answer self-test, validates signature domains and
canonical typed JSON, opens the exact evidence/policy commitments in briefs,
checks explicit membership and invitation IDs, and validates decision-to-brief
chain bindings. It requires Python 3.10+ and has no third-party dependencies.
It is a conformance tool—not production crypto code or a general-purpose Spore
parser.

Coverage: a valid two-of-three certificate, a three-approval certificate, and
acceptance after the deadline but before expiry. Negative cases are wrong or
malformed hashes, expiry, pre-creation time, below-quorum, duplicate reviewer,
rejection listed as approval, non-canonical order, outsider key, decision at the
deadline, future decision, tampered approval signature, tampered epoch with a
recomputed hash, a correctly signed minority threshold, wrong domain, unknown
field, duplicate key, null version, and trailing JSON. Each negative case changes
one thing, so a verifier that accepts it has a specific rule gap.

Canonical bytes are Go `encoding/json` output of the structs: declared field
order, no insignificant whitespace, and HTML-safe escaping of `<`, `>`, `&`,
U+2028, and U+2029. Signatures cover `domain + NUL + canonical body`. Handoff
`[]byte` values are base64-encoded JSON strings; the handoff-envelope hash is
SHA-256 over the full typed envelope JSON, including its signature. Sort reviewers
and approvals by lowercase pin. A verifier must reproduce the fixture's manifest
signing input and review hash before evaluating certificate cases.

The generator is test-only. The test regenerates the file in memory and fails on
any byte drift. Regenerate only after an intentional encoding change, with
`SPORE_UPDATE_DAO_REVIEW_VECTORS=1 go test ./internal/daoreview -run TestDAOReviewConformanceVectors`.
The window cases share one error message, so the vectors check accept/reject
outcomes, not message text.

## Local evidence

Tests cover fixed membership, distinct pins/addresses, self-review exclusion,
strict-majority bounds, signed commitment/epoch immutability, reviewer identity,
wrong invitation/policy/evidence, deadlines/expiry/future timestamps, rejection
handling, duplicate/equivocating decisions, self-selected trust pins, strict
JSON decoding, certificate sorting, plaintext omission, packet limits, and atomic
queue rollback. A compiled CLI test runs one coordinator and three independent
identity/state directories over existing local HTTP E2 stores/carrier fixtures:
private invitations, injected receive-write failure and body-free recovery,
missing-decision status, explicit human-policy export, two approve/one reject,
persistence receipts, certificate export, and keyless offline verification.

This is local verification, not a funded-chain DAO deployment, external crypto
review, independent live operators, proof of governance legitimacy, or live
RelayOS integration. No RelayOS server files are changed by this feature.
