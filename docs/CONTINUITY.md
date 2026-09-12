# Continuity vault

> **Security model:** this is an explicit, local recovery protocol. It is not
> proof of death or incapacity, does not custody funds, and does not perform
> automatic spending, credential rotation, or irreversible actions.

`spore continuity` is the first dead-man continuity slice. It is an explicit,
local, encrypted release workflow—not an automatic wallet or fund executor.

## What it does

1. `create` encrypts a payload with a random content key.
2. That content key is wrapped separately to each designated X25519 recipient.
3. The owner signs a genesis check-in and every later check-in.
4. `status` evaluates the latest signed deadline.
5. After the deadline, a designated recipient explicitly runs `release`.

The vault JSON contains encrypted payload data, public keys, recipient envelopes,
commitments, and signed check-in records. It contains no plaintext payload and
no private key. Vault and released-payload files are written through an atomic
temporary-file replacement and requested with private permissions.

## Example

```sh
# owner-key contains exactly 64 hex characters; keep it private
spore continuity create \
  -owner-key ./owner.key \
  -recipient-pub RECIPIENT_X25519_PUBLIC_KEY_HEX \
  -file ./sealed-instructions.txt \
  -out ./continuity-vault.json \
  -interval 24h -grace 24h

# run before the current deadline
spore continuity check-in \
  -vault ./continuity-vault.json \
  -owner-key ./owner.key

spore continuity status -vault ./continuity-vault.json

# recipient performs this only after the deadline
spore continuity release \
  -vault ./continuity-vault.json \
  -recipient-key ./recipient.key \
  -out ./released-instructions.txt
```

`-at UNIX` exists for deterministic inspection and recovery testing. It is not
a time oracle. If the owner misses the deadline, a late check-in is rejected and
cannot move the deadline forward.

## Security boundary

- No chain transaction is posted.
- No wallet RPC is contacted.
- No money is moved.
- No recipient is contacted automatically.
- Release is explicit and local.
- The vault does not prove that a person is dead or incapacitated; it proves
  only that a signed check-in deadline was missed.
- A holder of a recipient private key can release after the deadline.
- Anyone with the vault can see metadata and ciphertext, but cannot decrypt it
  without a designated recipient key.
- The owner key is used to derive a separate signing key for check-ins. This is
  a v1 convenience boundary; a future v2 can use an independently provisioned
  signing key and threshold release observers.

## Explicit v1 boundary

The observer, N-of-M quorum, and optional chain-anchor features below are
implemented, but they remain explicit local workflows. This v1 intentionally
does not claim:

- an always-on observer scheduler or hosted monitoring service;
- automatic notifications or recovery orchestration;
- automatic key rotation, credential revocation, wallet spending, or other
  irreversible actions;
- chain finality beyond the chain's own confirmation/reorg behavior;
- legal proof of death, incapacity, or succession.

A continuity artifact proves only the signed state and deadline it contains. It
does not prove a person's death or incapacity. Production operation still
requires independently protected vault copies, observer availability, and a
human recovery procedure.

## Observer slice

The observer layer is now available:

```sh
# generate an independent observer signing key
spore continuity observer-keygen -out ./observer.key

# inspect the vault file and emit a signed release-ready notice after due time
spore continuity observe \
  -vault ./continuity-vault.json \
  -observer-key ./observer.key \
  -out ./release-notice.json

# verify the notice signature and bind it to the exact vault state
spore continuity verify-notice \
  -notice ./release-notice.json \
  -vault ./continuity-vault.json
```

The observer reads the vault file's non-secret metadata, ciphertext, commitments,
and signed check-in chain. The vault is not a public transaction record, and the
observer still needs access to the vault file or a trusted copy. It does **not**
receive recipient private keys, payload plaintext, or wallet authority. The
notice is a signed fact that the observer saw a particular vault deadline pass;
it is not proof of death or incapacity, and it does not release the payload by
itself.

## N-of-M observer release

The quorum layer is now available. Create a policy listing approved observer
public keys and a threshold, then collect independent attestations:

```sh
spore continuity quorum-create \
  -vault ./continuity-vault.json \
  -threshold 2 \
  -attester-pub OBSERVER_A_PUB,OBSERVER_B_PUB,OBSERVER_C_PUB \
  -out ./quorum-policy.json

spore continuity attest \
  -vault ./continuity-vault.json \
  -policy ./quorum-policy.json \
  -observer-key ./observer-a.key \
  -out ./attestation-a.json

spore continuity quorum \
  -policy ./quorum-policy.json \
  -attestations ./attestation-a.json,./attestation-b.json \
  -out ./quorum-release.json

spore continuity verify-quorum \
  -quorum ./quorum-release.json \
  -vault ./continuity-vault.json

spore continuity release-quorum \
  -vault ./continuity-vault.json \
  -quorum ./quorum-release.json \
  -recipient-key ./recipient.key \
  -out ./released-instructions.txt
```

A quorum policy binds the exact vault ID, vault payload commitment, owner signing
key, check-in sequence, and deadline. A later owner check-in makes the policy stale;
old attestations cannot be replayed. The quorum bundle contains notices and
signatures only—never plaintext, recipient private keys, or wallet authority.
Release remains explicit and local.

No observer can release alone, and this still does not prove death or incapacity.
It proves only that the threshold of independent observers signed the same
missed-deadline epoch.

## Optional chain anchoring

A policy/deadline commitment can be created and checked without network access:

```sh
spore continuity anchor-create \
  -vault ./continuity-vault.json \
  -policy ./quorum-policy.json \
  -out ./continuity-anchor.json

spore continuity anchor-verify \
  -anchor ./continuity-anchor.json \
  -vault ./continuity-vault.json \
  -policy ./quorum-policy.json
```

The anchor commits to the vault ID, quorum-policy ID, signed check-in sequence,
and deadline. The DERO wire form carries only the two opaque 32-byte IDs plus
the deadline and sequence metadata. DERO's message field is recipient-encrypted,
so this is not a public transaction-metadata commitment; it contains no
plaintext, ciphertext, recipient key, or wallet authority. A later owner check-in
makes the anchor invalid against the current vault.

Posting is deliberately separate and explicit:

```sh
spore continuity anchor-post \
  -anchor ./continuity-anchor.json \
  -vault ./continuity-vault.json \
  -policy ./quorum-policy.json \
  -to DERO_DESTINATION \
  -rpc http://127.0.0.1:20209/json_rpc \
  -ringsize 16 \
  -receipt ./continuity-anchor-receipt.json
```

`anchor-post` is the only command in this slice that contacts a wallet. It
re-verifies the anchor against the current vault and policy immediately before
posting, uses minimum postage, and never runs automatically during observation,
quorum assembly, or release. It does not move the continuity payload or release
funds. The optional receipt records the exact txid, anchor identifiers, ring
size, posting time, and digest of the canonical wire payload; it contains no
plaintext or private key.

To verify wallet-history readback of the exact payload:

```sh
spore continuity anchor-check \
  -receipt ./continuity-anchor-receipt.json \
  -anchor ./continuity-anchor.json \
  -rpc http://127.0.0.1:20209/json_rpc
```

`anchor-check` proves that the wallet history returned the exact continuity
payload for that txid. It does not prove confirmation depth, finality, or
absence of future chain reorgs.

The chain remains an optional timestamp/commitment carrier, not a liveness
oracle and not proof of death or incapacity.
