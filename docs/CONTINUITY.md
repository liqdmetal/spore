# Continuity vault

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

## Not yet included

This slice intentionally does not claim:

- an always-on heartbeat observer;
- threshold/N-of-M recipient release;
- chain-anchored commitments or deadlines;
- automatic notifications;
- automatic key rotation, credential revocation, or wallet actions;
- legal proof of death, incapacity, or succession.

Those are separate protocol and operational features. The next safe extension is
an observer that verifies the signed vault and publishes only a release-ready
notice; it must not receive private keys or plaintext.
