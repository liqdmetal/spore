# Spore Carrier Matrix

Spore carries only the canonical 0xE2 pointer on permanent or semi-permanent
transports. X3DH handshake data, ratchet headers, and ciphertext remain in the
TTL-bound off-chain body store. A carrier that cannot carry the pointer must
return an explicit unsupported error; it must never downgrade to a legacy
one-shot message.

## Current and planned carriers

| Carrier | Pointer transport | Body lifecycle | Delivery discovery | Burn/erase semantics | Status |
|---|---|---|---|---|---|
| DERO | Typed native payload | Off-chain TTL/reaping | Wallet/chain scan | Native payload is immutable; pointer remains | Live E2 path |
| EVM | Mailbox contract payload | Off-chain TTL/reaping | Contract mailbox | `burn(to, seq)` after delivery when enabled | Live E2 path |
| Solana | Mailbox-program payload | Off-chain TTL/reaping | Inbox account scan | `burn(idx)` after delivery when enabled | Live E2 path |
| Monero | Existing payment-ID seam is too small | Off-chain TTL/reaping | Authenticated rendezvous required | No pointer burn in current seam | Explicitly unsupported for direct E2 pointer |
| Nostr | Signed event content containing pointer | Relay retention/deletion is best-effort | Relay pool + recipient tag | NIP-09 deletion request, best-effort | Carrier implementation |
| Bitcoin | `OP_RETURN` output, maximum 80 bytes | Off-chain TTL/reaping | Esplora-compatible indexer | Immutable; body-only compost | Carrier implementation |
| Cosmos SDK chains | Configured memo/message field | Off-chain TTL/reaping | Configured LCD/RPC/indexer | Chain-specific; no generic burn claim | Configurable carrier seam |
| TON | Configured comment/payload field | Off-chain TTL/reaping | Configured API/indexer | No generic burn claim | Configurable carrier seam |

## Carrier invariants

1. The carrier receives canonical pointer bytes only; it never receives
   plaintext or ratchet ciphertext.
2. Pointer parsing is strict: version, route handle, CID, and nonzero expiry
   must all be valid.
3. Incoming records that are not valid E2 pointers are rejected as legacy or
   unsupported. They are not reinterpreted.
4. Body expiry is independent of the permanent carrier record. Deleting an
   off-chain body does not erase an immutable chain transaction.
5. A delete/burn operation is not claimed unless the underlying transport has
   a real deletion primitive. Best-effort relay deletion is not the same as
   chain erasure.
6. Every new conversation uses E2. DERO-native short whispers, E1, and the
   old one-shot long-body path remain compatibility modes only.

## Deployment order

1. Nostr: lowest fee and infrastructure barrier; validate relay-pool behavior
   and deletion semantics first.
2. Bitcoin: strongest settlement/censorship-resistance anchor; develop on
   signet/testnet before mainnet, and enforce the 80-byte pointer ceiling.
3. Cosmos: integrate one configured SDK chain through an explicit memo/message
   profile before claiming generic IBC-wide support.
4. TON: integrate one explicit API/indexer and wallet sender profile before
   claiming universal TON transaction support.

Cosmos and TON are deliberately profiles/seams rather than invented universal
backends. Each supported profile must document its exact transaction endpoint,
message field, indexer query, fee behavior, and whether delivery is final.

## Prekey bundle discovery

`spore msg send-e2` accepts a recipient's public X3DH bundle two ways:

- `-bundle FILE.json` — a bundle saved to disk out-of-band (e.g. shared over
  a separate secure channel).
- `-bundle-url URL [-bundle-token TOKEN]` — fetched live via `GET /prekey`
  from the recipient's mailbox (`internal/mailbox`'s `PUT/GET /prekey`
  route), optionally through a bearer-token-gated `HandlerToken` mailbox.

These are mutually exclusive; the CLI refuses both or neither. Discovery is
a transport convenience only, never a trust boundary substitute:
`EstablishInitiator` still verifies the fetched bundle's `SPK_sig` against
the caller-supplied `-pinned-sig`, so a compromised or malicious mailbox can
at worst withhold or serve a stale bundle (causing `send-e2` to fail loudly)
— it cannot forge a bundle that passes signature pinning, and the discovery
request is a bodyless GET that never carries plaintext, ciphertext, or any
private key material.

### Single-use batches (the OPK guarantee at the serving layer)

`PUT /prekey-batch` accepts N **pre-signed public bundles** (generated offline
by `spore prekeybatch gen` — the identity/SPK private keys never reach the
mailbox). `GET /prekey` **pops one bundle per request** (durable before the
response), so two senders can never receive the same one-time prekey. On
exhaustion the mailbox falls back to the static `/prekey` bundle when one was
published (degraded 3-DH mode, documented in `docs/RATCHET.md` §10), else 404.
Restart never resurrects a popped bundle.

## Value carriage (pay-with-message)

`chain.PostPayload` takes an `amountHint`: native transfer value rides the
SAME tx as the pointer — money and message are atomic (both land or neither
does). Per-carrier truth:

| Carrier | `-amount` | Mechanism |
|---|---|---|
| DERO | ✅ supported | `PostPayloadAmount` (atomic units; 1 DERO = 100000). Wire-tested. |
| EVM | ✅ supported (calldata path) | tx `value` in wei. The mailbox-contract path is NOT payable; the E2 carrier uses the calldata path. |
| Bitcoin | ❌ refused | backend discards the hint (dust-output value wiring not done) — the CLI refuses `-amount` rather than silently underpaying |
| TON | ❌ refused | backend discards the hint (value-bearing message not wired) |
| Nostr / Cosmos / Solana / XMR | ❌ refused | relays hold no value / memo seam / program mailbox / no E2 |

In-thread settlement (`msg invoice` / `msg pay`) rides the same rails: an
invoice is a ratcheted envelope; `pay` attaches the value AND posts a
payment envelope referencing the invoice id, so the proof of payment is
end-to-end encrypted like everything else.
