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
