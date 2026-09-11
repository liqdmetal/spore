# Spore roadmap — what's shipped, what's left

*Authoritative per-carrier status lives in
[`README.md`](README.md#chain--carrier-status) and
[`docs/CARRIER_MATRIX.md`](docs/CARRIER_MATRIX.md). This roadmap tracks done vs.
remaining; it does not re-state live status.*

## Shipped

### Transport + privacy core
- **m³ chain seam** (`internal/chain`): `Chain` + `Watch` + `Burner`. Core has
  zero chain-specific dependency (proven by mock chain + 7 real backends).
- **DERO** — whisper (no-relay unicast), long bodies, rooms, browser UI.
  Live, mainnet-verified.
- **EVM / Solana** — mailbox delivery + auto-burn after receipt. Solana program
  v3 live on mainnet; EVM verified on anvil (deploy pending).
- **E2 secure layer** (`internal/secure`, `0xE0` envelope) for public chains.
- **X3DH + Double Ratchet** (`internal/ratchet`, `internal/ratchetwire`, `0xE2`):
  forward-private, post-compromise healing, AAD-bound to the session, ratchet
  rollback on failed decrypt. Interop vectors in `docs/`.
- **Multi-device sync** (`e2-device`): encrypted state export/import, durable
  device ledger, collision detection, and fail-closed sends on flagged sessions.

### Compostability
- Off-chain TTL body store (`internal/store`), crash-safe write ordering.
- EVM `burn(to,seq)` + Solana `burn(idx)` after delivery; `chain.Watch`
  auto-burn.
- Durable encrypted local ratchet state with append-only anti-rollback log.
- `maildb` purge + `spore panic` verifiable local wipe.
- **Continuity vault v1:** encrypted recipient-wrapped payload, signed check-in
  chain, deterministic missed-deadline evaluation, and explicit local release.
  See [`docs/CONTINUITY.md`](docs/CONTINUITY.md). No automatic fund movement.
- **Continuity observer v1:** independent Ed25519 observer keys and signed
  release-ready notices bound to an exact vault state. Observers see no plaintext,
  recipient keys, or wallet authority.

### Continuity vault — next protocol slices
- N-of-M recipient or observer release, with independent operators.
- Optional chain commitment for policy/deadline anchoring.
- Notification and recovery UX without handing plaintext or keys to a service.
- No automatic wallet spending or irreversible account actions.

### Carriers (all carry the same opaque 74-byte pointer, no downgrade)
- **Nostr** (signed events, NIP-09 best-effort delete), **Bitcoin**
  (`OP_RETURN` ≤80B, signer-injected), **Cosmos** (configurable memo seam),
  **TON** (configurable comment seam). XMR refused for E2 (8-byte seam too
  small) rather than downgraded.

### Email-class features
- Delivery receipts, `reply-e2`, `forward-e2`, session/thread listing.
- Attachments (`-out-dir` / `-msg-file`), ntfy notifications (metadata only).
- Offline compose queue (`compose`/`flush`), HMAC-sealed + path-contained.
- Local `maildb`: contacts + allowlist, threads, tokenized/scoped/highlighted
  search.

### Settlement (the moat)
- **Pay-with-message**: `-amount 5.5dero` rides the SAME atomic tx as the
  pointer (DERO + EVM-calldata; wire-tested). Other carriers refuse `-amount`
  rather than silently underpay.
- In-thread **invoice / payment** envelopes (`msg invoice`, `msg pay`).

### Onboarding + ops
- `spore init` one-shot identity kit + `config.json` defaults (every E2 command
  picks them up; explicit flags always win).
- **Single-use prekey batches**: offline `prekeybatch gen` (identity key never
  leaves the device), `push` to the mailbox, `GET /prekey` pops one bundle per
  sender. Restart never resurrects a popped bundle.
- `relay run` with authenticated mailbox hop + per-body exponential backoff.
- `status` / `doctor` health + preflight.

## Remaining (honest, rough priority order)

| # | Item | Why it's gated / what it needs |
|---|---|---|
| 1 | **Serverless bodies over `spore-peer`** | E2 off-chain bodies ride the HTTP mailbox today. Wiring E2 frame fetch to the P2P peer transport removes the last always-on-server dependency for body delivery. The peer repo (`liqdmetal/spore-peer`, Rust) predates E2 and carries no ratchet — needs an E2 body-fetch adapter. |
| 2 | **Escrow + swap in chat** | Wire `msg` to the live sap escrow / relay-dex HTLC contracts (SC-call seam in the CLI). Contracts are mainnet-live; this is integration, not new crypto. Enables settlement rake (docs/BUSINESS.md line 2). |
| 3 | **Tokenized search** | maildb search is substring + AND/NOT/phrase/scope today. A real inverted index (AND/OR, phrase, sender-scoped) is the next depth. |
| 4 | **Bitcoin/TON value carriage** | Their `PostPayload` discards the amount hint today, so `-amount` is refused on them. Real support needs Bitcoin dust-output + fee/UTXO wiring and a TON value-bearing message. |
| 5 | **Deploy `MyceliumMailbox.sol`** | Written + backend proven; needs a funded EVM account on a real chain. |
| 6 | **Solana cross-wallet delivery** | Program requires recipient to sign; client currently self-messages. Both parties must run the backend. |
| 7 | **XMR live-verify** | Pruned `monerod` syncing; needs a real `monero-wallet-rpc`. Scope stays short-signal + off-chain rendezvous (no native payload encryption, no E2 pointer). |
| 8 | **L1 mempool catch (~1–2s)** | Rust scanner on derohe-rs watches the node txpool and decrypts before mining. |
| 9 | **Relay fabric interconnection** | Relay nodes forwarding encrypted pointer/body across a substrate mesh (Waku/Iroh/libp2p). |
| 10 | **More chains** (Zcash / ARRR / Decred / Verge) | Each a `chain.Chain` backend reusing the envelope/relay pattern. |
| 11 | **Cross-chain identity proof** (DERO↔EVM) | Research crypto — the hard piece. Gates true interchain messaging. |

## Honest notes
- Items #1–3 are the real product leaps (no-server bodies, multi-device,
  in-chat settlement); #6–12 are integrations with real-node dependencies or
  research, not "tonight" work.
- Where a chain has no native encrypted rail, m³ supplies secrecy — the
  tradeoff is metadata (a tx/event/inbox record exists) stays visible at that
  layer, same as DERO whisper's honest limit.
- **Cross-chain direct messaging is impossible** (different key crypto).
  Cross-chain = rendezvous/relay + identity proof (#12), signaling + handoff.
- Group *broadcast* still needs a relay or an SC — no-relay is unicast by
  construction.
- **Immutable carriers keep the pointer scrap forever.** Compostability is
  cryptographic (bodies rot, local state wipes), not chain-erasure. No protocol
  can promise otherwise; we don't.
