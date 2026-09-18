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
- **Continuity quorum v1:** thresholded N-of-M independent attestations bound to
  the exact check-in epoch; quorum-gated recipient release remains explicit and
  non-custodial.
- **Continuity watch v1:** signed local watch checkpoints, one metadata-only
  release-ready event per exact epoch, and durable at-least-once notification
  retry through the existing outbox. No automatic release or wallet action.

### Serverless body transport (spore-peer)
- **`sporepeer://` store backend** (`internal/peerstore`): E2 bodies ride the
  P2P peer transport instead of the always-on HTTP mailbox. Bidirectional —
  a sender's node holds and serves,  recipient fetches by CID — with `sha256 == cid` verified on both sides of
  the socket. Wire frames are specified in
  [`docs/WIRE_SPEC.md`](docs/WIRE_SPEC.md) §5; setup in
  [`docs/PEER_SETUP.md`](docs/PEER_SETUP.md).
- **`spore serve` daemon** (`cmd/spore/serve`): long-lived hold with graceful
  drain, loopback-by-default binding, and `-reap-every` background composting
  on top of read-time `410 gone` enforcement. Drop-in with the Rust
  `spore-peer serve --dir` in both directions.
- **Cross-binary interop, both directions, gated:** a real Rust
  `spore-peer fetch` from a Go-served hold, and a Go client against a real
  Rust server — including the verbatim `404 not found` / `410 gone` error
  strings crossing the binary boundary — run in CI and locally via
  `scripts/gates.sh`.
- **Shared conformance vectors:** `docs/interop-vectors.json` is consumed by
  both implementations (Rust-side `spec_*` tests skip loudly only when the
  spore checkout is absent).
- **Hold-layout contract (§7):** `<cid>.body` / `.exp` / `.expms` with
  crash-safe write ordering and sub-second (millisecond) TTL precision that
  old and new binaries read compatibly.
- **Security review with hash-pinned remediations:**
  [`AUDIT-SPOREPEER.md`](AUDIT-SPOREPEER.md), enforced by the doc-refs CI
  check.

### Continuity vault — shipped protocol slices
- **Continuity chain anchor v1:** optional DERO commitment to the exact vault,
  quorum policy, check-in sequence, and deadline. Posting is explicit and
  re-verifies state immediately before the wallet call; no automatic action.
- **Strict artifact validation:** versioned continuity JSON rejects unknown and
  duplicate fields, trailing data, malformed bindings, stale epochs, and null
  identifiers.

### Continuity vault — remaining production slices
- Independent second-machine recovery drill with protected key transfer.
- Independent cryptographic review and controlled live-chain evidence.
- Notification deployment hardening beyond the explicit local watch/outbox workflow.
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
- **HTLC escrow funding in chat:** `-escrow htlc` locks `-amount` in the
  mainnet RelayHTLC contract with preimage-hash, recipient, and expiry
  (claim/refund and DEX swap surfaces remain — product row #1).

### Onboarding + ops
- `spore init` one-shot identity kit + `config.json` defaults (every E2 command
  picks them up; explicit flags always win).
- **Single-use prekey batches**: offline `prekeybatch gen` (identity key never
  leaves the device), `push` to the mailbox, `GET /prekey` pops one bundle per
  sender. Restart never resurrects a popped bundle.
- `relay run` with authenticated mailbox hop + per-body exponential backoff.
- `status` / `doctor` health + preflight.

## Remaining (honest, rough priority order)

### Production evidence gates before broader feature breadth

| # | Gate | Why it is required |
|---|---|---|
| P0 | Independent continuity protocol review | Local tests do not replace external cryptographic review. |
| P0 | Two-party live E2E and adversarial soak | Mainnet/self-message/local-Anvil evidence is not equivalent to independent-recipient production proof. |
| P1 | Recovery drill and protected vault-copy runbook | A continuity product must survive operator/device loss, not just decrypt in one test process. |
| P1 | Anchor live-chain evidence | Wallet-history readback is implemented; controlled funded posting and reorg/finality evidence remain. |
| P1 | Watch deployment hardening | Local metadata-only watch/outbox is implemented; scheduling, provider hardening, and recovery operations remain. |

Closed since drafting: **Windows CI and release provenance** (Windows
build+vet+test and `-race` jobs in CI; keyless SLSA attestation on release
artifacts) and **bounded parsers** (E2 wire bounds + fuzz-smoke targets;
continuity strict decode with size caps).

### Product roadmap after the evidence gates

| # | Item | Why it's gated / what it needs |
|---|---|---|
| 1 | **Finish escrow + swap UX in chat** | The contract seam is live: `internal/sap` (generated relay-dex bindings: HTLC fund/claim/refund, DEX swap, wrap/unwrap) and `-escrow htlc` funds a RelayHTLC from `msg` (`-escrow-hash/-escrow-recipient/-escrow-expiry`). Remaining: claim/refund flows in-thread, `-escrow dex` (DEXSwap/WrapDERO surfaces), and the operator rake collection (see docs/BUSINESS.md, "Line 2 — settlement rake"). |
| 2 | **Finish tokenized search execution** | The inverted index exists (`internal/maildb/inverted_index.go`: AND/OR/NOT/phrase) and the query grammar is wired — `SearchQuery{All,AnyOf,Not,Phrase,Peer,Thread,TxID}` and `mail search` with `-phrase/-peer/-thread/-txid` + highlighted snippets. Remaining: execute `Search` *through* the index (it still linear-scans messages and the index is maintained but unconsulted), surface OR/NOT via CLI flags, and make the index survive restart cheaply. |
| 3 | **Bitcoin/TON value carriage** | Their `PostPayload` discards the amount hint today, so `-amount` is refused on them. Real support needs Bitcoin dust-output + fee/UTXO wiring and a TON value-bearing message. |
| 4 | **Deploy `MyceliumMailbox.sol`** | Written + backend proven; needs a funded EVM account on a real chain. |
| 5 | **Solana cross-wallet delivery** | Program requires recipient to sign; client currently self-messages. Both parties must run the backend. |
| 6 | **XMR live-verify** | Pruned `monerod` syncing; needs a real `monero-wallet-rpc`. Scope stays short-signal + off-chain rendezvous (no native payload encryption, no E2 pointer). |
| 7 | **L1 mempool catch (~1–2s)** | Rust scanner on derohe-rs watches the node txpool and decrypts before mining. |
| 8 | **Relay fabric interconnection** — **shipped** | Relay nodes forwarding encrypted pointers across a mesh; bodies never touch the fabric (spore-peer carries them). F1 relay verbs, F2 Go client + `spore fabric subscribe` drain into E2 ingestion + `-route-fabric` on send, F3 drain-union dedupe + jitter + operator knobs — all **shipped** and adversarially reviewed ([`AUDIT-RELAYFABRIC.md`](AUDIT-RELAYFABRIC.md)); a real E2 send's pointer rides the fabric from real send to real drain in the gates. See [`docs/RELAY_FABRIC.md`](docs/RELAY_FABRIC.md): `freg`/`fput`/`fpop` on the spore-peer socket, epoch-salted fabric handles (rotation rides prekey-batch epochs, zero coordination via dual-publish), registration bound to contact-seed possession. F4 (transport adapters, cover traffic, onion publish) is designed in [`docs/RELAY_FABRIC_F4.md`](docs/RELAY_FABRIC_F4.md), not built. |
| 9 | **More chains** (Zcash / ARRR / Decred / Verge) | Each a `chain.Chain` backend reusing the envelope/relay pattern. |
| 10 | **Cross-chain identity proof** (DERO↔EVM) | Research crypto — the hard piece. Gates true interchain messaging. |

## Honest notes
- **Serverless bodies shipped** (see the spore-peer section above) — the last
  always-on-server dependency for body delivery is gone, and the pointer rail
  went serverless too (#8 relay fabric shipped). The remaining real
  product leaps are in-chat settlement (#1) and deep search (#2); #3–#7, #9,
  #10 are integrations with real-node dependencies or research, not "tonight"
  work.
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
