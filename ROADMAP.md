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
  v3 live on mainnet; EVM verified on anvil with the in-repo deploy path ready
  (`spore contract deploy-mycelium`; needs a funded account + solc).
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
- **HTLC escrow in chat:** `-escrow htlc` locks `-amount` in the
  mainnet RelayHTLC contract; `msg escrow claim` (preimage, locally verified
  first) and `msg escrow refund` close it in-thread with a
  `spore/escrow/v1` settlement notice riding the session.
- **Relay-dex settlements in chat:** `msg dex swap|wrap|unwrap` invoke the
  RelayDEX/RelayWrappedDero contracts and announce the outcome in-thread via
  a `spore/dex/v1` envelope (ingest renders it, ledger records it);
  `msg dex fees` publishes the exact in-contract fee schedule and the
  SPORE_SAP_* contract-ID configuration state. All sap entry points refuse
  locally when a contract ID is unconfigured — the empty-SCID invoke the
  fund path previously allowed is gone.
- **Settlements render in the browser:** `spore web` classifies typed
  plaintexts (escrow/dex/invoice/payment/receipt) with the SAME parsers the
  CLI ingest uses and the inbox renders them as styled cards — never raw
  envelope JSON; a client-side sniff backstops servers predating the field.

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
continuity strict decode with size caps). Continuous fuzzing runs via
ClusterFuzzLite (PR code-change mode on every fuzzed-code PR, daily batch
+ prune on main) after the OSS-Fuzz upstream submission was declined as
premature (google/oss-fuzz PR 16145) — same libFuzzer binaries, no
upstream gate.

### Product roadmap after the evidence gates

#### v0.8.0 — E2 pointer deployment on the EVM mailbox contract

**Goal:** `spore msg send-e2 -to 0x…` works end-to-end on a real EVM chain
through a deployed `MyceliumMailbox`, with compost-on-delivery proven on that
chain — turning the EVM row in the carrier matrix from "live-verified (local
Anvil); deployment pending" into "live, deployment receipt published".

Everything hard about this is already built and pinned; what remains is
pointing it at a funded account on a real chain and publishing the evidence.

**Already in-repo (built, tested, pinned):**

- **The contract:** `contracts/MyceliumMailbox.sol` — per-recipient sequenced
  inbox, an `Inbox(to,from,seq,cid)` log for cheap `eth_getLogs` delivery
  discovery (no full block scan), recipient-only `read`/`burn`. It stores
  only opaque pointer bytes and never holds a key.
- **The backend wiring:** `internal/evm/mailbox.go` — `deliver(to,data)`
  encoding, log decode, `read(to,seq)`, and `burn(to,seq)` wired through
  `chain.Watch`'s auto-burn (burn failure never fails a delivery). Verified
  on Anvil end-to-end, including the post-burn empty-slot compost proof.
  The raw-calldata path stays the default and the payable one; `-mailbox`
  selects the contract path.
- **The deploy path:** `spore contract deploy-mycelium` signs and broadcasts
  the EIP-155 creation tx itself (hand-rolled over btcec, no go-ethereum
  dependency; signing + address derivation pinned byte-for-byte against
  go-ethereum vectors) and verifies code before printing the `-mailbox`
  address. Only remaining dependency: a funded EVM account on a real chain.
- **Pinned creation bytecode:** `tools/mycelium.bin` is real solc v0.8.26
  output of the documented pipeline, held in place by
  `TestPinnedMyceliumBytecode`, `TestDeployTxCarriesPinnedMyceliumCode`, and
  `TestSolcRecompileMatchesPinned` — no supply-chain gap between "what was
  audited" and "what gets deployed".

**v0.8.0 must do:**

1. **Deploy for real.** Choose the chain (a cheap L2 is the honest first
   target — pointer txs are small and frequent), fund a key, run
   `spore contract deploy-mycelium` against its RPC, and record the txid +
   contract address in `docs/LIVE_NODES.md` as the deployment receipt.
2. **Two-party E2E on the deployed mailbox.** A → B `send-e2` with
   `-mailbox <deployed>` and a `-store` of the test's choosing; B receives,
   acks, `chain.Watch` burns, and the on-chain slot is verified empty. The
   Anvil proof, repeated where it counts.
3. **Publish the addresses.** `-mailbox` is a flag today, not a default —
   ship default contract addresses per supported chain (config defaults /
   `spore init` output) so `send-e2` works without retyping it.
4. **Honest fee + limit notes.** Document per-chain gas reality for
   deliver/burn, and keep the value-carriage rule as-is: calldata is
   payable, the contract path is not — refuse `-amount` there rather than
   silently underpaying.
5. **(Stretch, not the gate)** pay-with-message through the contract path —
   needs a `payable deliver` variant or a value-forwarding pattern. Kept out
   of the done-bar on purpose so the core deployment is not hostage to it.

**Done when:**

- [ ] `MyceliumMailbox` deployed on a real EVM chain; creation txid + address
      published in `docs/LIVE_NODES.md` and reflected in the carrier matrix.
- [ ] Two-party `send-e2` → receive → auto-burn proven against that
      deployment, with the burned slot verified empty on-chain.
- [ ] Default `-mailbox` address wired into per-chain config defaults.
- [ ] CARRIER_MATRIX + README EVM rows updated to "live" with the same
      honesty standard as the DERO/Solana rows.

Deliberately **not** in v0.8.0: cross-chain identity proof (item #10 below).
EVM delivery here is DERO-independent — the recipient is an EVM address and
the ratchet is X3DH as today; cross-chain rendezvous is its own later gate.

| # | Item | Why it's gated / what it needs |
|---|---|---|
| 1 | **Finish escrow + swap UX in chat** | **HTLC close and dex settlements are both in-thread.** Escrow: `msg escrow claim/refund` (see shipped notes). Swap: `msg dex swap|wrap|unwrap` invoke RelayDEX/RelayWrappedDero and announce via `spore/dex/v1` envelopes; `msg dex fees` publishes the in-contract rake (90/10 LP/treasury, atomic swaps free) per docs/BUSINESS.md. Contract IDs now have a real config seam (`SPORE_SAP_HTLC_SC/DEX_SC/WDERO_SC` env) with local refusals — previously `sap.HTLCContractID` was never seeded, so the HTLC fund path sent an empty SCID. **Two-party soak shipped:** `spore derosim serve` (wallet-RPC simulator with honest RelayHTLC/RelayDEX/RelayWrappedDero semantics — hash-verified claims, expiry refunds, constant-product min-out, 1:1 wrap mint/burn) + `scripts/escrow_dex_soak.sh` drive real CLI processes both sides through bootstrap → fund→claim → fund→refund → swap → wrap/unwrap → receipts-ledger + web-card checks (31 green). The soak forced the swap input leg into existence: `msg dex swap -amount <n><ta-token>` (was a zero-deposit invoke that moved nothing). |
| 2 | **Tokenized search execution** — **shipped** | `maildb.Search` now prefilters through the inverted index (`PositionsContaining`: one vocabulary scan unions the positions of tokens containing any query term — a provable superset under substring semantics), the index is rebuilt on `Open` so search survives restart, `Purge` rebuilds it so compaction can never misalign positions, and `mail search` gained `-any`/`-not` OR/NOT flags. Exact `matchesQuery` semantics are unchanged and pinned by equivalence tests. |
| 3 | **Bitcoin/TON value carriage** | Their `PostPayload` discards the amount hint today, so `-amount` is refused on them. Real support needs Bitcoin dust-output + fee/UTXO wiring and a TON value-bearing message. |
| 4 | **Deploy `MyceliumMailbox.sol`** | The deploy path is now in-repo: `spore contract deploy-mycelium` signs and broadcasts the EIP-155 creation tx itself (hand-rolled over btcec, no go-ethereum dep; signing + address derivation pinned byte-for-byte against go-ethereum vectors, happy path stub-node-tested) and verifies code before printing the `-mailbox` address. Still gated on: a funded EVM account on a real chain. The solc creation bytecode is now **committed and pinned**: `tools/mycelium.bin` is the real solc v0.8.26 output of the documented pipeline, held in place by `TestPinnedMyceliumBytecode` (sha256 + solc-shape checks: constructor prologue, embedded-runtime size consistency, solc metadata marker), `TestDeployTxCarriesPinnedMyceliumCode` (the signed creation tx the deploy path broadcasts must embed the pinned bytes exactly), and `TestSolcRecompileMatchesPinned` (re-runs the pipeline from the repo root — solc metadata is path-sensitive — and byte-diffs; skips where solc 0.8.26 isn't installed). Regenerating artifact + pins is a deliberate paired act. **v0.8.0 target — detailed plan in the subsection above.** |
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
