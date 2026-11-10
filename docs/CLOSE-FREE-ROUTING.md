# Close-to-free messaging and routing

> **Status, 2026-11-10: the Tron half of this plan has shipped.** `internal/tron`,
> the `internal/backend` case, the `-chain` help entry and the
> `docs/CARRIER_MATRIX.md` row landed in v0.11.0 — §3's steps are done, and its
> "must add" list is history. Still planned: the routing tier policy and the
> multi-chain receive fan-in in §2.2. Everything below stands as written: it is
> the assessment that chose the carrier, with its 2026-11 fee inputs, not a
> current status page.

Scope: assessment + plan. No code changed by this document.
Status key: **live** = shipped path; **planned** = not in code; **probe pending** = exact value not measured or not verifiable from repo.

Source notes:
- Fee figures below use TRX amounts exactly and USD figures as the ~2026-11 exchange-rate framing supplied (illustrative; TRX amounts are the authoritative numbers).
- No USD conversion is made here. No TRX price is assumed.
- Tron figures are 2026-11 inputs, not measured by this repo.
- `cmd\spore\e2cmd.go`: `-chain` help at line 373 (`pointer carrier: dero|evm|solana|nostr|bitcoin|cosmos|ton (xmr unsupported)`) and ChainConfig assembly at lines 194-196 verified against the tree; `tron` has since been added to both (v0.11.0); the line numbers cited are where they stood when this was written.

---

## 1. Tron memo carrier profile

### 1.1 Mechanism
- Carrier: memo-bearing TRX / TRC-10 transfer to recipient base58 address. Sender = tx `from`.
- Privacy model: fully public, same class as EVM calldata and the Solana inbox PDA. Chain carries only the opaque `0xE2` pointer. Body lives off-chain with TTL.
- Memo ceiling: ~200 B (endpoint may enforce less; probe pending).
- Pointer fit (base64, canonical padded):
  - PointerV1 = 74 B -> **100 chars**
  - PointerV2 = 106 B -> **144 chars**
  - Both fit under ~200 B.
- **Code gap:** `internal/ton/ton.go` hard-codes `PointerSize = 74` and `PointerVersion = 1`. Tron must not copy that check; it must accept V2 (106 B) or the V2 path is unreachable on Tron.

### 1.2 Fees (2026-11 inputs, TRX explicit)
| Item | Value |
|---|---|
| Plain transfer resource | bandwidth only; 1 byte tx = 1 point |
| Contract call resource | energy; **excluded by design** (no mailbox SC in this profile) |
| Free pool | 1500 bandwidth / account / day, resets 00:00 UTC |
| Free pointer txs | 1500/300 = 5 to 1500/250 = 6 per day (250-300 B/tx) |
| Staking | (your frozen / total frozen) x ~43.2B daily bandwidth |
| Marginal stake cost | ~0 TRX (per input) |
| Stake for ~50 msgs/day | ~150-400 TRX frozen (**probe pending**) |
| Burn past quota (bandwidth) | 1000 SUN/point = 0.001 TRX/byte |
| Burn past quota (energy) | 420 SUN/unit (not used by plain transfers) |
| One pointer msg burn | 250-300 B x 1000 SUN = 0.25-0.30 TRX |
| **Real band** | **0 TRX (free/staked) to ~0.30 TRX (pure burn)** |

### 1.3 Indexer and profile pins
- Primary: TronGrid API v1 `https://api.trongrid.io/v1/accounts/{address}/transactions`; free tier ~15 req/s per key.
- Fallback: TronScan public API.
- Full node: ~3 TB+ (input figure).
- Profile must pin `BaseURL`, `PostPath`, `ListPath`, `HeightPath` explicitly, same discipline as `internal/ton` `validateConfig` (explicit paths required, https/http only, no userinfo).
- Discovery: recipient scans own incoming transfer stream; require sender != self; strict-memo parse (canonical padded base64, exact length, version/reserved bytes, nonzero deadline).

### 1.4 Finality
- 27 Super Representatives, 3 s blocks.
- Readable ~3 s; ~19 confirmations ~57 s irreversible.

### 1.5 Burn semantics
- **No message-erasure primitive** on the memo seam (transfer is immutable).
- Compost is body-only (off-chain body deleted after delivery; tx remains).
- A TVM mailbox SC could add a real Burner, but costs energy. Deliberately **out of the memo profile**.
- Invariant: do not claim burn on Tron.

### 1.6 Verdict
- **ADOPT** as **CHEAP-TIER** memo carrier. Cost 0 -> ~0.30 TRX/msg. V1 and V2 fit.
- **NOT** a free tier at scale: only 5-6 free msgs/day/account.
- **NOT** an anchor. Bitcoin stays anchor.

---

## 2. Routing architecture

### 2.1 Per-carrier table

Fee column: numbers as given in input; currency unit probe pending except where marked TRX.

| Carrier | Cost per msg | Latency / finality | Pointer capacity | Burn / erase | Status |
|---|---|---|---|---|---|
| DERO | 0 (free tier) | native E2 | V1 R/C/D; V2 compact W=0xE221 + I/C/D fits 111 B payload-0 | immutable; pointer remains | **live** (mainnet verified) |
| Nostr | 0 (free tier) | ms-s publish | 256 KiB event cap | NIP-09 deletion, best-effort | carrier implementation |
| Solana | ~$0.001 (base + optional priority) | ~0.4 s slot / ~13 s to 32 conf | program mailbox payload | `burn(idx)` when enabled | **live** (self-messaging mainnet verified) |
| EVM L2 | ~$0.0001-0.01 | seconds-minutes (L2-dependent) | calldata path (mailbox SC path not payable) | `burn(to, seq)` when enabled | **live** (Anvil verified; deployment pending) |
| EVM L1 | ~$1-10 | ~12 s-2 min | calldata | `burn` when enabled | anchor |
| Cosmos SDK | ~$0.001-0.05 | ~6-7 s (tendermint final) | memo ~512 B-1 KB | chain-specific; no generic burn claim | configurable seam |
| TON | ~0.005-0.05 TON (~$0.01-0.10) | ~1-5 s | comment up to ~127 B; **code V1-only (74 B)** | no generic burn claim | configurable seam |
| **Tron** | **0 to ~0.30 TRX** | **~3 s readable; ~57 s irreversible** | memo ~200 B; V1 100 chars, V2 144 chars | no primitive; body-only compost | **shipped** (`internal/tron`, v0.11.0); not live-verified |
| Bitcoin | ~$0.02-2 (feerate-dependent) | ~10 min-1 h (1-6 conf) | OP_RETURN 80 B; **code V1-only** (V2 108 B script refused) | immutable; body-only compost | carrier implementation; anchor |
| Monero (XMR) | n/a | n/a | 8 B payment-id seam | n/a | **refused** for E2 pointer; never downgraded |

### 2.2 Tiers over the existing Chain seam

```
                 send-e2 (sender)
                        |
          +-------------v--------------+
          |  routing policy (planned)  |
          |  latency budget + anchor   |
          |  + per-carrier LIVE probe  |
          +--+---------+----------+----+
             |         |          |
   FREE      |  CHEAP  |          |  ANCHOR
   tier      |  tier   |          |  tier
   ----------+---------+----------+----------
   DERO      | Solana  | Bitcoin  |
   Nostr     | EVM L2  |          |
             | TON     |          |
             | Tron    |          |
             | Cosmos  |          |
   ----------+---------+----------+----------
   each arrow = chain.Chain.PostPayload(to, pointer)
   (pointer bytes only; body in TTL store)
```

Rules:
1. Fee-aware sender picks the cheapest **LIVE** carrier per message that meets the latency budget and anchor policy.
2. Unsupported carrier -> explicit error. Never a legacy fallback.
3. Receive side: one `WatchE2` per configured carrier, fanned into one receive loop with per-chain cursors (planned; current seam `internal/ratchetwire/carrier.go:87`).
4. Phone offline: hosted mailbox holds only TTL ciphertext + single-use prekeys (`GET /prekey` pops once; `PUT /prekey-batch`). Notifications are wake-up signals only (`docs/NOTIFICATIONS.md`). Decrypt happens on device.

### 2.3 Invariants kept
- Pointer-only on chain; body never on chain.
- Strict parsing on every carrier.
- Unsupported carriers refuse (XMR-style); no legacy downgrade.
- Burn claimed only where a real primitive exists.
- BSD-3; no token.

---

## 3. Implementation plan

**Next release**
1. `internal/tron/tron.go` + `tron_test.go`, mirroring `internal/ton/ton.go`:
   - strict memo encode/parse (canonical padded base64; accept V1 74 B and V2 106 B; reject others)
   - `validateConfig` with pinned BaseURL + PostPath + ListPath + HeightPath
   - `DeliveryGuaranteed` gate; no fallback transfer
   - `Sender` seam
2. `internal/backend/backend.go`:
   - add `case "tron"` next to the ton case (~line 106)
   - extend `Supported()` (~line 132) to include `tron`
   - update unknown-type message (~line 127). Current text `(want dero|evm|xmr|solana)` is stale (omits nostr, bitcoin, cosmos, ton).
3. `cmd\spore\e2cmd.go`:
   - `-chain` help (~line 373) lists `tron`
   - ChainConfig assembly (~194-196) passes tron fields. **Probe pending:** read blocked; verify before editing.
4. `docs\CARRIER_MATRIX.md`: add Tron row + deployment order note.
5. Tests:
   - strict memo parse (valid V1/V2; malformed; wrong length; non-canonical base64)
   - pointer-only invariant (no plaintext/ciphertext in memo)
   - unsupported carriers still refuse (XMR-style)
   - backend `Build` covers `tron`

**Later**
- `internal/routing`: per-carrier fee estimate + liveness probe + tier policy wired into `send-e2`.
- Multi-chain receive fan-in (`internal/ratchetwire/carrier.go:87` WatchE2).
- Tron mailbox SC with real Burner, gated on energy economics. Not in memo profile.

**Gaps found while reading (must fix before claiming support)**
- `internal/ton` PointerSize = 74: V2 unreachable on TON.
- `internal/bitcoin` PointerScript: V2 (106 B payload, 108 B script) refused by the 80 B cap; Bitcoin is V1-only.
- `internal/backend` Supported and unknown-type text out of date.

---

## 4. Numbered report

1. **Per-carrier cost** (as given; unit probe pending except TRX)
   - DERO 0 (free) | Nostr 0 (free) | Solana ~$0.001 | EVM L2 ~$0.0001-0.01 | EVM L1 ~$1-10 (anchor)
   - Cosmos ~$0.001-0.05 | TON ~0.005-0.05 TON (~$0.01-0.10) | **Tron 0-0.30 TRX (~$0-$0.09)** | Bitcoin ~$0.02-2 | XMR refused
2. **Tron verdict**
   - Memo ~200 B ceiling; V1 100 chars, V2 144 chars, both fit.
   - Free: 5-6 msgs/day/account (1500 bandwidth pool).
   - Stake: ~150-400 TRX covers ~50 msgs/day (probe pending).
   - Burn: 0.25-0.30 TRX per msg past quota.
   - Finality: ~3 s readable, ~57 s irreversible (19 confirmations).
   - Burn: none on memo seam.
   - **ADOPT as cheap-tier memo carrier. NOT free-at-scale. NOT anchor.**
3. **Architecture in one screen**
   - Tiers: free (DERO, Nostr) -> cheap (Solana, EVM L2, TON, Tron, Cosmos) -> anchor (Bitcoin).
   - Sender: cheapest LIVE carrier meeting latency + anchor policy. No legacy fallback.
   - Receive: one WatchE2 per carrier, per-chain cursors, one loop.
   - Phone offline: mailbox holds TTL ciphertext + single-use prekeys; notify = wake-up only; decrypt on device.
4. **Plan:** `internal/tron` + tests -> `backend` tron case -> `e2cmd` help/config (after read unblocked) -> CARRIER_MATRIX row -> tests (strict parse, pointer-only, XMR refusal, backend build). Later: routing policy, multi-chain fan-in, TVM Burner (energy-gated).
5. **Commit sha:** recorded by `git rev-parse HEAD` after the commit (see final output).
