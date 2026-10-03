# Live-node spec — verify EVM + Solana + XMR for real

m³ EVM and Solana backends are **live-verified**; XMR is still mock-verified.
This spec tracks the live nodes that prove each for real, on the Hetzner box
(YOUR-NODE-HOST) where the DERO node already lives.

## Goals / status at a glance
1. **EVM** — ✅ **live-verified** on a local anvil node (below); **v0.9.0 target:
   `MyceliumMailbox` on Base** (comparison + runbook in §3).
2. **Solana** — ✅ **live on mainnet** (program deployed + backend verified).
3. **XMR (Monero)** — ⏳ mock-verified; a pruned `monerod` is syncing so
   `spore msg send/recv -chain xmr` can verify end-to-end like DERO did.

---

## 1. Monero node on Hetzner

### STATUS: monerod RUNNING (pruned, systemd-managed) — 2026-09-05
- Installed official Monero **v0.18.5.1** linux-x64 binaries to `/opt/monero`
  (verified sha256 `22a7dda7...` matches getmonero.org signed list).
- `monerod` runs as user `monero`, pruned, data `/var/lib/monero`, daemon RPC
  `127.0.0.1:18081`, p2p `0.0.0.0:18080`, managed by `monerod.service`
  (systemd, auto-restart + boot). **Syncing (~60% as of 2026-09-05)**; multi-hour
  to tip ~3.75M.
- **Remaining on XMR path** (after sync reaches tip):
  1. Create + fund a test wallet (`monero-wallet-cli`), note the seed.
  2. Run `monero-wallet-rpc` on `127.0.0.1:18082` (behind auth / SSH tunnel).
  3. `spore msg send/recv -chain xmr` live round-trip.

### Why a node is needed
Monero has no public-API node like DERO's. The XMR backend talks to a **wallet
RPC** (`transfer`, `get_transfers`, `get_height`, `get_address`), which needs a
local `monerod` (daemon) synced to the chain + a wallet. Both must run on the
box.

### Requirements on YOUR-NODE-HOST
- **monerod** (daemon) + **monero-wallet-rpc** binaries.
  - Source build (needs the FULL monero source — the local `~/monero` is a
    partial checkout with no `src/wallet`) OR a prebuilt release binary.
  - **Monero chain is ~180 GB+** (pruned ~50–60 GB). Must confirm disk headroom
    — the box already holds dero data. **Pruned sync recommended.**
- **Run as its own user** (`monero`), not root, matching the derod setup.
- **Daemon RPC** bound to `127.0.0.1:18081` (never exposed).
- **Wallet RPC** bound to `127.0.0.1:18082` behind basic auth, or via SSH
    tunnel like the DERO wallet — do NOT open 18082 to the internet.
- **chain settings**: `--prune-blockchain`, `--data-dir /var/lib/monero`,
  `--restricted-rpc` for the daemon (no mining control).
- **Funding + registration**: Monero needs no on-chain registration, but each
  test wallet needs a tiny XMR balance for tx fees (postage).

### Steps (node admin — user runs in another window, per standing rule)
```
1. Confirm disk: df -h ; confirm >=80 GB free (pruned) before starting.
2. Install monero: prebuilt linux-x64 tarball (fastest) into /opt/monero,
   or full source build (cargo not needed; cmake/gcc). Prebuilt recommended.
3. useradd -r -m monero
4. monerod --prune-blockchain --data-dir /var/lib/monero
     --restricted-rpc --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081
     --confirm-external-bind --non-interactive &
   # sync to tip: monerod get_info height == network height (~3.2M)
5. monero-wallet-cli --generate-from-json or monero-wallet-cli --daemon-address
     127.0.0.1:18081  (create the test wallet; keep a copy of the seed)
6. Fund wallet with a small XMR amount (postage ~ micro-XMR per tx)
7. monero-wallet-rpc --wallet-file /opt/monero/wallet/spore \
     --rpc-bind-port 18082 --daemon-address 127.0.0.1:18081 \
     --rpc-login spore:CHANGEME --password-file <...> &
8. systemd units for monerod + monero-wallet-rpc (restart on boot)
9. Verify locally on the box:
     spore msg send -chain xmr -rpc http://127.0.0.1:18082/json_rpc \
        -to <wallet-b-subaddr> -msg "hi"
     spore msg recv -chain xmr -rpc http://127.0.0.1:18082/json_rpc
```

### XMR note (repeat)
Monero carries only an **8-byte payment id**. Short signals ("hi", "sup?")
verify on-chain. Longer text must ride off-chain rendezvous (VISION §3) — so
live XMR verification is scoped to **short no-relay signals**, which is the
honest capability. Long-body XMR is a rendezvous integration, separate.

---

### STATUS: EVM backend LIVE-VERIFIED — 2026-09-05
- anvil 1.8.1 (foundry) running on Hetzner `127.0.0.1:8545` (`/var/log/anvil.log`).
- `spore msg send -chain evm` → txid `0x69f8...9fa` mined in anvil block 1,
  calldata `0x01001068692066726f...` (canonical kind 0x01 text "hi from evm live").
- `spore msg recv -chain evm` on recipient account decoded it:
  `msg 0x69f8048e4b15be…: hi from evm live`.
- **internal/evm is now LIVE-VERIFIED** (no longer mock-only). To prove it
  against a real chain later, point at a funded account on a real EVM RPC —
  backend logic is identical.

## 2. EVM node / RPC target

### Reality check (why a public testnet alone isn't enough)
`internal/evm` signs via `eth_sendTransaction` with `from` = our address.
Public Sepolia RPCs (e.g. a hosted endpoint) are **read-only** — they can't
sign a tx for you. Live EVM verification needs the **private key** to sign
locally. Options:

| Option | Signing | Effort |
|---|---|---|
| **Local anvil/geth dev node** on the box | anvil auto-funds + unlocks accounts | low, self-contained |
| **Local geth with our funded key** on Sepolia | geth unlocks a key we import | med (needs a funded key + faucet) |
| **EVM wallet-RPC the CLI reaches** | wallet holds key | depends on user's wallet |
| **`spore evm-proxy` in front of a public RPC** (§3) | signs locally, loopback | low — no node, no wallet |

### Recommended: anvil (foundry) dev node on Hetzner
`anvil` is a 10-second local EVM node that pre-funds test accounts and accepts
`eth_sendTransaction` for them — no faucet, no real chain, but it exercises the
EXACT same JSON-RPC path the backend uses. This verifies the `internal/evm`
backend + seam for real (round-trip send/recv) without needing Sepolia funds.

Then, to prove it against a **real** EVM chain, swap in a funded account later.
The backend logic is identical; only the RPC endpoint + funded key change.

### Steps (anvil path)
```
1. Install foundry (anvil) on the box:  curl -L https://foundry.paradigm.xyz | bash
2. anvil --port 8545 &   (pre-funded accounts on 127.0.0.1:8545)
3. spore msg send -chain evm -rpc http://127.0.0.1:8545 \
        -from 0x<anvil-account-0> -to 0x<account-1> -msg "hi"
   spore msg recv -chain evm -rpc http://127.0.0.1:8545 -from 0x<account-0>
4. Round-trip a message between two anvil accounts.
```

---

## 3. EVM mailbox deployment — Base (v0.9.0 runbook)

Executes the "deploy for real" step of the v0.9.0 roadmap item
(ROADMAP.md, product roadmap): put the already-built-and-pinned
`MyceliumMailbox` on a real chain and publish the receipt.

### Why Base (chain comparison, as of 2026-09)

| Chain | Fee reality for a pointer tx | Fits our deploy path? | Verdict |
|---|---|---|---|
| **Base** (OP stack, chain 8453) | Lowest of the majors — avg ≈ $0.01/tx (Token Terminal, 2026-09) | ✅ full EVM equivalence; legacy EIP-155 + `eth_sendRawTransaction` work unchanged | **Chosen** |
| Arbitrum One | Same class ($0.007–$0.012 avg across Arbitrum/OP majors, 2026) | ✅ | Runner-up — second deployment if wanted |
| OP Mainnet | Same class, slightly above Base on average | ✅ | Fine; no advantage over Base |
| Polygon PoS | Comparable or cheaper | ⚠️ own validator set — a different security story than an Ethereum L1; gas asset is POL | Ruled out (announce honestly or not at all) |
| zk rollups (zkSync Era, …) | Comparable | ⚠️ not byte-equivalent with solc EVM output — risks the pinned-bytecode guarantee | Ruled out |
| Ethereum L1 | Dollars per message | ✅ but pointless at pointer volume | Anchor-class only |

Decision: **Base first** — turnkey public RPC (`https://mainnet.base.org`),
a real testnet (`https://sepolia.base.org`, chain 84532), explorers
(basescan.org / sepolia.basescan.org), and faucet-funded Base Sepolia.
Arbitrum One is the follow-on if a second L1-anchored deployment is ever
wanted. Fee numbers move with L1 gas; the runbook rule is **measure with
`eth_gasPrice` at run time**, never trust a doc number.

Why the code fits without changes (checked against `internal/evm`):

- solc v0.8.26 output runs as-is on a full-equivalence OP stack — storage,
  events, `keccak256`, nothing exotic. `tools/mycelium.bin` deploys verbatim.
- `spore contract deploy-mycelium` is self-contained: `eth_chainId`, nonce,
  `eth_gasPrice`, `eth_estimateGas`, legacy EIP-155 signing (btcec),
  `eth_sendRawTransaction`, then `eth_getCode` polling. All standard; type-0
  txs remain valid on Base. Pass `-wait 5m` — L2 sequencing to code-visible
  state can outpace the default 2-minute poll on a slow day.
- Delivery discovery is exactly what the mailbox contract buys: `eth_getLogs`
  on `Inbox(to=us)` + `read(to,seq)`, and `chain.Watch` auto-burn calls
  `burn(to,seq)` — no nonstandard APIs anywhere.
- The raw-calldata fallback's 200-block lookback would be ~7 minutes at
  Base's ~2s blocks — irrelevant here (we deploy the contract precisely so
  discovery is log-based), but it is why the contract path is the deployment
  goal and not a nicety.

### Runbook — Phase A: rehearsal on Base Sepolia (free, do first)

One-command path: `scripts/sepolia_rehearsal.sh` drives every step below
(estimate → deploy → two-party proof through a pair of loopback proxies →
empty-slot assertion) and prints the STATUS lines for the block at the end
of this section. It needs `SPORE_EVM_PRIVATE_KEY` **and**
`SPORE_EVM_PRIVATE_KEY_B` — TWO funded keys, because the recipient's proxy
signs the burn (`burn(to,seq)` requires `msg.sender == to`). The manual
equivalent:

```
1. Throwaway keys (TWO — the recipient's proxy signs the burn, so the
   RECIPIENT key needs gas too): export SPORE_EVM_PRIVATE_KEY=0x<32-byte
   hex> and SPORE_EVM_PRIVATE_KEY_B=0x<different 32-byte hex>
   (env vars, not argv — same rule as every other secret in this repo).
2. Fund it from a Base Sepolia faucet (Alchemy or Chainlink run ones).
   A deploy plus a dozen deliver/burn rounds cost well under
   0.01 testnet ETH.
3. Deploy (signs locally — a public RPC is enough):
     spore contract deploy-mycelium -rpc https://sepolia.base.org -wait 5m
   It verifies code at the derived creation address before printing the
   contract address. Record address + creation txid.
4. Two-party proof (mirrors the Anvil proof, now against a real chain).
   Sends sign node-side, so both endpoints run the loopback signing proxy
   (`spore evm-proxy` — local EIP-155 signing for eth_sendTransaction,
   everything else forwarded verbatim) in front of the same public RPC —
   A with key A, B with key B (the burn is signed by B's proxy):
     A: SPORE_EVM_PRIVATE_KEY=0x…A spore evm-proxy -rpc https://sepolia.base.org -listen 127.0.0.1:8555
     B: SPORE_EVM_PRIVATE_KEY=0x…B spore evm-proxy -rpc https://sepolia.base.org -listen 127.0.0.1:8556
     sender:    spore msg send-e2 -to 0xB… -mailbox 0x<addr> \
                  -rpc http://127.0.0.1:8555 -from 0xA… \
                  (bundle/pinned-sig/store flags as ONBOARDING §4)
     recipient: spore msg recv-e2 -mailbox 0x<addr> \
                  -rpc http://127.0.0.1:8556 -from 0xB… \
                  -min-height <current eth_blockNumber> \
                  (auto-burn is the default; -min-height keeps the log
                   scan bounded — the deliver tx lands in a LATER block)
   Then assert compost on-chain — `length(to)` unchanged after the burn and
   `read()` returning empty data (the slot is provably empty):
     cast call 0x<addr> "length(address)(uint256)" 0xB… \
       --rpc-url https://sepolia.base.org
5. Record txids (creation, one deliver, one burn) in the STATUS block below.
   The burn txid is unlogged by design (chain.Watch treats the burn as
   best-effort and the proxy logs nothing), so read it from the explorer's
   tx history for the contract — or cite the empty-slot read() as the proof,
   which is what the script does.
```

### Runbook — Phase B: Base mainnet (chain 8453)

```
1. Fund a dedicated spore key with a small ETH amount. Measure first —
   the whole eth_gasPrice × gas computation is one command:
     spore contract estimate -rpc https://mainnet.base.org -from 0x<deployer>
   Run it before deploying (deploy row only), then again after Phase B
   step 2 with `-mailbox 0x<addr>` added — deliver/burn rows and the
   N-round funding total appear. The burn row is a labeled conservative
   constant when the node refuses to estimate a burn against an empty
   slot (real burns are typically cheaper); the command ends with the
   standing rule: re-run at deploy time, never fund from a stale number.
   At 2026 fee levels this is cents per message, but measure, don't
   assume.
2. spore contract deploy-mycelium -rpc https://mainnet.base.org -wait 5m
3. Two-party proof again, against mainnet, with tiny real amounts.
4. Publish:
   - the receipt block below (creation txid, contract address, deployer, date)
   - default `-mailbox` per chain in config defaults (the roadmap done-bar)
   - CARRIER_MATRIX + README EVM rows flip to "live" — same honesty bar
     as the DERO/Solana rows.
```

### Deployment day: from funded key to signed tag (the one-commit flip)

Phase B ends with a deployed contract and a proven two-party round. What
follows is the publication sequence, in order — each step names the check
that keeps it honest. The exact flipped wording for step 5 is pinned by
`internal/evm/mailboxdefaults_test.go` (the receipt gate), which is the
in-repo source of truth for every string involved; this runbook stays valid
even when out-of-repo design notes are gone.

1. **Capture the receipt.** From the Phase B outputs (and Phase A if it
   ran): contract address, creation tx, deployer, date, one deliver txid.
   The burn tx is unlogged by design — cite the on-chain empty-slot
   `read()` as the proof. The rehearsal script's `receipt` step prints
   these lines ready to paste into the STATUS block below.
2. **Keep the measured numbers.** Phase B step 1 already ran
   `spore contract estimate` twice (pre-deploy with `-from` only;
   post-deploy with `-mailbox`). Save both outputs — the fee + limit
   notes are filled from them in the release-prep pass, never from a doc
   number, and the funding decision already used the post-deploy total.
3. **Paste the receipt into the STATUS block below** — address, creation
   tx, deployer, date, deliver txid — and flip the STATUS block's
   "shipped in" line from `<release>` to the shipping release.
4. **Add the registry entry** to `internal/evm/mailboxdefaults.go`:

   ```go
   "8453": {
       ChainID:    8453,
       Address:    "<address from step 1>", // lowercase, 0x + 40 hex
       Default:    "v0.9.0",
       ReceiptRef: "docs/LIVE_NODES.md §3 STATUS / Base mainnet",
   },
   ```

   From this commit on, `spore init -chain evm` writes that address as the
   shipped default mailbox (opt out with `-mailbox-contract=`).
5. **Flip the four operator-facing rows in the SAME commit** — README
   chain table, CARRIER_MATRIX EVM row, the LIVE_NODES header + goals
   item 1, ONBOARDING readiness row — to the exact claims pinned by
   `deploymentDayDocClaims` in the gate test. All four flip together or
   not at all: the gate fails if any doc claims the deployment is live
   while the registry is empty, if any keeps the pre-deployment wording
   after it ships, and if the shipped address is not cited in §3.
6. **Referee:** `go test ./internal/evm ./cmd/spore` must be green —
   `TestShippedMailboxDefaultsCarryReceipts` and
   `TestDocClaimsMatchRegistryState` pass only when receipt, registry,
   and docs agree.
7. **Full gates, then push:** `go test ./...` + lefthook green, push
   main, wait for CI (check by head SHA via `gh api
   repos/liqdmetal/spore/actions/runs?head_sha=<sha>` — the run list
   lags).
8. **Signed tag LAST**, after CI is green on the flip commit: fill the
   tag draft's placeholders from the receipt (search for the FILL
   markers), then `git tag -s v0.9.0 -F <file>` and push the tag — the
   release workflow fires on `v*` tags, which is exactly why the tag is
   always the last action.

Before the signed tag, the release-prep pass finishes the release's honest
claims: the fee + limit notes are filled from the step-2 estimate outputs,
and Patches 6 and 7 drain the narrative and remaining audited-document
status claims to match the published chain status —
`TestReleasePrepProseDrainedAfterFlip` enforces that drain once the registry
entry from step 4 exists.

### STATUS: MyceliumMailbox on Base — PENDING

- Base Sepolia rehearsal: address `0x…`, creation tx `0x…`, date …
- Base mainnet: address `0x…`, creation tx `0x…`, deployer `0x…`, date …
- Two-party E2E → receive → auto-burn → empty-slot proof: txids …
- Default `-mailbox` (config `evm_mailbox`) shipped in: <release>

### Honest notes (sender-side reality)

- **Sends sign through the loopback proxy; the public RPC never signs.**
  `spore evm-proxy` (shipped) intercepts `eth_sendTransaction`, signs with
  the same hand-rolled EIP-155 signer the deploy uses (key zeroed after each
  signing; a caller-supplied `from` that mismatches the key fails loudly,
  never silently rewritten), broadcasts raw, and forwards every other method
  verbatim. Loopback-only by construction — it signs whatever arrives, so it
  must never be exposed. On the send/receive legs the CLI's `-rpc` points at
  `http://127.0.0.1:8555`, not at Base; the deploy command never needed the
  proxy (it signed raw EIP-155 itself).
- Public RPC etiquette: `eth_getLogs` range/rate limits may apply on
  `mainnet.base.org`; the backend's Inbox query is `fromBlock`-bounded. If
  limits bite, run your own node or a paid RPC — nothing in the backend is
  Base-specific; that is the point of the JSON-RPC seam.
- Compost is the recipient's gas: `burn(to,seq)` costs a real (small) fee
  per message on EVM, unlike DERO's native expiry.
- Value carriage on EVM: the calldata path (no mailbox configured) is
  payable — `-amount` rides the same tx as the pointer. The mailbox-contract
  path is NOT payable: `deliver()` is not a payable function, so `msg
  send-e2` and `msg pay` REFUSE `-amount` when a mailbox is set (explicit
  `-mailbox` or the config `evm_mailbox` default) instead of silently
  dropping the money. Settle separately with `msg pay` against a
  calldata-path config, or use the direct calldata path.
- Default `-mailbox` shipped as the config `evm_mailbox` seam (init
  `-mailbox-contract` writes it; explicit flags always win; it never leaks
  into the URL-flavored `-mailbox` of prekeybatch/invite — applied only in
  the chain-backend funnels).

---

## Solana — LIVE on mainnet (2026-09-05)

- **BPF mailbox program deployed + live-verified on Solana mainnet** (v2):
  program ID `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs` (v1 `28c7UyzaevLfatrTtzX2pgTcgKDgsRuiQ22UPWC4gEhL` had a rent bug; v2 fixes inbox rent on a fresh id). Source + tests in `solana-program/`.
- Go `internal/solana` backend verified against the live program (self-messaging:
  the program requires the recipient to sign). RPC default
  `https://api.mainnet-beta.solana.com`. Signer key = deployer.
- **Remaining on Solana path:** cross-wallet delivery (both parties run the
  backend; the recipient must sign to read their own inbox).

---

## Decisions needed (user)
1. **XMR install path**: prebuilt monero tarball (fast, recommended) vs full
   source build on the box? And confirm disk headroom first. (monerod is
   syncing — the daemon side is up.)
2. **XMR verification scope**: OK that live XMR proves *short signals* only
   (long text needs the rendezvous work)? Or do you want the rendezvous
   integration speced first?

## Not live-verified: what that means
EVM and Solana are live-verified (anvil / mainnet above). **`internal/xmr`
remains mock-verified**: correct against the seam and the RPC shape, but not
confirmed against a real chain. A pruned `monerod` is syncing (~60%) on the box;
the remaining path is a `monero-wallet-rpc` round-trip, exactly like the DERO
node did.
