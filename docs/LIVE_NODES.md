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

### Rehearse for free first: the local Anvil proof

`scripts/anvil_e2e.sh` runs the entire two-party arc — deploy the PINNED
`tools/mycelium.bin` through the real `spore contract deploy-mycelium` path,
publish a prekey batch, A → B `send-e2 -mailbox`, B receiving with auto-burn,
and the empty-slot read back — against a throwaway local Anvil that the script
starts and stops itself. No keys, no faucet, no network, no jq: it needs only
`anvil` on PATH, and with `-s` it self-skips (exit 0) where foundry is absent.
It is the fast pre-flight for Phase A below and the local mirror of this
runbook — run it before spending testnet ETH, and again after any carrier
change. It also pins the compost promise on-chain: the script fails unless a
fresh-state read of the burned slot (and, with foundry's `cast`, the
contract's own `read(to, seq)`) comes back empty.

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

### Go/no-go checklist — the pre-deploy gates, in order

Every gate below names what it proves and the exact evidence that counts as
GO. Gates 0–3 are free; gate 4 is the only step that spends mainnet ETH. Stop
at the first NO-GO: nothing before gate 4 is irreversible, and a deployed
contract with no shipped default (gate 6) is inert.

One command runs the free, read-only gates (0–2) and ends in a GO/NO-GO:

```bash
scripts/preflight-base.sh                 # Base mainnet defaults: chain 8453
scripts/preflight-base.sh -a 0x… -c 31337 # any EVM chain (e.g. a local anvil)
scripts/preflight-base.sh -m 0x…          # after gate 4: adds the round budget
```

It never signs, deploys, or sends anything. It derives the deployer address
without printing the key, computes the predicted creation address from the
live nonce, and checks the deployer's balance against the live estimate; a
missing tool (foundry/`cast`, go, `anvil`) is a NO-GO with a reason, never a
silent pass. Run it before gate 3 and again after gate 4.

#### Gate 0 — the proof runs locally, and the shipped bytes are the audited bytes

```bash
bash scripts/anvil_e2e.sh                 # free, offline, self-skips without foundry
go test ./internal/evm ./cmd/spore -count=1
go test ./internal/evm -run 'TestPinnedMyceliumBytecode|TestDeployTxCarriesPinnedMyceliumCode' -count=1 -v
```

GO when the harness ends `ANVIL E2E GREEN — N checks` with its final
`ON-CHAIN PROOF: read(to, seq=…) is empty`, both packages print `ok`, and the
pin tests PASS. NO-GO on any skip of `TestPinnedMyceliumBytecode` — its sha256
check is what ties `tools/mycelium.bin` to the reviewed source, and a skip
there means the deployed bytes are unproven.

#### Gate 1 — chain, key, and predicted address (read-only)

```bash
export RPC=https://mainnet.base.org
export SPORE_EVM_PRIVATE_KEY=0x…            # deployer + sender; fund it in gate 2
cast chain-id --rpc-url $RPC                # must print 8453
cast wallet address --private-key $SPORE_EVM_PRIVATE_KEY
cast nonce <deployer> --rpc-url $RPC
cast compute-address <deployer> --nonce <nonce>   # the address gate 4 must print
sha256sum tools/mycelium.bin
```

GO when the chain id is exactly `8453`, the derived deployer address is one
you control and are willing to fund, and you have recorded the nonce, the
predicted creation address, and the bytecode hash. NO-GO on any other chain
id — a pointer sent to a contract address on a different chain targets a
different (or absent) contract — or when the predicted address is not the one
you intend to publish.

#### Gate 2 — measure the funding number (read-only, live gas)

```bash
spore contract estimate -rpc $RPC -from <deployer>
```

GO when a `deploy … gas …` row is printed and `estimates sent from <deployer>`
matches gate 1. `funding total` is *expected* to read "not computable" here:
the deliver/burn rows need a mailbox, which does not exist yet. Fund the
deployer with at least the deploy figure plus headroom; after gate 4, re-run
with `-mailbox 0x<addr> -rounds N` for the round budget. The command restates
the rule itself: re-run at deploy time, never fund from a stale number.

#### Gate 3 — rehearse the whole arc on Base Sepolia (free)

```bash
export SPORE_EVM_PRIVATE_KEY=0x…A     # deployer + sender
export SPORE_EVM_PRIVATE_KEY_B=0x…B   # recipient; its proxy signs the burn
scripts/sepolia_rehearsal.sh
```

GO when the script ends green **and** prints the empty-slot proof
(`COMPOST VERIFIED`, and with foundry's `cast` the
`ON-CHAIN COMPOST PROOF: read(to, seq=…) returned EMPTY bytes` line), and its
`receipt` step emits the paste-ready STATUS lines. NO-GO if the compost
assertion falls back or the burn is unproven — mainnet is not the place to
discover a burn that does not land.

#### Gate 4 — deploy on Base mainnet (the one spending step)

```bash
SPORE_EVM_PRIVATE_KEY=$SPORE_EVM_PRIVATE_KEY \
  spore contract deploy-mycelium -rpc $RPC -wait 5m -bin tools/mycelium.bin
```

GO when it prints all three lines — `tx hash: 0x…`, `contract addr: 0x…`, and
`code verified: yes (eth_getCode non-empty)` — and the printed address equals
the gate-1 prediction (if it does not, STOP: something else consumed the
nonce). Confirm independently:

```bash
cast receipt <creation-tx> --rpc-url $RPC   # status 1
cast code <addr> --rpc-url $RPC             # non-empty
spore contract estimate -rpc $RPC -from <deployer> -mailbox <addr> -rounds 12   # full funding total
```

The last line is the number the honest fee notes are filled from — and the
funding decision already used.

#### Gate 5 — the two-party proof on the deployed mailbox (tiny real amounts)

Sends sign node-side, so both endpoints run the loopback signing proxy in
front of the same public RPC: A with key A, B with key B (the recipient's
proxy signs the burn, so B needs gas too). Auto-burn is on by default — do
**not** pass `-auto-burn=false`.

```bash
# A: SPORE_EVM_PRIVATE_KEY=0x…A spore evm-proxy -rpc $RPC -listen 127.0.0.1:8555
# B: SPORE_EVM_PRIVATE_KEY=0x…B spore evm-proxy -rpc $RPC -listen 127.0.0.1:8556
spore msg recv-e2 -chain evm -from 0xB… -rpc http://127.0.0.1:8556 -mailbox <addr> -min-height <block>
spore msg send-e2 -to 0xB… -chain evm -from 0xA… -rpc http://127.0.0.1:8555 -mailbox <addr> \
  (bundle/pinned-sig/store flags as ONBOARDING §4)
```

GO when B decrypts **and** the slot is provably empty — the P0-3 evidence
(`ROADMAP-PRODUCTION.md`: "Dependent on the mailbox actually burning
correctly"):

```bash
cast call <addr> "length(address)(uint256)" 0xB… --rpc-url $RPC
cast call <addr> "read(address,uint256)(address,uint256,bytes)" 0xB… <seq> --from 0xB… --rpc-url $RPC
```

`length(to)` counts every delivery and never decreases; `read(to, seq)` read
as B must return empty `bytes` for the burned slot. NO-GO while it returns
data: that is exactly the missed burn the local harness catches, and shipping
a default on top of it would make every message permanent.

#### Gate 6 — publish (one commit, then the tag)

Paste the receipt into the STATUS block below; add the
`KnownMailboxDeployments["8453"]` entry; flip the four operator-facing rows
(README, CARRIER_MATRIX, this file's header + goals, ONBOARDING) in the **same
commit**; fill the honest fee + limit notes from the gate 2 and gate 4
estimator output (including that the contract path is not payable, so `-amount`
is refused there by design). Then referee:

```bash
go test ./internal/evm ./cmd/spore -count=1   # the receipt gate
bash scripts/gates.sh                        # the FULL suite, not --quick
```

GO when both are green — these tests fail loudly if a doc claims a deployment
the registry does not carry, or vice versa. Push, wait for CI green on the
head SHA (check by SHA — the run list lags), dispatch `release.yml` as a
dry-run, and only then create the signed tag: `git tag -s v0.9.0 -F <draft>`
(the release workflow fires on `v*`).

#### Abort rules

| Where it fails | What to do |
|---|---|
| Gates 0–3 | Do not spend. Fix and re-run from gate 0. |
| Gate 4 (tx reverts) | Nothing changed on chain. Re-run gate 1 first — a landed tx shifts the nonce and the predicted address. |
| Gate 5 (slot still holds data) | Leave the registry empty and the docs pre-deployment. A deployed contract with no shipped default is inert, and the pre-deployment wording stays honest. |

| Gate | Cost | Proves | Evidence that counts |
|---|---|---|---|
| 0 | free | the path works locally; shipped bytes = audited bytes | `ANVIL E2E GREEN` + empty-slot read; pin tests PASS |
| 1 | free | right chain, right key, predicted address | chainid `8453`; derived + predicted address recorded |
| 2 | free | what it costs | deploy row priced; `estimates sent from` matches gate 1 |
| 3 | testnet | the whole arc including the burn | rehearsal green + empty-slot proof + STATUS lines |
| 4 | mainnet | the deployment exists | tx hash, contract addr == prediction, `code verified: yes` |
| 5 | mainnet | two-party delivery + compost on the real chain | B decrypts + `read(to, seq)` empty |
| 6 | free | the publish is receipt-honest | receipt gate + full gates green; CI green on the head |

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
in-repo source of truth for every string involved. The ready-to-apply flip
patch is vendored at
[`release-designs/v0.9.0-doc-flips.md`](../release-designs/v0.9.0-doc-flips.md),
with the line-wrap constraints a 2026-10-06 rehearsal found annotated at its
end — so this runbook stays valid even if the out-of-repo design notes are
gone.

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
   Steps 3 and 4 are executable: with both frozen patches applied,
   `bash scripts/release-fill.sh -in values` performs the whole receipt
   substitution — both STATUS rows, the deliver tx, the address the burn
   note cites, the registry entry, and the fee block's measured numbers —
   from one key=value file, and REFUSES an incomplete receipt rather than
   leaving a tree that half-claims a deployment. `bash
   scripts/release-fill.sh --check` needs no values at all: it only
   confirms every marker anchor still resolves, which is what catches a doc
   edit that moved a line out from under the patches.
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
   always the last action. `scripts/release-tag-message.sh --write` does
   the fill check and the strip in one step and **refuses while any field
   is unfilled**: the tag body is the one artifact the receipt gate never
   reads, and a tag is immutable once pushed, so a placeholder signed
   into it would be permanent.

Before the signed tag, the release-prep pass finishes the release's honest
claims: the fee + limit notes are filled from the step-2 estimate outputs,
and Patches 6 and 7 drain the narrative and remaining audited-document
status claims to match the published chain status —
`TestReleasePrepProseDrainedAfterFlip` enforces that drain once the registry
entry from step 4 exists.

The flip and the fee pass are executable, and rehearsed long before release
day. `release-designs/v0.9.0-doc-flips.patch` and
`release-designs/v0.9.0-fee-notes.patch` are the frozen apply-ready forms of
the passes above, in that order (the fee patch's base is the tree the flip
produces), and `scripts/release-day-rehearsal.sh` applies both to a throwaway
tree and runs the referee there — then removes the registry entry and requires
the same run to fail, so a gate that accepts every tree cannot pass as a green
rehearsal. It runs on every push; the deployment-day commit is the only run
whose address is real.

Because both patches carry markers until the deployment produces the numbers,
`scripts/release-placeholders.sh` is the last check before the tag: it derives
the release surfaces from the patches themselves and sweeps them for the dry
run's synthetic receipt values, its placeholder mailbox address, and any
unfilled measured number. The receipt gate cannot substitute for it — a
placeholder address is still `0x` + 40 hex and is still cited in §3, so a
forgotten one would ship as the default mailbox for every user. Run it after
filling; it must exit 0.

The fill itself is rehearsed, not just documented.
`scripts/release-fill-rehearsal.sh` deploys the pinned bytecode to a local
Anvil, runs the runbook's own `spore contract estimate` against it, fills a
scratch tree from those real values, and then requires the result to sweep
clean *and* keep the referee green — the direction nothing else checks, since
both frozen patches are markers-only until the deployment exists. It perturbs
the registry address afterwards and requires the referee to fail, so a fill
that disagrees with the receipt cannot pass as green. It self-skips without
foundry, which makes it a pre-tag step rather than an inner-loop gate.

`scripts/release-readiness.sh` is the single command that answers "am I ready to
tag?": it composes the checks above with the registry's own state and the tag
draft's structure, exits 1 while anything is outstanding, names each blocker
with the command that clears it, and prints the checklist steps no machine can
decide. It is expected to be blocked until release day. It never replaces the
tag itself: the signed tag is still the last action, and `scripts/release-tag-message.sh --write`
prepares its message.

### Post-launch: the compost watchdog (the red signal)

The deployment's headline claim is that a delivered message composts — the
recipient reads it and the on-chain slot is erased. Chain state, not logs, is
the only witness that cannot lie about it, so
`scripts/mailbox-compost-watch.sh` watches exactly that: it reads the
mailbox's own storage and turns red when slots stop burning.

The bug that motivates it was real and silent. `msg recv-e2` once built its
watch options without `AutoBurn`, so every delivered pointer sat in the
mailbox forever while delivery logs looked perfectly healthy (found and fixed
via `scripts/anvil_e2e.sh`, which now pins the empty-slot read on every run).
A log-scraping monitor would have reported green the whole time.

How it can see a recipient-only slot: `read(to, seq)` requires
`msg.sender == to`, but `eth_call` accepts a `from`, so the watchdog simulates
the read *as the recipient*. The payload is already E2E-encrypted — the
contract never holds a key — so this leaks nothing, and the watchdog only ever
inspects the DATA LENGTH, never the bytes.

For each watched recipient it reads `length(to)` and inspects the most recent
`--depth` sequence numbers. A slot with non-zero data whose delivery block is
older than `--grace-seconds` was read and never burned: compost is broken for
that slot.

```bash
# One-shot health check by hand (no alert; the exit code carries the verdict):
bash scripts/mailbox-compost-watch.sh --rpc https://mainnet.base.org \
  --mailbox <addr> --recipient 0xB…

# cron/systemd: page on a stuck slot, at most once every 10 minutes:
MAILBOX_COMPOST_WEBHOOK=https://hooks.slack.com/services/… \
  bash scripts/mailbox-compost-watch.sh --rpc "$RPC" --mailbox <addr> \
    --recipient 0xB… --once --grace-seconds 1800

# Or leave it running and let it re-check every interval:
bash scripts/mailbox-compost-watch.sh --rpc "$RPC" --mailbox <addr> \
  --recipient 0xB…
```

- The webhook URL lives in `$MAILBOX_COMPOST_WEBHOOK`, never in argv, and the
  URL itself is never put in the payload. The alert JSON carries the mailbox,
  the stuck count, the oldest age, and a per-recipient
  `addr:length:unburned` summary.
- `--grace-seconds` is the honesty knob: a slot younger than the window is
  just "not read yet", not a missed burn. Set it above how long a legitimate
  recipient takes to come online — 900s is the default, and 1800s is
  reasonable for a phone that is often offline.
- Exit codes: `0` healthy, `1` a stuck slot beyond `--max-unburned` (default
  0), `2` **cannot check** (RPC unreachable, no contract at `--mailbox`, a
  malformed read), `3` usage error, `4` alert delivery failed (`--once`).
  Exit `2` is never a silent pass: a watchdog that cannot see the chain must
  not report green — wire both `1` and `2` to a page.
- `--depth` (default 64) bounds the read cost per pass; `--json` prints one
  machine-readable result object for a dashboard; `--dry-run` prints the alert
  payload instead of POSTing it.
- curl + bash only — no jq, no foundry — so the same script runs from a cron
  box, a container, or your laptop, and it needs no signing key at all.

Exercise it right after gate 5, on the deployed mailbox: with one slot burned
and a second delivered slot left unburned, the watchdog reads green (`0`)
while the unburned slot is inside its grace window and turns red (`1`) once it
exits. That is the same polarity the local proof asserts.

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
- **Compost is wired on the E2 receive path too.** `msg recv-e2` now passes
  `AutoBurn` to `chain.Watch` (default on; `-auto-burn=false` disables it),
  matching what `msg recv` always did. Before this it never erased the
  delivered pointer, so a configured MyceliumMailbox slot kept it forever —
  the local Anvil proof above asserts the erased slot, which is how the gap
  was found.
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
