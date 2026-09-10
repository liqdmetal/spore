# Live-node spec — verify EVM + Solana + XMR for real

m³ EVM and Solana backends are **live-verified**; XMR is still mock-verified.
This spec tracks the live nodes that prove each for real, on the Hetzner box
(YOUR-NODE-HOST) where the DERO node already lives.

## Goals / status at a glance
1. **EVM** — ✅ **live-verified** on a local anvil node (below).
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
