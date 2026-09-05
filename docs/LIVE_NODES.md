# Live-node spec — verify EVM + XMR for real

m³ EVM and XMR backends are code-complete and mock-verified. To make them
**live-usable** (the way DERO is), each needs a real node to point at. This
spec covers both, on the Hetzner box (65.108.140.19) where the DERO node
already lives.

## Goals
1. **XMR (Monero)** — a live `monero-wallet-rpc` + daemon on Hetzner, so
   `mycelium msg send/recv -chain xmr` verifies end-to-end like DERO did.
2. **EVM** — a live EVM JSON-RPC endpoint (any EVM-compatible chain) so the
   `internal/evm` backend + `msg -chain evm` verifies for real.

---

## 1. Monero node on Hetzner

### Why a node is needed
Monero has no public-API node like DERO's. The XMR backend talks to a **wallet
RPC** (`transfer`, `get_transfers`, `get_height`, `get_address`), which needs a
local `monerod` (daemon) synced to the chain + a wallet. Both must run on the
box.

### Requirements on 65.108.140.19
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
7. monero-wallet-rpc --wallet-file /opt/monero/wallet/mycelium \
     --rpc-bind-port 18082 --daemon-address 127.0.0.1:18081 \
     --rpc-login mycelium:CHANGEME --password-file <...> &
8. systemd units for monerod + monero-wallet-rpc (restart on boot)
9. Verify locally on the box:
     mycelium msg send -chain xmr -rpc http://127.0.0.1:18082/json_rpc \
        -to <wallet-b-subaddr> -msg "hi"
     mycelium msg recv -chain xmr -rpc http://127.0.0.1:18082/json_rpc
```

### XMR note (repeat)
Monero carries only an **8-byte payment id**. Short signals ("hi", "sup?")
verify on-chain. Longer text must ride off-chain rendezvous (VISION §3) — so
live XMR verification is scoped to **short no-relay signals**, which is the
honest capability. Long-body XMR is a rendezvous integration, separate.

---

## 2. EVM node / RPC target

### Why a node is needed
`internal/evm` talks JSON-RPC to any EVM-compatible chain. No chain is wired
yet, and Obscura was scrubbed (not production-ready). Options for a real EVM
target:

| Option | Pros | Cons | Effort |
|---|---|---|---|
| **Public EVM RPC** (e.g. a testnet — Sepolia/Holesky) | free, instant, faucet | backend posts 0-value txs as calldata; needs a funded account on that RPC's signer | low |
| **Local dev node** (geth/anvil on Hetzner) | full control, no external dependency | must run + fund an account; private | med |
| **EVM chain with a funded wallet RPC** | real usage | depends on which chain the user runs | varies |

### Recommended: a public testnet via an account the user controls
The `internal/evm` backend signs via `eth_sendTransaction` with `from` = our
address on that chain. So live verification needs:
1. An **EVM wallet** (MetaMask-style) with an address on the chosen chain.
2. **A JSON-RPC endpoint** for that chain (public or local) the wallet can
   submit to.
3. A tiny native-token balance for gas.

### Steps
```
1. Pick a chain: Sepolia (public testnet, faucet) is the simplest live target.
2. Wallet: user provides an EVM address + a way to sign/send on it
   (local geth account, or a wallet-RPC the CLI can reach).
3. RPC endpoint: public https endpoint for Sepolia, or run anvil/geth locally.
4. mycelium msg send -chain evm -rpc <endpoint> -from <0x...> \
        -to <friend-0x...> -msg "hi"
   mycelium msg recv -chain evm -rpc <endpoint> -from <0x...>
```
The `evm` backend scans recent blocks for txs addressed `to == from`, so recv
works on the same RPC. Verify a message round-trips between two real EVM
addresses.

---

## Decisions needed (user)
1. **XMR install path**: prebuilt monero tarball (fast, recommended) vs full
   source build on the box? And confirm disk headroom first.
2. **XMR verification scope**: OK that live XMR proves *short signals* only
   (long text needs the rendezvous work)? Or do you want the rendezvous
   integration speced first?
3. **EVM target chain**: which chain to verify on (recommend a testnet like
   Sepolia), and do you have a funded EVM address to sign with?

## Not live-verified: what that means
Until these nodes run, `internal/evm` + `internal/xmr` remain **mock-verified**:
correct against the seam and the RPC shape, but not confirmed against a real
chain. This spec is the path to close that, exactly like the DERO node did.
