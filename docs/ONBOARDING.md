# Mycelium m³ — onboarding (zero → first message)

**What it is, in one line:** an E2E-encrypted, no-relay private messenger. You
talk point-to-point (wallet-to-wallet, no server/relay in the middle), and
messages **rot** — they're compostable by design.

This page is the shortest honest path to a first message. It's copy-paste
first, prose second.

**Get the binary** (`v0.2.0` is current — always grab `/releases/latest`):

```bash
# either download from the releases page, or build from source:
curl -LO https://github.com/liqdmetal/mycelium/releases/latest/download/mycelium-windows-amd64.exe
#  ^ then run the rest of this guide as:  ./mycelium-windows-amd64.exe <cmd>
#  or, if you build/install it:
go install github.com/liqdmetal/mycelium/cmd/mycelium@latest
```
Every command below is shown as `mycelium …` — substitute
`./mycelium-windows-amd64.exe` if you downloaded the exe. Verify with
`mycelium -version`.

---

## 0. Sanity check — no chain, no wallet, no setup

Run the demo: it exercises the full **send → receive → burn** lifecycle
in-process (encrypt, deliver, TTL-expire, and reject after burn). Nothing
touches a network.

```bash
mycelium demo
```

Expected tail: `OK: body evicted, key erased, anchor inert.` If that runs,
your binary works — the rest is just which chain you can reach.

---

## What's usable right now

Read this first. Chains are **not** equally ready.

| Chain | Usable today? | For a first message you need |
|---|---|---|
| **DERO** | ✅ **live, mainnet** | a funded + registered DERO wallet running `--rpc-server` |
| **Solana** | ✅ **live, mainnet** (self-messaging demo) | a Solana keypair + a little SOL for fees |
| **EVM** | 🧪 **dev only** (local `anvil`/geth) | a local EVM node + an account |
| **XMR** | 🚧 **not yet** — backend built, on-chain blocked | a synced Monero node (content rides off-chain) |

> The fastest real message today is **DERO** or a **Solana self-test**. EVM is
> a local-node smoke test. XMR is not a place to send yet.

The identity model is one simple idea (explained once, below), then the
per-chain fast paths.

---

## Identity keys — the one concept to get

For chains without native payload encryption (EVM, Solana, XMR) your message
is wrapped in mycelium's own E2E envelope, keyed to a **mycelium identity
keypair** — *chain-independent*, one identity across every chain.

```bash
mycelium msg keygen          # prints:  pub: <64 hex>   priv: <64 hex>
mycelium msg keygen -out key # or write priv to a file (0600); keeps stdout clean
```

- Give **`pub`** to anyone who will message you — they encrypt to it.
- Keep **`priv`** secret — only it decrypts what's addressed to you.
- **DERO doesn't need this** — DERO encrypts natively. Identity keys are for
  EVM / Solana / XMR envelopes.

---

## DERO — live mainnet, fastest real first message

Short, no-relay, natively E2E-encrypted by DERO. Costs a tiny bit of DERO per
message.

**One-time:** install `dero-wallet-cli`, create a wallet, register it on-chain,
and fund it (any exchange).

```bash
# terminal 1 — keep open. This is your endpoint: it holds your keys,
# encrypts/decrypts natively, and serves messages.
dero-wallet-cli --wallet-file mywallet.db --rpc-server --rpc-bind 127.0.0.1:20209
#   (first run: `register` then `address` inside the wallet prompt)

# terminal 2 — send a first "hi" to a friend's dero1… address.
# whisper's default RPC is 127.0.0.1:20209 — matches the wallet above.
mycelium whisper send -to dero1q…your-friend… -msg "hi"

# same terminal / another — watch for replies (leave running):
mycelium whisper recv
```

Full friend-to-friend setup: [`docs/PEER_SETUP.md`](PEER_SETUP.md).

> The `msg` surface also drives DERO (`-chain dero`, the default) but needs an
> explicit `-rpc URL`: `mycelium msg send -chain dero -rpc
> http://127.0.0.1:20209/json_rpc -to dero1… -msg "hi"`. `whisper` exists purely
> as the no-extra-flag DERO shortcut above.

---

## Solana — live mainnet, self-test in one command

A mycelium mailbox program is **deployed and verified on Solana mainnet**
(default program `4a3DB9nd5q37nCJbgTSDaNML8Vn5nCJNAuJUHpMNmXpa`, v3). Today the
client self-messages (delivers to your own inbox); cross-wallet delivery needs
both parties running the backend.

**One-time:** a funded Solana keypair + a little SOL for tx fees.

```bash
# your signer keypair JSON (create with `solana-keygen new -o id.json`, or reuse one)

# SEND to yourself — pass YOUR base58 public key as -to (not the literal word "self"):
mycelium msg send -chain solana -keyfile id.json -to <your-solana-pubkey> -msg "hi"

# RECEIVE from your own inbox:
mycelium msg recv -chain solana -keyfile id.json
```

> ⚠️ `-to self` does **not** work — the backend needs a real base58 address.
> Put your actual pubkey there.

---

## EVM — dev-only (local node)

EVM calldata is public, so messages ride the E2E secure envelope — content is
private even though the tx is visible. **Verified against a local `anvil`
node; not against a public EVM chain yet.** Needs your address + identity keys.

```bash
anvil &                                # local dev node on http://127.0.0.1:8545
mycelium msg keygen                    # one-time: your identity pub/priv

mycelium msg send -chain evm -rpc http://127.0.0.1:8545 \
  -from <0x-your-anvil-account> -to <0x-friend-account> \
  -key <your-priv> -peer-pub <friend-pub> -msg "hi"

mycelium msg recv -chain evm -rpc http://127.0.0.1:8545 \
  -from <0x-your-anvil-account> -key <your-priv>
```

---

## XMR — not ready yet (honest)

Monero has **no per-recipient message field** (only an 8-byte payment id), so
an XMR message is a **knock** (a signal ≤8 bytes), and the content rides
**off-chain rendezvous**. The backend is built and mock-tested, but live
verification is pending a synced Monero node — **don't point real money at it
or rely on it for messaging yet.**

---

## Long bodies & always-on receive (`mailbox`)

Short `msg send` lines ride a tx directly. For **longer bodies** the content
is E2E-encrypted, held off-chain by the sender, and a pointer rides the DERO
whisper path (XMR contributes identity only). The **mailbox** is the always-on
cross-chain receiver that serves + scans + decrypts long bodies headless:

```bash
mycelium mailbox run -dir ~/my-mb -chain dero -rpc http://127.0.0.1:20209/json_rpc   # serve+scan+decrypt (keep open)
mycelium mailbox list -dir ~/my-mb                    # show what arrived
mycelium mailbox get  -dir ~/my-mb <cid-or-txid>      # print one message
```

`mailbox run` needs the same wallet RPC your DERO endpoint uses (`-rpc`, above
it's your wallet's 20209). It generates and prints your long-term pubkey on
first run — give it to senders so they encrypt bodies to you.

---

## Honest limits (so you're not surprised)

- **DERO** hides sender + content natively (ring sig). **EVM / Solana / XMR**
  expose *that a tx/event happened and roughly when* — the **content** stays
  private only via the envelope.
- **XMR** carries short signals only; content is off-chain (B1 route).
- **Solana** self-messaging today; cross-wallet needs both ends running the
  backend.
- **No relay = point-to-point unicast.** Group *broadcast* still needs a relay
  or smart contract. For shared-key rooms instead, use `mycelium web` or
  `mycelium channel`.

## Donations
```bash
mycelium donate --all
```

## Commands at a glance
```
mycelium demo                             in-process send→recv→burn (no chain)
mycelium msg send|recv -chain dero|evm|xmr|solana     short message, any chain
mycelium msg send-long -to dero1… -recipient-pub HEX -msg "long body"
mycelium msg keygen                       identity keypair (E2E on non-DERO)
mycelium mailbox run|list|get             always-on cross-chain long-body receiver
mycelium whisper send|recv                DERO no-relay short (default -chain dero)
mycelium donate [chain] | --all           per-chain donation rail
mycelium web / channel / chat             browser chat / IRC-style rooms (DERO)
```
