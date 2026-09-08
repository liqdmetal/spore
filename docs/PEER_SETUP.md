# Spore — peer setup for friends

Spore m³ is a **no-relay private messenger**. Two people talk **point to
point**: a whisper rides a real DERO transaction, encrypted end-to-end by
DERO. There is no server, no box, no operator in the middle — but that means
**each person runs their own endpoint**. This guide is the 5-minute friend path.

> Honest scope: **DERO is live and mainnet-verified.** EVM and Solana are
> live-verified (see `README.md` chain-status table); **Monero is mock-verified
> only** — not yet usable for real messaging (node still syncing).

---

## What you need (one-time)

1. **The `spore` binary** — download `spore-windows-amd64.exe` from the
   [releases page](https://github.com/liqdmetal/spore/releases).
2. **A DERO wallet** — install [dero-wallet-cli](https://github.com/deroproject/derohe/releases)
   and create one. You need a tiny bit of DERO for postage (~0.001 DERO per
   message) and a one-time registration fee.
3. **A public DERO daemon to point at** (you don't run a node):
   - `dero-ch4k1pu.mindmesh.de:10102` (public), or any public daemon.

## Step 1 — wallet setup (once)

```bash
# create a wallet (or restore an existing one)
dero-wallet-cli --wallet-file mywallet.db
# in the wallet: register on-chain (one-time) then note your address
#   command: register
#   command: address
```

Fund the wallet with a small amount of DERO (from any exchange). Registration
needs the chain's minimum; postage is ~1 atomic unit per whisper, so a tiny
balance lasts a long time.

## Step 2 — run the wallet RPC server (keep this window open)

```bash
dero-wallet-cli --wallet-file mywallet.db --rpc-server --rpc-bind 127.0.0.1:20209
```

Leave it running. Spore whispers send and receive **through this wallet** —
you do not run a node. `20209` is the port spore's `whisper` commands expect
by default.

## Step 3 — message!

In a second terminal:

```bash
# your wallet RPC is on 20209 (spore's default, so -rpc is optional).
# SEND a whisper (<=80 chars)
spore-windows-amd64.exe whisper send \
  -to dero1q...friend-address... \
  -msg "hey from spore"

# RECEIVE (keep running to watch for messages)
spore-windows-amd64.exe whisper recv
```

When a message arrives you'll see:
```
whisper 954f149f…: hey from spore
```

That's it. If someone else runs the same three steps with **their** wallet, you
can message each other across the DERO network — no server, no relay, nobody
but the two of you.

---

## How privacy actually works (so you trust it)

- A whisper is a **real DERO transaction** carrying an encrypted payload.
  DERO encrypts every tx payload point-to-point, so only the recipient's key
  reads it.
- **No body sits on-chain.** Long messages ride a peer-to-peer body store and
  rot after a TTL; the on-chain anchor holds only a hash and a burn deadline.
- **Current path limitation:** one-shot body encryption is confidential but not
  forward-secret; a later compromise of the recipient's long-term key can
  decrypt a copied ciphertext before it expires. The X3DH + Double Ratchet
  session is implemented in `internal/ratchet`, but its 0xE2 wire integration
  is not shipped yet.
- **Target behavior:** ratcheted per-message keys are erased after use, so
  copied historical ciphertext becomes undecryptable after key compromise.
  Do not claim that target for the current direct path.

## What's NOT live yet (honest)

- **Monero** is mock-verified only. Don't point real money or rely on it for
  messaging yet — it needs live-node verification (a `monero-wallet-rpc`) once
  the syncing node catches up. EVM and Solana backends are live-verified; see
  `README.md` for their precise status.
- A friend must run their **own** wallet + `whisper recv`. This is the privacy
  model: no shared box to subpoena, no operator. The cost is that "just chat in
  a browser with no setup" isn't the experience — use `spore web`
  (shared-key rooms) for that instead.

## Dev / power-user

```bash
go install github.com/liqdmetal/spore/cmd/spore@latest
spore -version
spore donate --all   # per-chain donation rail
```
