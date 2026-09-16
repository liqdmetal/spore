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
# New DERO sends use the E2 kit and default to ring size 16. Spore accepts only 8 or 16.
# SEND a forward-private E2 whisper; stdin keeps plaintext out of argv
spore-windows-amd64.exe whisper send \
  -to dero1q...friend-address... \
  -identity ~/.spore/identity.key \
  -bundle ./friend-bundle.json \
  -pinned-sig FRIEND_SIGNING_KEY_HEX \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -ringsize 16

# RECEIVE (keep running to watch for messages)
spore-windows-amd64.exe whisper recv \
  -identity ~/.spore/identity.key \
  -spk ~/.spore/spk.key \
  -opk-pool ~/.spore/opk-pool.json \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
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

- A new whisper is a **real DERO transaction** carrying an opaque 0xE2
  pointer. DERO carries the pointer; X3DH + Double Ratchet encrypts the body.
- **No body sits on-chain.** Long messages ride the configured off-chain body
  store and rot after a TTL; the on-chain anchor holds only the pointer.
- **New DERO sends are forward-private:** `whisper send`, `whisper send-long`,
  `msg send -chain dero`, and `msg send-long` are compatibility names for the
  canonical X3DH + Double Ratchet path. The DERO transaction carries only the
  opaque E2 pointer; the body remains off-chain.
- **Old records remain legacy:** native DERO payloads, 0xE1 envelopes, and
  one-shot long-body records are receive-only compatibility data and are not
  forward-private after a long-term-key compromise.

## What's NOT live yet (honest)

- **Monero** is mock-verified only. Don't point real money or rely on it for
  messaging yet — it needs live-node verification (a `monero-wallet-rpc`) once
  the syncing node catches up. EVM and Solana backends are live-verified; see
  `README.md` for their precise status.
- A friend must run their **own** wallet + E2 receiver (`whisper recv` with
  the E2 kit, or `msg recv-e2`). This is the privacy model: no shared box to
  subpoena, no operator. Bare `whisper recv` remains only for old native mail.

## Dev / power-user

```bash
go install github.com/liqdmetal/spore/cmd/spore@latest
spore -version
spore donate --all   # per-chain donation rail
```

## Serverless bodies (`sporepeer://`) — nobody holds your bytes but you two

`-store http://mailbox` needs a mailbox; `-store nostr://` publishes to a
public commons. The third posture needs **neither**: the sender's own node
holds the body and the receiver pulls it P2P over the spore-peer transport.
Only the two of you ever hold the bytes.

Sender (you hold and serve your bodies):

```bash
spore msg send-e2 -to FRIEND_ADDR -identity ~/.spore/identity.key \
  -bundle ./friend-bundle.json -pinned-sig FRIEND_SIGNING_KEY_HEX \
  -store sporepeer://FRIEND_IP:8099 \
  -store-dir ~/.spore/hold -store-serve 0.0.0.0:8099 \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
```

- `-store sporepeer://FRIEND_IP:8099` — the peer to FETCH from (their
  listener; also where your receive-side pulls land).
- `-store-dir ~/.spore/hold` — where YOUR bodies are held until their TTL
  rots them.
- `-store-serve 0.0.0.0:8099` — bind YOUR spore-peer listener; the startup
  line prints the exact `sporepeer://` address to give your contact. Use
  `127.0.0.1:8099` if you only ever fetch locally.

Receiver (keep it running; fetches from the sender's node):

```bash
spore msg recv-e2 -identity ~/.spore/identity.key -spk ~/.spore/spk.key \
  -opk-pool ~/.spore/opk-pool.json \
  -store sporepeer://SENDER_IP:8099 -store-dir ~/.spore/hold \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
```

Honest limits: **both endpoints must be online** for the fetch — the
sender's node IS the store, which is exactly why no operator exists. The
transport is unauthenticated by design: anyone who can reach the port can
fetch the (inert-without-the-ratchet-key) ciphertext, so firewall the port
if that bothers you. A body whose TTL has passed composts on the holder's
disk; a late fetch then gets a clean 404, not silence. Interoperates with
the standalone Rust `spore-peer serve/fetch` binary in both directions.
