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

(Not building? The checksum-verified installer in
[`docs/ONBOARDING.md`](ONBOARDING.md#get-the-binary) covers the same platforms
the release matrix ships — including the `spore-peer` transport this document
describes.)

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
  `127.0.0.1:8099` if you only ever fetch locally. For a node that stays
  up regardless of your CLI sessions, run the dedicated daemon instead:
  `spore serve -dir ~/.spore/hold -listen 0.0.0.0:8099 -reap-every 10m`
  (same wire protocol, loopback by default, signal-driven shutdown).
- `-store-reap-every 10m` — optional background composting: expired bodies
  leave `-store-dir` on this cadence instead of only when their CID is
  asked for. Expiry is always enforced at read time either way; this flag
  only controls when the bytes leave your disk. For a node that stays up
  (this page's receiver), set it to a fraction of the smallest TTL you
  issue.

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

## Running a fabric relay (volunteer operators)

If a contact hands you a `FabricRelays` line for their card, they are asking
you to run the pointer-forwarding half ([`RELAY_FABRIC.md`](RELAY_FABRIC.md)):
a `spore-peer serve -fabric` daemon that queues 74-byte pointers for
recipients to drain. It is the same binary and the same hold as above — one
flag turns the body node into a relay:

```bash
spore-peer serve --dir /var/lib/spore-peer/hold --listen 0.0.0.0:8099 \
  -fabric \
  --announce-addr relay.example.org:8099 \
  --pidfile /run/spore-peer/spore-peer.pid \
  --fabric-per-handle 32 --fabric-horizon 604800 --fabric-max-lease 604800 \
  --fabric-fput-rate 60 --fabric-max-regs 50000
```

- `--announce-addr` — what fabric clients and `sporepeer://` senders must
  dial: your PUBLIC host:port (behind NAT/container boundaries), not the
  bind address. Echoed on stderr ahead of the readiness line.
- `--pidfile` — written atomically **before** the bind; a graceful stop
  (SIGTERM, Ctrl+C/Ctrl+Break) removes it, a SIGKILL leaves it — the
  dead-run signal a supervisor keys on. See `deploy/` in the spore-peer
  repo for a hardened systemd unit and a Windows wrapper.

The fabric knobs (every one is optional; these are the defaults). The
daemon echoes the effective values on the `listening on` readiness line,
so you can verify a tuning change on the running process:

| Flag | Default | What it bounds |
|---|---|---|
| `--fabric-per-handle` | 32 | Queued pointers per handle. FIFO, evict-oldest — compost, don't hoard. This is the flood bound: a handle-spammer's garbage evicts itself, and a drain costs at most this much. |
| `--fabric-horizon` | 604800 (7d) | How far out a pointer's burn deadline may be. Every compost path is deadline-triggered, so uncapped far-future deadlines would be immortal envelopes — unbounded disk. Lower it if you want tighter churn. |
| `--fabric-max-lease` | 604800 (7d) | freg lease cap in seconds. A recipient re-registers at renewal; leases are memory-only (a restart clears them; clients re-register on their next drain — queues are NOT lost). |
| `--fabric-fput-rate` | 60 | Per-IP publish rate per minute. fpop shares this window: both are unauthenticated parser paths and neither is cheaper to flood than the other. |
| `--fabric-max-regs` | 50000 | Live registration budget. freg is unauthenticated, so this — not memory growth — is the DoS answer; a full budget answers 503 and never evicts others' registrations. |
What a relay operator can and cannot learn: pointers are inert (the
ratchet is the filter — a relay sees a public handle, timing, and a sender
IP; never message content, never the session id). Running a relay exposes
your IP to publishers and drainers exactly as running the body node
exposes it to fetchers — same posture, one more port.

## Sender cover traffic (F4b, optional)

If you send over the fabric (`-route-fabric`), a first-hop relay sees your
publish times per handle and can fingerprint your sending cadence. Cover
traffic buries that signal: a small background loop publishes **decoy
pointers** to the same handles at Poisson-drawn intervals, so the relay's
view of your handle is a dense stream that hides the sparse real sends.

Run it on the SENDER's machine, long-lived (screen/tmux/service), one loop
per contact you fabric-send to:

```
spore fabric cover \
  -fabric-seed <recipient's contact seed> \
  -fabric-relay relay1.example.org:9000 -fabric-relay relay2.example.org:9000 \
  -fabric-epoch 2 \
  -cover-session <sid>,<sid> \
  -fabric-cover-rph 2 \
  -state-dir ~/.spore/state
```

- `-cover-session` — the session ids your sends actually use (`spore msg
  sessions`). Cover parked on any other handle hides nothing; the loop
  targets every relay × session × drain epoch (n and n−1), exactly like a
  real send.
- `-fabric-cover-rph` — cover events per hour. **Recommended: 2** for
  personal handles. Cover must roughly dominate your real send rate, not
  sprinkle: a rate wildly mismatched to your actual volume is its own
  signal. There is no default — cover changes your node's public request
  profile, so enabling it is a conscious choice. (Implementation caps the
  rate at 720/h.)
- Cost: ~3.5 KB/day of relay traffic at 2/h, plus a short-TTL decoy body
  on your own disk (reaped automatically).
- Your recipient's drain loop **pre-filters** decoys by route — cover
  costs them one local comparison per decoy, never a fetch or decrypt.
- `-fabric-cover-fold` (on `send-e2`/`reply-e2`) delays a real publish by
  one Uniform[0, cover-interval) draw so it lands inside the cover stream —
  trade up to a full cover interval of send latency for send-time hiding.
  Off by default; if you enable it, the rate you pass here must match your
  cover loop's `-fabric-cover-rph`.

What cover does NOT do (docs/RELAY_FABRIC_F4.md §2): it does not hide your
IP (decoys come from the same address), does not protect a recipient's
drain dials at all, and does not defeat a global traffic observer. Volume
itself remains a signal — five sends in an hour after a silent week shows
through everything except fold.
