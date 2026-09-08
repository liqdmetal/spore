# Spore — user guide

> **This guide is the DERO path.** Spore is multi-chain — the same core runs
> on EVM, Solana and (pending live-verify) Monero via `spore msg ... -chain
> dero|evm|xmr|solana`. See `README.md` for the chain-status table and
> `docs/LIVE_NODES.md` for what's verified.

Spore is a **no-relay private messenger on the DERO blockchain**. You write to
a person's DERO address; the message reaches them without ever passing through
a server you don't control. Messages are designed to *rot*: what lingers
on-chain is a hash and a dead key, not readable content.

This guide covers the `spore` CLI. Companion docs: `README.md` (overview),
`design.md` (threat model + status), `WHISPER.md` (the no-relay architecture),
`UX_PREVIEW.html` (UI mockup).

## 1. What spore is — the privacy promise in plain language

**The core claim.** Every DERO transaction already encrypts its payload
point-to-point so that only the recipient's wallet can read it. Spore rides
that property instead of fighting it.

- **Short messages ("whispers")** are tucked into the payload of a real DERO
  transaction. There is **no relay, no box, no shared store, and no exposed
  IP**: each person only ever talks to their own wallet and their own node.
- **Long messages** (more than one sentence, files, prose) never fit on-chain.
  They are encrypted to the recipient's key, held *on the sender's own disk*,
  and fetched **peer-to-peer** by the recipient. Only the sender and the
  recipient ever hold the bytes.
- **Rooms** (`channel`/`web`) are a separate, optional lane for group chat.
  Public rooms are readable by anyone but lines vanish after a short TTL;
  private rooms are sealed to a key the box itself never holds. Someone has to
  volunteer to host the box.

Because every whisper is a real transaction, the sender's identity is hidden by
DERO's ring signatures, but **the fact that "a transaction happened around time
T" is visible to the whole chain.** Sparse by construction — that's the honest
limit, spelled out in section 7.

## 2. What you need before you start

For any messaging mode you need:

1. **A DERO wallet running its RPC server.** Spore signs through the wallet.
   Start your wallet with `--rpc-server`, which by default listens on
   `http://127.0.0.1:20209/json_rpc`. Pass that URL to spore with `-rpc`.
   If your wallet RPC is password-protected, add `-rpc-login user:pass`.
   You need a little DERO balance to pay transaction postage when sending.
2. **A DERO node (daemon).** Spore resolves DERO names and confirms sends
   against a daemon's RPC, default `http://127.0.0.1:10102/json_rpc`.
   - **Run your own node for full privacy.** Then your wallet and your traffic
     touch only infrastructure you own.
   - **Or point `-daemon` at a public node** for convenience. This is the
     convenience-vs-privacy tradeoff: a public daemon is fine for name
     resolution and confirming that a transaction was mined, but you are
     trusting that node operator more than if you ran your own.
3. **The Rust `spore-peer` transport binary** (from the `derohe-rs` repo) —
   needed **only for long messages** (section 4). Short whispers don't need it.

## 3. Quick start: short messages (whispers)

A whisper is a real DERO transaction whose payload carries a short line,
encrypted by DERO to the recipient's wallet. No infrastructure in between.
Keep it to roughly one sentence — the payload budget is about **80–95 bytes**
of text. This is for a line, an invite, a ping — not prose.

**Sender** — Alice writes to Bob's address (or his DERO name, section 6):

```sh
spore whisper send \
  -rpc http://127.0.0.1:20209/json_rpc \
  -daemon http://127.0.0.1:10102/json_rpc \
  -to <bob's dero1... address or name> \
  -msg "meet at the usual place"
```

Spore prints the transaction id. Once mined (roughly one block), Bob can read
it.

**Recipient** — Bob runs a poller that watches his own wallet for incoming
whispers and prints them as they land:

```sh
spore whisper recv -rpc http://127.0.0.1:20209/json_rpc
```

Each incoming whisper prints as `whisper <txid>: <text>`. Leave `recv` running,
or poll it periodically. Bob only needs his own wallet + node — nothing is
pushed from a third-party server.

## 4. Long messages, end to end

A whisper can't carry prose. For anything longer (or a file), the body is
encrypted to the recipient's **spore long-term key**, held on the **sender's
disk**, and a short *pointer-whisper* (sender ephemeral pubkey + body checksum)
is sent on-chain. The recipient later fetches the body peer-to-peer, verifies
its checksum (sha256), decrypts, and both sides let the keys rot.

### Step 0 — each side generates a long-term key once

```sh
spore whisper keygen -key mycompost.key
```

This writes a persistent private key to `mycompost.key` (permissions 0600) and
prints the matching **public key** to share. Treat the `.key` file as a secret —
guard it like a wallet.

**Key exchange is manual today:** Bob tells Alice his long-term **public key**
and a **reachable peer address** out of band (a chat, a note, in person). Keep
the private key file to yourself.

### Step 1 — sender encrypts and holds the body

```sh
spore whisper send-long \
  -to <recipient address or name> \
  -recipient-pub <recipient's spore long-term pubkey hex> \
  -msg "the real long message goes here, as long as you like" \
  -out-dir myoutbox \
  -daemon http://127.0.0.1:10102/json_rpc \
  -rpc http://127.0.0.1:20209/json_rpc
```

Use `-file /path/to/doc` instead of `-msg` to send a file's contents. The body
is encrypted to the recipient's key and written to `-out-dir` (default
`spore-outbox`) on **your** machine; a pointer-whisper goes on-chain. The
body itself never rides a block.

Spore then tells you to make the body fetchable:

```sh
spore-peer serve --dir myoutbox
```

Run that in the background and leave it up until the recipient has fetched.
Share your reachable `host:port` with the recipient.

### Step 2 — recipient fetches and decrypts

Bob runs `whisper recv` with his key file and Alice's peer address:

```sh
spore whisper recv \
  -rpc http://127.0.0.1:20209/json_rpc \
  -key mycompost.key \
  -peer-addr <alice's host:port> \
  -peer-bin spore-peer \
  -in-dir myinbox
```

When the pointer-whisper for a long body arrives, `recv` fetches the ciphertext
from Alice's peer transport, verifies its checksum against the pointer, and
decrypts it with your key, printing `>>> long message (<N> bytes): ...`. Bodies
are pulled into `-in-dir` (default `spore-inbox`).

**Both peers must be online at fetch time.** If Bob is down when Alice serves,
the body waits on Alice's disk. This is the built-in store-and-forward tax of
having no relay.

> If you run `recv` without `-key`, it prints long-message pointers but can't
> fetch or decrypt them. If you pass `-key` but the file doesn't exist yet,
> `recv` creates it and tells you to share its pubkey with senders. Pointers
> without `-peer-addr` are reported but not fetched.

## 5. Channels and rooms (the group/public lane)

For more than one person at once, someone runs a **channel box** — a rendezvous
point that relays short, TTL-bounded lines and tracks who's online.

- **Public rooms** are readable live by anyone; lines expire after the box's
  TTL (`-linettl`, default 15 min) and are gone.
- **Private rooms** are sealed to a channel key that the box never holds — the
  box stores ciphertext it cannot read. Share the key with your friends out of
  band.
- The box is trusted for **availability and liveness only**, never for
  confidentiality. Someone must volunteer to host it and keep it reachable.

**Host the box:**

```sh
spore channel -listen :19192        # CLI/chat API box
spore web -listen :19192            # same box + an in-browser chat UI
```

`web` also accepts `-cert cert.pem -key key.pem` to serve over HTTPS, and
`-wallet-rpc`/`-wallet-login` to let the browser page post whispers through
your wallet. `channel` and `web` both set TTLs via `-linettl` and presence via
`-presencettl`.

**Join a room:**

```sh
spore chat -box http://host:19192 -channel general -nick alice
```

Post a single line and exit with `-say "hello"`, print who's online with
`-online`, or decrypt a private room by passing `-key <hex>`. Rooms are the
casual, semi-public lane — use whispers (sections 3–4) when you want the
no-relay, no-box hard-privacy path.

*(Spore also ships an older Model A "mailbox" mode — `spore daemon` +
`spore send` — where each endpoint runs a durable inbox and bodies are pushed
over HTTP then burned at a TTL. See the reference table below.)*

## 6. DERO names

Instead of a long `dero1...` address you can address someone by their DERO name
in any `-to` flag:

```sh
spore whisper send -to alice -msg "hello"
```

Spore resolves the name through the daemon you point at with `-daemon`
(default `http://127.0.0.1:10102/json_rpc`). A full `dero1...` address is used
directly and needs no daemon. Name resolution is a convenience over your node
— one more reason an honest operator runs their own.

## 7. What "rot" means, and the honest limits

> **Security status correction:** the current direct DERO whisper, 0xE1 public-chain envelope, and one-shot long-body paths are encrypted but not forward-secret. A later compromise of the recipient's long-term key can retro-decrypt recorded ciphertext. The X3DH + Double Ratchet session in `internal/ratchet` is implemented at the crypto layer but its 0xE2 wire adapter is not shipped yet. Treat forward secrecy as unavailable until that integration and its end-to-end tests land.



**Rot = content that becomes unrecoverable on purpose.** On DERO, content in a
block can never be deleted, so compostability is done two ways: **(a)** keys
are ephemeral and erased after use, turning any lingering ciphertext into
permanent garbage; and **(b)** bulk content never goes on-chain at all — long
bodies live on a sender's disk under a TTL, then are reaped and their keys
erased. After a message is read (or its TTL passes), old bodies are gone even
to the participants.

Be clear-eyed about what spore does *not* hide:

- **Metadata persists.** A whisper is a real transaction; anyone watching the
  chain can see "a transaction happened at roughly this time." The ring
  signature hides *who* sent it, but not that a message occurred. Long-body
  pointers on-chain are permanent but dead — they point at content that has
  already rotted.
- **Long messages need both peers online at once** (store-and-forward tax), as
  noted in section 4.
- **Group broadcast has no free lunch.** No-relay is unicast and sparse by
  design. Real-time group rooms need a hosted box (section 5); broadcasting a
  private message to many people without any box would cost one transaction
  per recipient.
- **Key exchange is manual.** You share your long-term public key and a peer
  address out of band. Verify identities through whatever channel you trust —
  there is no built-in directory or contact discovery yet.

## 8. Command reference

| Command | What it does |
|---|---|
| `spore demo` | Runs an in-process send → receive → burn lifecycle with no node (sanity check). |
| `spore whisper send -rpc URL [-rpc-login u:p] -daemon URL -to ADDR-OR-NAME -msg TEXT` | Send a short (~80–95 byte) no-relay message as a DERO tx payload. |
| `spore whisper send-long -to ADDR-OR-NAME -recipient-pub HEX -file F \| -msg TEXT [-out-dir D] [-daemon URL] [-rpc URL]` | Encrypt a long body/file to the recipient's key, hold it locally, post a pointer-whisper. |
| `spore whisper recv -rpc URL [-rpc-login u:p] [-key KFILE] [-peer-addr host:port] [-peer-bin B] [-in-dir D]` | Poll for incoming; print whispers; fetch + decrypt long bodies when `-key`/`-peer-addr` are set. |
| `spore whisper keygen [-key KFILE]` | Create a persistent long-term pub/priv key (writes priv to `KFILE` at 0600). |
| `spore keygen` | Print a fresh medium-term key (pub + priv hex) for the Model A mailbox mode. |
| `spore daemon -listen :PORT -dir DIR -priv HEX -rpc URL [-rpc-login u:p]` | Run a recipient mailbox: durable HTTP inbox + chain scanner that decrypts and burns bodies (Model A). |
| `spore send -to ADDR -peer-pub HEX -peer-inbox URL -msg TEXT [-ttl 1h] [-rpc URL]` | Model A: encrypt to the recipient's medium-term key, push the body to their inbox, post an anchor. |
| `spore channel -listen :PORT [-linettl 15m] [-presencettl 1m]` | Run an IRC-style channel box (public/private rooms, presence, TTL lines). |
| `spore chat -box URL -channel NAME -nick X [-key HEX] [-interval 3s] [-say TEXT] [-online]` | Join a channel box room: tail it, post a line, list who's online, or decrypt a private room. |
| `spore web -listen :PORT [-cert C -key K] [-wallet-rpc URL]` | Run a channel box **and** serve the in-browser chat UI on the same origin; optional HTTPS. |

Every short-whisper and send command also accepts `-rpc-login user:pass` when
your wallet RPC uses basic auth.
