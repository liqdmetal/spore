# Spore — user guide

> **This guide is the DERO path.** This project is multi-chain — the same core runs
> on EVM, Solana and (pending live-verify) Monero via `spore msg ... -chain
> dero|evm|xmr|solana`. See `README.md` for the chain-status table and
> `docs/LIVE_NODES.md` for what's verified.

This project is a no-relay private messenger on the DERO blockchain. You write to
a person's DERO address; the message reaches them without ever passing through
a server you don't control. Messages are designed to rot: what lingers
on-chain is a hash and a dead key, not readable content.

This guide covers the `spore` CLI. Companion docs: `README.md` (overview),
`design.md` (threat model + status), `WHISPER.md` (the no-relay architecture),
`UX_PREVIEW.html` (UI mockup).

## 1. What spore is — the privacy promise in plain language

**The core claim.** Every new DERO message uses `0xE2`: X3DH establishes the
conversation, Double Ratchet evolves message keys, and DERO carries only an
opaque pointer in a ring-8 or ring-16 transaction.

- **Short and long messages** use the same forward-private E2 path. The body is
  encrypted off-chain, stored under a TTL, and fetched by the receiver.
- **DERO carries no new plaintext body.** Only the opaque pointer and minimum
  postage enter the transaction; the ring size defaults to 16 and may be set to
  8. Spore rejects all other ring sizes for message posts.
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
3. **An E2 body store** — your mailbox or another supported store. It holds
   only encrypted, TTL-bound bodies; new sends do not use the historical
   `spore-peer` one-shot transport.

## 3. Quick start: short messages (whispers)

A new whisper is a real DERO transaction whose payload carries only an opaque
0xE2 pointer. X3DH + Double Ratchet encrypts the body in the off-chain store;
DERO carries the pointer and postage. There is no short-message payload limit
for the E2 body.

**Sender** — Alice writes to Bob's address (or his DERO name, section 6):

```sh
printf 'meet at the usual place\n' | spore whisper send \
  -to <bob's dero1... address or name> \
  -identity ~/.spore/identity.key \
  -bundle ./bob-bundle.json \
  -pinned-sig <bob signing key hex> \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -ringsize 16 \
  -rpc http://127.0.0.1:20209/json_rpc

# Optional smaller DERO transaction; Spore accepts only 8 or 16.
printf 'smaller transaction\n' | spore whisper send \
  -to <bob's dero1... address or name> -identity ~/.spore/identity.key \
  -bundle ./bob-bundle.json -pinned-sig <bob signing key hex> \
  -store https://your-mailbox.example -state-dir ~/.spore/state \
  -state-key ~/.spore/state.key -ringsize 8 \
  -rpc http://127.0.0.1:20209/json_rpc
```

Spore prints the transaction id. Once mined (roughly one block), Bob can read
it. New DERO posts default to ring size 16; use `-ringsize 8` when you want
smaller transactions. Spore accepts only 8 or 16.

**Recipient** — Bob runs the E2 receiver against his own wallet and mailbox:

```sh
spore whisper recv \
  -rpc http://127.0.0.1:20209/json_rpc \
  -identity ~/.spore/identity.key -spk ~/.spore/spk.key \
  -opk-pool ~/.spore/opk-pool.json \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
```

The receiver consumes the DERO pointer, fetches the encrypted body, advances the
Double Ratchet, and erases consumed message keys. Bare `spore whisper recv`
remains available only to read old native DERO whispers.

## 4. Long messages, end to end

Short and long DERO sends use the same 0xE2 protocol. A long body is read from
`-file`, encrypted by X3DH + Double Ratchet, stored off-chain with a deadline,
and represented on DERO by the same opaque pointer. There is no separate
long-term-key or peer-serving crypto path for new messages.

### Step 0 — provision the E2 kit

```sh
spore init -dir ~/.spore
```

Share the generated public prekey bundle and signing public key with the other
party (or publish the bundle through the mailbox prekey route). Keep
`identity.key`, `spk.key`, `state.key`, and the OPK pool private.

### Step 1 — sender encrypts and holds the body

```sh
spore whisper send-long \
  -to <recipient address or name> \
  -identity ~/.spore/identity.key \
  -bundle ./friend-bundle.json \
  -pinned-sig <friend signing key hex> \
  -file ./body.txt \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -rpc http://127.0.0.1:20209/json_rpc

# Short DERO alias: body comes from stdin and still uses X3DH + Double Ratchet.
printf 'hello\n' | spore whisper send \
  -to <recipient address or name> \
  -identity ~/.spore/identity.key \
  -bundle ./friend-bundle.json \
  -pinned-sig <friend signing key hex> \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -rpc http://127.0.0.1:20209/json_rpc
```

Use `-file /path/to/doc` to send a long body. The body is encrypted by the
Double Ratchet and written to the configured off-chain store; the DERO
transaction carries only the E2 pointer. No `spore-peer` process or legacy
long-term body key is involved for new messages.

### Step 2 — recipient fetches and decrypts

Bob runs the E2 receiver with his wallet, ratchet kit, body store, and durable
state:

```sh
spore whisper recv \
  -rpc http://127.0.0.1:20209/json_rpc \
  -identity ~/.spore/identity.key \
  -spk ~/.spore/spk.key \
  -opk-pool ~/.spore/opk-pool.json \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
```

When the E2 pointer arrives, the receiver fetches the ciphertext by CID,
verifies the deadline and content address, advances the ratchet, erases the
consumed message key, and prints the plaintext locally. The old `-key`,
`-peer-addr`, and `-peer-bin` flags are for receiving pre-upgrade records only.

**Both peers need access to the configured body store.** The DERO chain carries
only the pointer; it never carries the body.

> Bare `spore whisper recv` remains available for old native DERO whispers.
> It does not decode new E2 pointers.

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
in any `-to` flag. Use stdin or `-msg-file`; plaintext is never placed in
argv:

```sh
printf 'hello\n' | spore whisper send \
  -to alice \
  -identity ~/.spore/identity.key \
  -bundle ./alice-bundle.json \
  -pinned-sig <alice signing key hex> \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -daemon http://127.0.0.1:10102/json_rpc \
  -rpc http://127.0.0.1:20209/json_rpc
```

Spore resolves the name through the daemon you point at with `-daemon`
(default `http://127.0.0.1:10102/json_rpc`). A full `dero1...` address is used
directly and needs no daemon. Name resolution is a convenience over your node
— one more reason an honest operator runs their own.

## 7. What "rot" means, and the honest limits

> **Security status:** every NEW message uses the `0xE2` path (X3DH + Double
> Ratchet, `internal/ratchetwire`): forward-secret, post-compromise healing,
> off-chain TTL bodies, single-use prekeys, and durable encrypted state. The
> familiar DERO commands `whisper send`, `whisper send-long`, `msg send
> -chain dero`, and `msg send-long` are compatibility names for this same E2
> path. Old native DERO payloads, old `0xE1` envelopes, and old one-shot bodies
> remain receive-only compatibility records and are not forward-private.

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
- **Key exchange is out-of-band by design (TOFU + pinning).** E2 discovery is
  automated: your mailbox serves pre-signed single-use bundles (`GET
  /prekey`), senders fetch them with `-bundle-url`, and every bundle is still
  verified against a pinned sig shared once out-of-band. `spore msg mail` keeps
  a local address book. There is no global directory — that would be a
  sybil/linkability farm.

## 8. Command reference

| Command | What it does |
|---|---|
| `spore demo` | Runs an in-process send → receive → burn lifecycle with no node (sanity check). |
| `spore whisper send -to ADDR-OR-NAME -identity F (-bundle F \| -bundle-url URL) -pinned-sig HEX [-ringsize 8\|16] ...` | DERO compatibility alias for canonical X3DH + Double Ratchet E2; short body reads stdin or `-msg-file`; ring defaults to 16. |
| `spore whisper send-long -to ADDR-OR-NAME -identity F (-bundle F \| -bundle-url URL) -pinned-sig HEX -file F [-ringsize 8\|16] ...` | DERO compatibility alias for canonical E2 with an off-chain ratcheted long body and on-chain opaque pointer; ring defaults to 16. |
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
