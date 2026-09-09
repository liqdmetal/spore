# Spore — onboarding (zero → first forward-private message)

**In one line:** an E2E-encrypted, forward-private, compostable messenger. You
talk wallet-to-wallet, money and message can ride the same atomic tx, and
everything rots on your schedule. No central server, no VC, no token.

Copy-paste first, prose second. The **E2 path (`*-e2`) is the real messenger** —
forward-secret, single-use prekeys, off-chain bodies. The legacy `whisper`/`msg
send` paths are at the bottom for compatibility and are **not** forward-private.

**Get the binary** (grab `/releases/latest`, or build):

```bash
curl -LO https://github.com/liqdmetal/spore/releases/latest/download/spore-windows-amd64.exe
#  run the rest as:  ./spore-windows-amd64.exe <cmd>
#  or build/install:
go install github.com/liqdmetal/spore/cmd/spore@latest
```
Below, `spore …` means your binary. Verify with `spore -version`.

---

## 0. Sanity check — no chain, no wallet, no setup

```bash
spore demo
```
Exercises the full **send → receive → burn** lifecycle in-process. Expected
tail: `OK: body evicted, key erased, anchor inert.` If that runs, your binary
works.

---

## 1. Initialize (one command, one time)

```bash
spore init
```

This creates your whole identity kit under `~/.spore/` (override with
`SPORE_HOME` or `-dir`), all `0600` except the public bundle:

| File | What |
|---|---|
| `identity.key` | your long-term identity private key (X25519) — **never share** |
| `spk.key` | signed-prekey private key — **never share** |
| `state.key` | encrypts your local ratchet session state — **never share** |
| `opk-pool.json` | one-time-prekey **private** halves (consumed once each) |
| `batch.json` | single-use **public** prekey bundles, ready to publish |
| `bundle.json` | your public identity card (share out-of-band so contacts pin you) |
| `config.json` | defaults so every later command is short |

It prints your **pinned-sig** (your public signing key). Share `pinned-sig` +
`bundle.json` **out-of-band** (in person, a QR code, a separate channel) so
contacts can pin your identity. That out-of-band pin is the trust root —
discovery below is transport convenience, never a trust substitute.

After `init`, **every `*-e2` command reads `config.json` automatically** — you
stop retyping `-identity`, `-spk`, `-state-dir`, `-state-key`, `-store`, etc.
Explicit flags always win.

---

## 2. Run your mailbox (your always-on node)

Your mailbox holds your off-chain message bodies and **serves your single-use
prekeys** so others can start a conversation with you. It never touches your
identity/SPK private keys.

```bash
spore mailbox run -dir ~/.spore/mailbox -listen 127.0.0.1:8080
#   add -token SECRET to require a bearer token on every route (do this for
#   any non-loopback / internet-reachable bind)
```

Then publish your prekey batch to it (one-time; refill later):

```bash
spore prekeybatch push -in ~/.spore/batch.json -mailbox http://127.0.0.1:8080
spore prekeybatch status -mailbox http://127.0.0.1:8080   # is it serving? (consumes one bundle)
```

Each `GET /prekey` from a sender **pops one single-use bundle** — two senders
never get the same one-time key. When the batch runs low, refill:

```bash
spore prekeybatch gen -out ~/.spore/batch2.json -n 50   # auto-continues OPK ids
spore prekeybatch push -in ~/.spore/batch2.json -mailbox http://127.0.0.1:8080
```

> **No home server?** A hosted Model-B mailbox does steps 2 for you as a blind
> courier (it never holds your keys). See [`MODEL_B_SERVICE.md`](MODEL_B_SERVICE.md).
> Self-hosting is the privacy default; hosting is optional convenience.

---

## 3. Receive (leave running)

```bash
spore msg recv-e2
#   useful flags (all optional):
#     -auto-ack        reply "delivered" on the same session (delivery receipts)
#     -maildb ~/.spore/mail.json   index into local contacts/threads/search
#     -out-dir ~/inbox             save each body to a file (attachments)
#     -ntfy https://ntfy.sh/your-secret-topic   ping your phone (metadata only)
```

`recv-e2` watches the chain for pointers addressed to you, fetches the
off-chain body, ratchets it open, and prints it. Blocked contacts (see
`msg mail block`) are dropped **before** decryption.

---

## 4. Send

You need the recipient's **chain address**, their **pinned-sig**, and a way to
get their **bundle** (a local file, or their mailbox's `/prekey` URL).

```bash
# discover their bundle from their mailbox (pinned-sig still verified):
echo "hello" | spore msg send-e2 \
  -to dero1q…their-address… \
  -bundle-url http://THEIR-MAILBOX/prekey \
  -pinned-sig THEIR_PINNED_SIG_HEX

# …or from a bundle file they shared with you:
echo "hello" | spore msg send-e2 \
  -to dero1q…their-address… \
  -bundle ./their-bundle.json \
  -pinned-sig THEIR_PINNED_SIG_HEX
```

**Plaintext is never an argv flag** — shell history, `ps`, and crash reports
read argv. Use `-msg-file F` or pipe via stdin (shown above).

---

## 5. The rest of the email-class flow

```bash
# continue a thread (reply):
spore msg sessions                          # list your session/thread ids
echo "re: your msg" | spore msg reply-e2 -to ADDR -session <16-hex-id>

# forward a saved message to someone new (fresh session):
spore msg forward-e2 -to NEWADDR -file ~/inbox/<txid>.msg -bundle-url URL -pinned-sig HEX

# pay WITH the message (money + pointer ride ONE atomic tx — DERO/EVM only):
echo "invoice #42 settled" | spore msg send-e2 -to ADDR -bundle-url URL \
  -pinned-sig HEX -amount 25dero

# request payment in-thread, then settle it:
spore msg invoice -to ADDR -session <id> -amount 25dero -for "invoice #42"
spore msg pay     -to ADDR -session <id> -amount 25dero -invoice <invoice-id>

# offline: queue now, send when a carrier is reachable:
echo "from the plane" | spore msg compose -to ADDR -bundle-url URL -pinned-sig HEX
spore msg flush                             # drains the queue through the real send path

# local mail store (contacts, allowlist, threads, search):
spore msg mail add -addr ADDR -nick Alice -pinned HEX
spore msg mail threads
spore msg mail search invoice -peer ADDR
spore msg mail block -addr SPAMMER
spore msg mail purge -older-than 720h       # bound local plaintext retention
```

---

## 6. Compostability as a feature

```bash
spore panic                 # DRY RUN: lists exactly what would be wiped
spore panic -confirm        # verifiably shred keys, state, maildb, spool, out-dir
```

`panic` targets only spore-shaped files in the paths you pass and re-verifies
each one is gone (or fails loudly). Off-chain bodies already rot on their TTL;
EVM/Solana mailbox records burn on delivery; `panic` erases your local
plaintext. What **can't** be erased: the opaque pointer scrap on an immutable
chain (DERO/Bitcoin) — it's useless once the body reaps, but the tx is public
history. We don't pretend otherwise.

---

## Chain / carrier readiness

| Carrier | Usable today? | First message needs |
|---|---|---|
| **DERO** | ✅ live, mainnet | a funded DERO wallet running `--rpc-server`; **native value + pay-with-message** |
| **Solana** | ✅ live, mainnet (self-messaging) | a Solana keypair + SOL for fees |
| **EVM** | 🧪 dev (local `anvil`) | a local EVM node + account; **pay-with-message on calldata path** |
| **Nostr** | 🧪 carrier impl | relay URLs + a Nostr key |
| **Bitcoin** | 🧪 carrier impl (signer-injected) | an Esplora-compatible indexer + a signer; `-amount` refused (value not wired) |
| **Cosmos / TON** | 🧪 configurable seams | an explicit endpoint profile; `-amount` refused |
| **XMR** | 🚧 not for E2 | 8-byte seam too small for the pointer — refused, not downgraded |

`-chain` selects the carrier (`dero` default). Full matrix + invariants:
[`CARRIER_MATRIX.md`](CARRIER_MATRIX.md).

---

## Privacy model (honest limits)

- **Forward-private + compostable** on the `*-e2` path. Legacy
  `whisper`/`msg send`/`0xE1`/one-shot long-body are **compatibility only** and
  are **not** forward-private after a long-term-key compromise.
- **Metadata is visible**: "a tx happened at ~time" is chain-wide public. DERO's
  ring sigs hide the sender; EVM/Solana/Bitcoin/TON expose tx metadata (content
  stays private via the off-chain ratchet body). ntfy sees "you got a message" +
  a short txid, never the body.
- **Local plaintext**: `maildb` stores decrypted snippets for search (0600,
  purge-able); the spool stores queued plaintext (0600, HMAC-sealed). `panic`
  wipes both.
- **No relay = point-to-point unicast.** Group broadcast needs a relay or an SC.

Threat model: [`SENDER_AUTH.md`](SENDER_AUTH.md) · wire formats:
[`WIRE_SPEC.md`](WIRE_SPEC.md) · ratchet: [`RATCHET.md`](RATCHET.md) ·
self-hosting: [`HOME_NODE.md`](HOME_NODE.md).

---

## Appendix — legacy DERO quick path (compatibility, not forward-private)

For a no-setup DERO-only short message (native encryption, but permanent
on-chain payload — no forward secrecy):

```bash
# terminal 1 — your DERO endpoint (wallet RPC on 20209):
dero-wallet-cli --wallet-file mywallet.db --rpc-server --rpc-bind 127.0.0.1:20209
#   first run: `register` then `address` inside the wallet prompt

# terminal 2 — send / receive:
spore whisper send -to dero1q…friend… -msg "hi"
spore whisper recv
```

Prefer the E2 path above for anything you care about. Donations:
`spore donate --all`.
