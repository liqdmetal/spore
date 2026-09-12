# Spore — onboarding (zero to first forward-private message)

In one line: an E2E-encrypted, forward-private, compostable messenger. You talk wallet-to-wallet, money and message can ride the same atomic tx, and everything rots on your schedule. No central server, no VC, no token.

Copy-paste first, prose second. The E2 path (`*-e2`) is the real messenger — forward-secret, single-use prekeys, off-chain bodies. The legacy `whisper`/`msg send` paths are at the bottom for compatibility and are not forward-private.

## Get the binary

```bash
curl -LO https://github.com/liqdmetal/spore/releases/latest/download/spore-windows-amd64.exe
#  run the rest as:  ./spore-windows-amd64.exe <cmd>
#  or build/install:
go install github.com/liqdmetal/spore/cmd/spore@latest
```

Below, `spore …` means your binary. Verify with `spore -version`.

## 0. Sanity check — no chain, no wallet, no setup

```bash
spore demo
```

Exercises the full send → receive → burn lifecycle in-process. Expected tail: `OK: body evicted, key erased, anchor inert.` If that runs, your binary works.

## 1. Initialize (one command, one time)

```bash
spore init
```

This creates your whole identity kit under `~/.spore/` (override with `SPORE_HOME` or `-dir`), all `0600` except the public bundle:

| File | What |
|---|---|
| `identity.key` | your long-term identity private key (X25519) — never share |
| `spk.key` | signed-prekey private key — never share |
| `state.key` | encrypts your local ratchet session state — never share |
| `opk-pool.json` | one-time-prekey private halves (consumed once each) |
| `batch.json` | single-use public prekey bundles, ready to publish |
| `identity-card.json` | your public identity card (share out-of-band so contacts pin you) |
| `store.key` | dedicated signing key for the `nostr://` serverless body store |
| `config.json` | defaults so every later command is short |

It prints your pinned-sig (your public signing key). Share `pinned-sig` + `identity-card.json` out-of-band (in person, a QR code, a separate channel) so contacts can pin your identity. That out-of-band pin is the trust root — discovery below is transport convenience, never a trust substitute.

### Why not `bundle.json`?

The card is deliberately named differently: `-bundle` expects a single pre-signed `SPKBundle` (one entry of `batch.json`), so a card named `bundle.json` is an onboarding dead end — the flag rejects it. `readBundle` now names that mistake explicitly and says what to do instead.

After `init`, every `*-e2` command reads `config.json` automatically — you stop retyping `-identity`, `-spk`, `-state-dir`, `-state-key`, `-store`, etc. Explicit flags always win.

## 2. Run your mailbox (your always-on node)

Your hosted mailbox stores ciphertext bodies and serves your single-use prekeys so others can start a conversation with you. It never touches your identity/SPK private keys; `spore msg recv-e2` decrypts on your device.

```bash
mkdir -p ~/.spore/users/me
# ~/.spore/tokens.json: {"me":"<your-secret>"}
spore mailbox host -users ~/.spore/users -listen 127.0.0.1:8080 \
  -tokens ~/.spore/tokens.json -privacy
```

Then publish your prekey batch to your user route (one-time; refill later):

```bash
spore prekeybatch push -in ~/.spore/batch.json \
  -mailbox http://127.0.0.1:8080/u/me
spore prekeybatch status -mailbox http://127.0.0.1:8080/u/me
```

Each `GET /prekey` from a sender pops one single-use bundle — two senders never get the same one-time key. When the batch runs low, refill:

```bash
spore prekeybatch gen -out ~/.spore/batch2.json -n 50   # auto-continues OPK ids
spore prekeybatch push -in ~/.spore/batch2.json \
  -mailbox http://127.0.0.1:8080/u/me
```

### Choose where your off-chain bodies live (`-store`)

The mailbox above is one option. `-store` picks the off-chain body store, and there are three postures:

| Posture | `-store` | You run | Prekey discovery |
|---|---|---|---|
| Home node (default, encouraged) | `http://127.0.0.1:8080` | your mailbox (step 2 above) | your mailbox serves `GET /prekey` |
| Serverless | `nostr://relay.damus.io,nos.lol` | nothing | manual bundle exchange only |
| Hosted (Model B) | `https://mailbox.example.net` | nothing — you pay | the operator's mailbox |

Hosted is the cleanest first-message path for a beta user who does not want to run a node: the operator runs a blind courier for you. See the hosted-beta flow below and MODEL_B_SERVICE.md.

Serverless is the no-servers endgame. Bodies are published as signed events to a public Nostr relay commons; nobody operates a store for you, and any subset of relays can serve a body by content address:

```bash
# set it once in config.json (init already generated ~/.spore/store.key for this)
spore msg recv-e2 -store nostr://relay.damus.io,nos.lol -store-key ~/.spore/store.key
```

`-store-key` must be a dedicated key (not your identity or chain key): publishing to a commons is linkable by pubkey, so a separate key stops a relay from tying your storage activity to your messaging identity.

### Serverless trade-offs — read before choosing it

- Prekey discovery is manual. With no mailbox there is no `GET /prekey`, so step 2's `prekeybatch push` has nowhere to go. Instead, each side hands the other ONE pre-signed bundle out-of-band (Signal, QR, in person):

  ```bash
  # on the RECIPIENT's machine: carve a single bundle out of batch.json
  # (batch.json is an ARRAY of bundles; -bundle takes exactly ONE)
  jq '.bundles[0]' ~/.spore/batch.json > my-bundle.json
  # then send my-bundle.json + your pinned-sig to the contact

  # on the SENDER's machine, once you have THEIR bundle + pinned-sig:
  echo "hello" | spore msg send-e2 -to THEIR_ADDR \
    -bundle ./their-bundle.json -pinned-sig THEIR_PINNED_SIG \
    -store nostr://relay.damus.io,nos.lol
  ```

  Note `-bundle` takes a single `SPKBundle`, not `batch.json` and not `identity-card.json` — `readBundle` rejects both with an explanation. Each bundle is single-use, so carve off a fresh one per new contact.

- 256 KiB body cap — relays reject large events. Attachments want the mailbox.
- Deletion is best-effort. NIP-09 requests are advisory and relays may keep copies. The real erasure is the ratchet: consumed message keys are destroyed, so lingering ciphertext is undecryptable garbage.

→ Full limits and hostile-relay defenses: CARRIER_MATRIX.md#off-chain-body-stores-mailbox-vs-the-serverless-commons

> No home server and want automatic prekeys? A hosted Model-B mailbox does step 2 for you as a blind courier (it never holds your keys). See MODEL_B_SERVICE.md. Self-hosting is the privacy default; hosting is optional convenience.

## 2b. Hosted beta (no node of your own)

If you do not want to run a node or mailbox yourself, an operator can run it for you as a blind courier. The operator never sees your identity/SPK private keys; `recv-e2` still decrypts on your device.

What the operator gives you:
- a mailbox route, e.g. `https://mailbox.example.net/u/<name>`
- a bearer token for that route
- (optionally) a private ntfy topic for arrival alerts

### 1) Initialize (same as always)

```bash
spore init
```

### 2) Push your prekey batch to the operator mailbox

```bash
spore prekeybatch push -in ~/.spore/batch.json \
  -mailbox https://mailbox.example.net/u/<name> \
  -token [REDACTED]
spore prekeybatch status -mailbox https://mailbox.example.net/u/<name> \
  -token [REDACTED]
```

Each `GET /prekey` pops one single-use bundle. Refill before it runs low:

```bash
spore prekeybatch gen -out ~/.spore/batch2.json -n 50
spore prekeybatch push -in ~/.spore/batch2.json \
  -mailbox https://mailbox.example.net/u/<name> \
  -token [REDACTED]
```

### 3) Receive (leave running)

```bash
spore msg recv-e2 \
  -identity ~/.spore/identity.json \
  -spk ~/.spore/spk.json \
  -store https://mailbox.example.net/u/<name> \
  -store-token [REDACTED] \
  -state-dir ~/.spore/state \
  -state-key ~/.spore/state.key \
  -auto-ack \
  -maildb ~/.spore/mail.json \
  -out-dir ~/inbox \
  -ntfy https://notify.example.net/<secret-topic>
# SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]  in the process environment, not on the command line
```

`-ntfy` is optional. If you omit ntfy, you still receive — you just keep `recv-e2` running. The ntfy alert is only a wake-up signal; it never carries the body.

The ntfy topic URL and bearer token are credentials; never paste them into the command line or into each other. Load `SPORE_NOTIFY_WEBHOOK_TOKEN` from the process environment.

### 4) Send (same as always, different bundle source)

```bash
echo "hello" | spore msg send-e2 \
  -to dero1q…their-address… \
  -bundle-url https://mailbox.example.net/u/their-name/prekey \
  -pinned-sig THEIR_PINNED_SIG_HEX
```

`-bundle-url` fetches a single-use bundle from the recipient's mailbox route. The recipient's pinned-sig is still verified out-of-band.

### Trust boundary (read this)

- The operator sees traffic + timing and the ciphertext bodies; it does not see plaintext or keys.
- `mailbox host -privacy` blanks the Sender field in the hosted log so the operator does not record who sent what.
- Body padding is on by default for premium users, so the operator cannot fingerprint message length.
- ntfy sees "you got a message" + a short txid, never the body.
- Full operator-run service docs: MODEL_B_SERVICE.md.

## 3. Receive (leave running)

```bash
spore msg recv-e2
#   useful flags (all optional):
#     -auto-ack        reply "delivered" on the same session (delivery receipts)
#     -maildb ~/.spore/mail.json   index into local contacts/threads/search
#     -out-dir ~/inbox             save each body to a file (attachments)
#     -ntfy https://notify.example.net/<secret-topic>   metadata-only ntfy alert (hosted beta)
#     SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]             ntfy auth (process environment, not argv)
#     -notify-email you@example.com -notify-smtp-host smtp.example.com -notify-smtp-from spore@example.com
#     -notify-sms +155****4567 -notify-twilio-sid AC... -notify-twilio-from +155****4321
#
#   Provider passwords/tokens come from environment variables, never argv:
#     SPORE_NOTIFY_SMTP_PASSWORD=[REDACTED]
#     SPORE_NOTIFY_TWILIO_AUTH_TOKEN=[REDACTED]
#   details: docs/NOTIFICATIONS.md
```

`recv-e2` watches the chain for pointers addressed to you, fetches the off-chain body, ratchets it open, and prints it. Blocked contacts (see `msg mail block`) are dropped before decryption.

## 4. Send

You need the recipient's chain address, their pinned-sig, and a way to get their bundle (a local file, or their mailbox's `/prekey` URL).

```bash
# discover their bundle from their mailbox (pinned-sig still verified);
# your own body goes in YOUR store, not the recipient's:
echo "hello" | spore msg send-e2 \
  -to dero1q…their-address… \
  -bundle-url http://THEIR-MAILBOX/prekey \
  -pinned-sig THEIR_PINNED_SIG_HEX \
  -store http://YOUR-MAILBOX-or-local-store \
  -store-token [REDACTED]

# …or from a bundle file they shared with you:
echo "hello" | spore msg send-e2 \
  -to dero1q…their-address… \
  -bundle ./their-bundle.json \
  -pinned-sig THEIR_PINNED_SIG_HEX \
  -store http://YOUR-MAILBOX-or-local-store \
  -store-token [REDACTED]
```

Plaintext is never an argv flag — shell history, `ps`, and crash reports read argv. Use `-msg-file F` or pipe via stdin (shown above).

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

## 6. Compostability as a feature

```bash
spore panic                 # DRY RUN: lists exactly what would be wiped
spore panic -confirm        # verifiably shred keys, state, maildb, spool, out-dir
```

`panic` targets only spore-shaped files in the paths you pass and re-verifies each one is gone (or fails loudly). Off-chain bodies already rot on their TTL; EVM/Solana mailbox records burn on delivery; `panic` erases your local plaintext. What can't be erased: the opaque pointer scrap on an immutable chain (DERO/Bitcoin) — it's useless once the body reaps, but the tx is public history. We don't pretend otherwise.

## Chain / carrier readiness

| Carrier | Usable today? | First message needs |
|---|---|---|
| DERO | ✅ live, mainnet | a funded DERO wallet running `--rpc-server`; native value + pay-with-message |
| Solana | ✅ live, mainnet (self-messaging) | a Solana keypair + SOL for fees |
| EVM | 🧪 dev (local anvil) | a local EVM node + account; pay-with-message on calldata path |
| Nostr | 🧪 carrier impl | relay URLs + a Nostr key |
| Bitcoin | 🧪 carrier impl (signer-injected) | an Esplora-compatible indexer + a signer; `-amount` refused (value not wired) |
| Cosmos / TON | 🧪 configurable seams | an explicit endpoint profile; `-amount` refused |
| XMR | 🚧 not for E2 | 8-byte seam too small for the pointer — refused, not downgraded |

`-chain` selects the carrier (`dero` default). Full matrix + invariants: CARRIER_MATRIX.md.

## Privacy model (honest limits)

- Forward-private + compostable on every NEW send. The DERO command names `whisper send`, `whisper send-long`, `msg send -chain dero`, and `msg send-long` are compatibility aliases for the canonical `*-e2` path; their old native/0xE1 records remain receive-only and are not forward-private.
- Metadata is visible: "a tx happened at ~time" is chain-wide public. DERO's ring sigs hide the sender; EVM/Solana/Bitcoin/TON expose tx metadata (content stays private via the off-chain ratchet body). ntfy sees "you got a message" + a short txid, never the body.
- Local plaintext: `maildb` stores decrypted snippets for search (0600, purge-able); the spool stores queued plaintext (0600, HMAC-sealed). `panic` wipes both.
- No relay = point-to-point unicast. Group broadcast needs a relay or an SC.

Threat model: SENDER_AUTH.md · wire formats: WIRE_SPEC.md · ratchet: RATCHET.md · self-hosting: HOME_NODE.md.

## Appendix — old native DERO records (receive-only compatibility)

Old native DERO records can still be received with the bare compatibility receiver, but new sends must use the E2 kit above. New DERO posts default to ring size 16; pass `-ringsize 8` to trade some transaction size for lower cost. Spore accepts only ring sizes 8 and 16.

Prefer the E2 path above for anything you care about. Donations: `spore donate --all`.
