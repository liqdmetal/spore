# Chat with a friend using spore — 5-minute setup

Two people, one conversation, no server in the middle. You each need the `spore`
binary and a channel to swap two short values out-of-band. Everything else is a
command.

This page is the short path. The long one — building from source, a mailbox you
host yourself, Tor-only machines — is [`ONBOARDING.md`](ONBOARDING.md).

## 1. Get the binary (both of you)

```bash
curl -fsSL https://raw.githubusercontent.com/liqdmetal/spore/main/scripts/install.sh | sh   # linux/macOS/WSL
```
```powershell
irm https://raw.githubusercontent.com/liqdmetal/spore/main/scripts/install.ps1 | iex        # Windows
```

Then `spore demo`: the whole send → receive → burn cycle with no wallet, no chain
and no network. If that prints its two messages, the binary is sound.

## 2. Make an identity (both of you)

```bash
spore init                        # ~/.spore: identity kit, prekey pool, config.json
```

`-dir DIR` (or `SPORE_HOME`) puts it elsewhere. That directory holds your keys:
keep it private, and `spore panic -confirm` is how you wipe it. `spore init` also
writes a config the later commands read, so you do not repeat paths and
addresses on every send.

## 3. Pick where bodies live (both of you)

Spore puts only an opaque pointer on-chain; the ciphertext body lives in a store
for its TTL. You need one address both of you can reach:

- a mailbox someone runs — yours, a friend's, or an operator's, or
- the public Nostr commons: `-store nostr://relay.damus.io,nos.lol` with a
  dedicated `-store-key` (a key of its own, never your identity key).

Mailbox setup, tokens, TLS and the trade-offs are in
[`ONBOARDING.md`](ONBOARDING.md) and
[`CARRIER_MATRIX.md`](CARRIER_MATRIX.md).

## 4. Swap two values out-of-band (both of you)

1. **Your public prekey bundle** — the sender needs it before the first message.
   Put it where your friend can fetch it, or hand over the file when you are
   already talking.
2. **Your pinned signing key** — the fingerprint your friend pins, sent over a
   channel where they already know the message is from you. A bundle fetched
   from a URL is a convenience, never the proof: `-pinned-sig` is still required
   and still verified.

## 5. One receives, one sends

**Your friend, receiving** (leave it running; `-out-dir` is where bodies land):

```bash
spore msg recv-e2 -identity ~/.spore/identity.key \
  -store https://your-mailbox.example -out-dir ./inbox
```

`-auto-ack` sends a delivery receipt back on the same session, `-maildb FILE`
indexes what arrives so you can search it later, and `-ntfy URL` wakes you
instead of holding a terminal open.

**You, sending** (the body never appears in `argv`):

```bash
printf 'meet at the usual place\n' | spore msg send-e2 \
  -to THEIR_ADDRESS -chain dero \
  -bundle ./their-bundle.json -pinned-sig THEIR_PINNED_SIG_HEX \
  -store https://your-mailbox.example \
  -identity ~/.spore/identity.key
```

Reply in the same thread with `spore msg reply-e2 -to ADDR -session HEX`, and
list open threads with `spore msg sessions`.

## What this is, and is not

The chain sees an opaque pointer and a fee; the body is forward-private and
expires on your schedule. Metadata — "a transaction happened at about this time"
— is public on every carrier. Deleting a body does not unwrite the pointer, and
no protocol can promise otherwise.

If something does not work, `spore doctor` is the preflight that names which
piece is missing.
