# Spore — m³ · Multi-chain Private Messenger

**In one line:** an E2E-encrypted, **forward-private, compostable** messenger
that rides any of seven chains — you talk wallet-to-wallet, money and message
in the same atomic transaction, and everything rots on your schedule. No
central server. No VC. No token.

**Want to send your first message? → [`docs/ONBOARDING.md`](docs/ONBOARDING.md)**
Two commands: `spore init` then `spore msg send-e2 …`. (`spore demo` runs with
no chain and no wallet if you just want to see it work.)

---

## What makes Spore different

| | Signal | Session | Telegram+TON | **Spore** |
|---|---|---|---|---|
| Forward secrecy (Double Ratchet) | ✓ | ✓ | partial | ✓ |
| Post-compromise healing | ✓ | ✓ | ✗ | ✓ |
| No central server | ✗ | ✓ (onion) | ✗ | ✓ (chain + your own node) |
| **Money moves WITH the message, same atomic tx** | ✗ | ✗ | custodial bots | **✓ native (DERO/EVM)** |
| **Messages compost** (bodies expire, mailbox burns, local panic-wipe) | ✗ | ✗ | ✗ | **✓** |
| Single-use prekeys served without exposing your identity key | — | — | — | **✓** |

Settlement-native, compostable, self-hosted private messaging is an empty
category. Spore is the messaging fruiting body on the Relay/Sap settlement
rail — money and words become the same atomic object, and both rot.

## The mycorrhizal model (m³)

In a forest, trees look separate — underground they are joined by a shared
mycorrhizal network exchanging nutrients and warnings. That is Spore:

- **Trees = endpoints.** Each an independent wallet + node on its own chain.
- **Spore = the substrate underneath.** A no-relay transport letting any tree
  signal another — quietly, point-to-point.
- **m³ = the network that emerges:** trees on different chains, joined through
  one underground fabric.

## Architecture (the honest model)

Spore carries **only an opaque 74-byte pointer on-chain**. The ratcheted
ciphertext, the handshake, and the message body stay **off-chain** in a
TTL-bound store and are reaped after expiry. A permanent chain can't forget a
transaction — so Spore never pretends to. What it guarantees:

> **The message body composts. The permanent carrier retains only an opaque,
> non-decryptable pointer scrap.**

- **X3DH + Double Ratchet** (`internal/ratchet`, `internal/ratchetwire`): every
  new conversation is `0xE2`, forward-private, post-compromise healing. The
  legacy `0xE1` envelope, DERO-native whispers, and one-shot long-body path
  remain **compatibility-only** and are documented as **not** forward-private.
- **Off-chain bodies** (`internal/store`): content-addressed, TTL-evicted,
  crash-safe (the expiry record is written before the body, so a crash can
  never leave an un-reapable ciphertext).
- **Single-use prekeys** (`internal/mailbox`): `GET /prekey` pops one
  pre-signed public bundle per sender — two senders never get the same OPK.
  The mailbox never touches your identity/SPK private keys; bundles are signed
  offline (`spore prekeybatch`).
- **Durable local state**: ratchet sessions are endpoint-local, encrypted at
  rest, anti-rollback (append-only sequence log survives restart), and
  inactivity-expiring.
- **No downgrade**: an unsupported carrier refuses rather than silently
  falling back to a legacy plaintext-forever path.

## Chain / carrier status

| Carrier | Backend | Pointer transport | Compost | Status |
|---|---|---|---|---|
| **DERO** | `internal/dero` | native encrypted tx payload carrying opaque E2 pointer | body TTL | **live, mainnet** |
| **EVM** | `internal/evm` | mailbox contract / calldata | `burn(to,seq)` after delivery | live-verified (local Anvil); deployment pending |
| **Solana** | `internal/solana` | inbox PDA (program v2) | `burn(idx)` after delivery | **live, mainnet; self-messaging verified** |
| **Nostr** | `internal/nostr` | signed event content | NIP-09 delete (best-effort) | carrier impl |
| **Bitcoin** | `internal/bitcoin` | `OP_RETURN` (≤80B) | body-only (chain immutable) | carrier impl, signer-injected |
| **Cosmos SDK** | `internal/cosmos` | configurable memo field | chain-specific | configurable seam |
| **TON** | `internal/ton` | configurable comment | no universal burn | configurable seam |
| Monero (XMR) | `internal/xmr` | 8-byte payment id | off-chain rendezvous | mock-verified; **too small for E2 pointer — refused, not downgraded** |

Full carrier matrix, invariants, and deployment order:
[`docs/CARRIER_MATRIX.md`](docs/CARRIER_MATRIX.md).

## Payments (settlement-native)

Money rides the **same transaction** as the pointer on DERO and EVM-calldata —
atomically, trustlessly, no custody. Spore never holds your funds; your wallet
signs.

- `spore msg send-e2 -amount 5.5dero …` — pay with the message.
- `spore msg invoice -amount 25dero …` — request payment in-thread.
- `spore msg pay -invoice <id> …` — settle: money + proof ride one atomic tx.

Bitcoin/TON value carriage is refused today (their backends discard the amount
hint) rather than silently sending an unpaid message as if paid.

## CLI (everything after `spore init` picks up config defaults)

```
spore init                     # one-shot onboarding: identity kit + config.json
spore demo                     # see it work — no chain, no wallet

# Forward-private E2 (the real messenger):
spore msg send-e2   -to ADDR (-bundle F | -bundle-url URL) -pinned-sig HEX [-ringsize 8|16] [-amount 5.5dero] [-msg-file F|-]
spore msg recv-e2   [-auto-ack] [-maildb F] [-out-dir D] [-ntfy URL]
spore msg reply-e2  -to ADDR -session HEX      # continue a thread
spore msg forward-e2 -to ADDR -file F …        # new session, same body
spore msg sessions                             # list thread/session ids
spore msg invoice|pay -session HEX -amount N   # in-thread settlement
spore msg compose | flush                      # offline send queue (HMAC-sealed)
spore msg mail add|list|block|threads|search|purge   # local contacts + search

# Prekey discovery (single-use):
spore prekeybatch gen|push|status

# Infra:
spore mailbox host|list|get    # hosted ciphertext/prekey service
spore msg recv-e2               # client-side E2 receive/decrypt
spore relay run                # store-and-forward hop (auth + backoff)
spore status | doctor          # health HUD + preflight

# Serverless (no home node): bodies live on a public Nostr relay commons.
#   -store nostr://relay.damus.io,nos.lol  -store-key ~/.spore/store.key
#   (any E2 command; dedicated key required — see docs/CARRIER_MATRIX.md)

# Compostability as a user feature:
spore panic [-home ~/.spore] [-confirm]   # verifiable local wipe of keys/state/maildb/spool

# Explicit continuity vault (no automatic fund movement):
spore continuity create -owner-key FILE -recipient-pub HEX[,HEX,...] -file PAYLOAD -out VAULT
spore continuity check-in -vault VAULT -owner-key FILE
spore continuity status -vault VAULT [-at UNIX]
spore continuity release -vault VAULT -recipient-key FILE -out PAYLOAD [-at UNIX]
spore continuity verify -vault VAULT

# N-of-M independent observer release:
spore continuity quorum-create -vault VAULT -threshold N -attester-pub HEX[,HEX,...] -out POLICY
spore continuity attest -vault VAULT -policy POLICY -observer-key KEY -out ATTESTATION [-at UNIX]
spore continuity quorum -policy POLICY -attestations A1[,A2,...] -out QUORUM
spore continuity verify-quorum -quorum QUORUM [-vault VAULT]
spore continuity release-quorum -vault VAULT -quorum QUORUM -recipient-key KEY -out PAYLOAD [-at UNIX]

# Optional chain commitment (opaque IDs only; posting is explicit):
spore continuity anchor-create -vault VAULT -policy POLICY -out ANCHOR
spore continuity anchor-verify -anchor ANCHOR -vault VAULT -policy POLICY
spore continuity anchor-post -anchor ANCHOR -vault VAULT -policy POLICY -to DERO_ADDR [-rpc URL] [-rpc-user USER] [-ringsize 8|16] [-receipt RECEIPT]  # password is prompted securely
spore continuity anchor-check -receipt RECEIPT -anchor ANCHOR [-rpc URL] [-rpc-user USER]  # wallet-history payload readback
```

Plaintext is **never** an argv flag (shell history, `ps`, and crash reports
read argv) — use `-msg-file` or stdin. Run `spore` with no args for full usage.

## Privacy model (honest limits)

- **Forward-private + compostable** on the E2 path; legacy paths are not. DERO E2 posts accept only `-ringsize 8` or `-ringsize 16`, defaulting to 16.
- **No relay**: a whisper is a real tx that P2P-fans to the recipient's node.
- **Metadata is visible**: "a tx happened at ~time" is chain-wide public.
  DERO's ring sigs hide the sender; EVM/Solana/Bitcoin/TON expose tx metadata
  (content stays private via the off-chain ratchet body). ntfy sees "you got a
  message" + a short txid, never the body.
- **Immutable carriers keep the pointer scrap forever** — deleting an off-chain
  body does not erase the on-chain pointer. No protocol can promise otherwise.
- **Local plaintext**: `maildb` stores decrypted snippets for search (0600,
  purge-able); the spool stores queued plaintext (0600, HMAC-sealed). `panic`
  wipes both.
- Threat model: [`docs/SENDER_AUTH.md`](docs/SENDER_AUTH.md) ·
  wire formats: [`docs/WIRE_SPEC.md`](docs/WIRE_SPEC.md) ·
  ratchet: [`docs/RATCHET.md`](docs/RATCHET.md).

## Self-host (the privacy default)

**Three deployment postures**, from zero infrastructure to fully self-hosted:

| | **Serverless** | **Home node** (encouraged) | **Hosted** (Model B) |
|---|---|---|---|
| You run | **nothing** | chain node + `spore mailbox host` (+ optional `spore relay run`) | nothing — you pay the operator |
| Off-chain bodies | `nostr://` public relay commons (`-store nostr://relay1,relay2`) | your mailbox over TLS + token | the service's mailbox (blind courier) |
| Prekey discovery | manual bundle exchange (`-bundle FILE`), or your own mailbox | your mailbox serves `GET /prekey` | the service's mailbox |
| Who's in the middle | nobody you pay; relays see ciphertext-by-CID | nobody | the service sees traffic + timing, never content |
| Trade-off | 256 KiB body cap, deletion is best-effort (the ratchet is the real erasure) | needs an always-on box | you trust the operator with metadata |

The serverless posture is the no-servers endgame: point `-store` at
`nostr://` relays, exchange bundles out-of-band, and no one operates anything
for you. Bodies are content-addressed ciphertext on a public commons; deletion
is best-effort, so the **ratchet's erased keys are what actually makes old
messages unreadable** — see
[`docs/CARRIER_MATRIX.md`](docs/CARRIER_MATRIX.md#off-chain-body-stores-mailbox-vs-the-serverless-commons)
for the honest limits.

→ [`docs/HOME_NODE.md`](docs/HOME_NODE.md) (copy-paste) ·
[`docs/MODEL_B_SERVICE.md`](docs/MODEL_B_SERVICE.md) ·
[`docs/MODEL_B_RUNBOOK.md`](docs/MODEL_B_RUNBOOK.md)

## Build & test

```
go build ./...   # builds clean
go vet ./...     # clean
go test ./...    # all packages green
go test -race ./internal/ratchetwire ./internal/mailbox ./internal/relay   # race-clean
```

Go 1.23.1+. No CGO.

## Sustainability (FOSS, grassroots — no VC, no token)

Spore is BSD-3 free software. It stays free. The operator (not the protocol)
can earn from optional convenience — see [`docs/BUSINESS.md`](docs/BUSINESS.md):
hosted Model-B mailboxes, settlement rake on in-chat escrow/swaps (sap/relay-dex),
and an optional business tier. None of it is required to use Spore privately and
forever-free.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md). Shipped recently: E2 (0xE2) forward-private
transport, 4 new carriers, pay-with-message + in-thread invoices, local maildb
(contacts/threads/search), offline compose queue, single-use prekey batches,
one-shot onboarding, panic wipe, and multi-device state sync via
`e2-device`. Next: serverless bodies over `spore-peer`, tokenized search, and
real-chain EVM deployment.

## License

BSD 3-Clause. Spore is clean-room Go; it imports no derohe source. derohe-rs
(the Rust port used for L1) and spore-peer are separately BSD-3-Clause.
