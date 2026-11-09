# Paying a stranger in Monero — and leaving with a signed receipt

*A buyer's walkthrough: one thread, one Monero payment, two signatures. About 15
minutes of setup, and none of it needs an account with anyone.*

Spore carries the conversation — forward-private, bodies that rot, an opaque
pointer on a chain. Monero carries the money. The receipt is the artifact that
ties one to the other, signed by both parties and re-checkable by a third.

Said first, because it changes the steps: **`spore msg pay` does not move XMR.**
It attaches value only on DERO or EVM and refuses `xmr` rather than print PAID
over a transfer that never happened. So the Monero leg below is a normal wallet
payment, and the receipt is what turns it into a record of the job. If you want
money and message in one atomic transaction, run the thread on DERO or EVM and
settle there; Monero is the rail for when you would rather the amount and the
payer were not public.

## 1. Install, then make an identity

```bash
# linux / macOS / WSL — checksum-verified, installs to ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/liqdmetal/spore/main/scripts/install.sh | sh

spore -version        # the release you got
spore demo            # no chain, no wallet: proves the binary works
spore init            # identity kit + config.json under ~/.spore
```

`spore init` prints your **pinned-sig** — your public signing key. Keep it: your
counterparty pins it, and it signs your half of the receipt. Everything after
this picks up `config.json` defaults, so the commands below stay short.

## 2. Pin the counterparty out of band

Get three things over a channel that is not this conversation:

| What | Why |
|---|---|
| `identity-card.json` and its `pinned-sig` | the trust root — a pinned key is what makes a thread *them* |
| their chain address | where the pointer transaction goes |
| where their prekey bundles are served | `https://…/u/<name>/prekey`, a `nostr://` store, or a file they send you |

A bundle fetched from a URL is transport convenience; the pin you got in person
is the trust. Spore refuses a bundle that does not match the pinned signature.

## 3. Decide how bodies travel

**Hosted mailbox (the phone-friendly option).** An operator runs
`spore mailbox host` and gives you a URL and a token. They hold expiring
ciphertext and single-use prekeys — never your keys, never plaintext — and they
see that traffic happened and when. Take that trade only if it suits you.
Publish your prekeys to their host once:

```bash
spore prekeybatch push -in ~/.spore/batch.json \
  -mailbox https://mail.example/u/you -token YOUR_TOKEN
```

Your commands then carry `-store https://mail.example/u/you -store-token
YOUR_TOKEN`, and their `-bundle-url` is `https://mail.example/u/them/prekey`.
Some operators bill the mailbox itself in XMR (their side runs `bill watch` and
provisions it after the first payment); the address and token come from them,
not from a signup form.

**Self-hosted or serverless instead.** Bodies in your own `spore serve` store
(`sporepeer://…`), or a public Nostr commons (`-store nostr://relay.damus.io,nos.lol`
with a dedicated `-store-key`). No operator, no metadata to a third party — you
are the always-on node, or your relay commons is.

## 4. Open the thread

Plaintext never goes on argv (shell history, `ps`, crash dumps read it). Write
it to a file or pipe it:

```bash
spore msg send-e2 -to THEIR_CHAIN_ADDR \
  -bundle-url https://mail.example/u/them/prekey \
  -pinned-sig THEIR_PINNED_SIG \
  -store https://mail.example/u/you -store-token YOUR_TOKEN \
  -msg-file brief.txt
```

Receive — run it when you check in, or leave it running:

```bash
spore msg recv-e2 -auto-ack -maildb ~/.spore/maildb.json
```

`spore msg sessions` lists the 16-hex session ids; every later command uses one.
It is a thread handle, not a secret.

## 5. Take the invoice in the thread

The provider asks in-band, so the amount and the job sit in one signed thread:

```bash
spore msg invoice -to YOUR_CHAIN_ADDR -session SESSION_HEX \
  -amount 2.5xmr -for "audit of mailbox host config" -due 72h
```

`-amount` carries its own unit — `2.5xmr` is 2 500 000 000 000 piconero, and
sub-piconero amounts are refused, not rounded. The INVOICE line names an id;
your `spore msg receipts` shows the same id on your side.

## 6. Pay it from your wallet

Send exactly the invoiced amount, in one transaction, to the address they gave
you. Keep the txid, and if you want evidence that stands on its own, have your
wallet produce a tx proof for that transaction and address:

```text
txid       4f2c…
address    the provider address you paid
signature  the wallet's get_tx_proof output for that tx + address
scheme     monero-tx-proof-v1
```

Then say so in the thread: txid plus proof, nothing else needed. The proof lets
*them* check the payment without trusting your word, and lets a third party
re-check it later.

If you are paying a hosted operator, use the per-order subaddress they handed
you. Paying the wallet's primary address still arrives, but it cannot be
attributed to your order — the operator's biller will hold it rather than
provision.

## 7. Turn the job into a receipt

Either side can create it; the canonical form is part of the protocol (sorted
keys, no floats, one trailing newline — the bytes are the format):

```bash
spore sign receipt create -out job.json \
  -service-category "audit.security" \
  -service-summary  "mailbox host configuration review" \
  -provider-pub PROVIDER_PINNED_SIG -client-pub YOUR_PINNED_SIG \
  -started-at  2026-11-09T10:00:00Z -finished-at 2026-11-09T14:30:00Z \
  -settlement rail=xmr,network=monero-mainnet,asset=xmr,amount=2500000000000,txid=TXID,settled=2026-11-09T14:41:00Z \
  -deliverable label=report,digest=sha256:DIGEST,bytes=48213 \
  -client-accepted -client-rating 5 -client-note "found it in an hour"
```

`amount` is atomic units — piconero for XMR — as a decimal string, never a
float. Optionally attach the wallet's proof to the record itself with
`-txproof txid=…,address=…,signature=…,scheme=monero-tx-proof-v1`: the proof is
bound to the record's bytes, so it cannot be moved onto a different receipt.

Each side signs only its own role, and the command refuses a key that is not
that role's key:

```bash
spore sign receipt sign -role client   -identity ~/.spore/identity.key -file job.json -out client.sig
spore sign receipt sign -role provider -identity ~/.spore/identity.key -file job.json -out provider.sig
spore sign receipt verify -file job.json -sigs client.sig,provider.sig -required both
```

`verify` checks the signatures *and* the fixed statement each role is allowed to
make. One signature verifies with `-required client`; it is simply not a
dual-signed record.

## 8. What you keep, and what someone else can check

- `job.json` plus both `.sig` files. Its `receipt_id` is the SHA-256 of the
  canonical bytes, computed by the verifier — never taken from the signer.
- `spore sign receipt export -dir . -format csv` writes one accounting row per
  settlement line with its evidence level: what an accountant actually needs.
- `spore sign receipt tally -dir .` counts dual-signed receipts only, one per
  client/provider pair — which is why a provider-only receipt can never become
  a reputation score.

## The honest limits

- **`tally` does not confirm a txid exists on-chain.** It checks that a receipt
  cites a txid you already confirmed. The tx proof is the checkable evidence,
  and checking it is the wallet's `check_tx_proof` call.
- **XMR is a money rail, not a carrier.** `msg pay` refuses it on purpose: no
  atomic money+message, so message and payment are separate objects joined by
  the receipt.
- **The chain keeps the pointer.** Bodies rot on schedule; the opaque pointer
  scrap does not, and no protocol can promise otherwise.
- **A hosted mailbox operator sees metadata** — that traffic happened, when,
  roughly how much — never content or keys. Self-host or use the commons if
  that is too much.
- **A receipt is a service, not a tax.** The default is none; the provider
  chooses whether to issue one, and that policy should be visible before the job
  is booked.
