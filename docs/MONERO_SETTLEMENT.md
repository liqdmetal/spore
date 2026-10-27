# Monero settlement — XMR as Spore's money rail

**Status: the amount seam ships, and the wallet integration is live-verified as
far as auth, the response shape and the decision core.** `xmr` is a
first-class money asset in the CLI (12 decimals, exact, tested), and `bill watch`
now decodes a real wallet's own payments (2026-10-27, wallet RPC v0.18.5.1 — §5,
§9). What is *not* live-verified: no XMR payment has been carried all the way
through provisioning into a receipt, which is the narrower reason §5 still gates
the rail behind `-xmr-unverified`.

Read with [CARRIER_MATRIX.md](CARRIER_MATRIX.md) (XMR is not a pointer carrier),
[JOB_RECEIPT_V1.md](JOB_RECEIPT_V1.md) (what a settlement line is),
[HOOKED_INTEGRATION.md](HOOKED_INTEGRATION.md) (message rail and money rail are
chosen separately), and [LIVE_NODES.md](LIVE_NODES.md) §1 (the node side).

## 1. The posture: Monero is the money rail, not the carrier

`CARRIER_MATRIX` refuses XMR as a direct E2 pointer carrier, and it is right to:
modern Monero allows only an **8-byte payment id**, so a tx can be a knock and
cannot carry content ([VISION.md](../VISION.md) §3, `internal/xmr`). That is a
judgement about the *carrier*.

Settlement is a different question, and Monero is the best privacy fit for it in
this project. A settlement line needs exactly six things —
`rail`, `network`, `asset`, `amount_atomic`, `txid`, `settled_at` — and Monero
supplies all six without any payload seam, mailbox, or operator. The two
questions are already independent in the design: a job whose message rode DERO,
EVM, or an off-chain rendezvous can settle in XMR, and a job whose message rode a
Monero *knock* can settle in anything.

What this buys: the one rail where "who paid whom, and how much" is not public.
That is the same property `internal/secure` buys for content, applied to money —
and it is the reason a privacy-first messenger should be able to quote a price in
XMR at all.

## 2. What ships now — piconero, exactly

`assetDecimals` in [money.go](../cmd/spore/money.go) now maps `xmr`/`monero` →
**12**, so 1 XMR = 1 000 000 000 000 piconero:

```
spore msg invoice -asset xmr -amount 2.5xmr -for "valve work"
spore sign receipt create … -settlement rail=xmr,network=monero-mainnet,asset=xmr,amount=2500000000000,txid=HEX,settled=2026-10-26T00:00:00Z
```

`internal/jobreceipt` needed **no change**: `rail`/`network`/`asset` are free
non-empty strings and `amount_atomic` must already be a decimal string of
non-negative integer atomic units. The no-float rule that document states as a
conformance requirement is what makes a new rail a table entry instead of a
format change. Monero is the case that rule was written for: its RPC reports
integer piconero, and its unit is wide enough to break float arithmetic.

Why the `big.Int` path is load-bearing rather than tidy, in the two numbers a
reviewer should re-derive rather than take on faith:

| Amount | piconero | through a float64 |
|---|---|---|
| 2^53+1 piconero | 9007199254740993 | renders `…992` — one piconero short |
| uint64 max piconero | 18446744073709551615 | renders `18446744.07370955` — **615 piconero short** |

Both are pinned by `TestXRMPiconeroExactness` and `TestFormatAmountRoundTrip`
(`cmd/spore/money_test.go`); both were proven to fail by mutation. Sub-piconero
input (`0.0000000000001`, 13 decimals) is refused, not truncated — it is not an
amount Monero can send.

## 3. Attribution: Monero names no sender

`bill watch` derives an account name from the txid, which works because DERO's
`get_transfers` returns `result.entries` with a sender-tagged incoming flag and
that flow does no address fan-out.

Monero's `get_transfers` returns **`result.in[]`**, and there is **no sender field
at all**, by design. So the payer is identified by *which address was paid*.

The entry's field set, checked against Monero **v0.18.0.0** source
(`COMMAND_RPC_GET_TRANSFERS::transfer_entry` in
`src/wallet/wallet_rpc_server_commands_defs.h`, and the incoming
`fill_transfer_entry` in `src/wallet/wallet_rpc_server.cpp`): `txid`,
`payment_id`, `height`, `timestamp`, `amount`, `amounts`, `fee`, `note`,
`destinations`, `type`, `unlock_time`, `locked`, `subaddr_index`,
`subaddr_indices`, `address`, `double_spend_seen`, `confirmations`,
`suggested_confirmations_threshold`. `address` **is** set on incoming entries —
the handler fills it from the receiving subaddress — which is what makes
attribution-by-subaddress possible at all.

A populated entry captured from the live v0.18.5.1 wallet on 2026-10-27 settles
the field set against a real response, not just the struct, and corrects one line
of it: an incoming entry carries `address`, `amount`, `amounts`, `confirmations`,
`double_spend_seen`, `fee`, `height`, `locked`, `note`, `payment_id`,
`subaddr_index`, `subaddr_indices`, `suggested_confirmations_threshold`,
`timestamp`, `txid`, `type`, `unlock_time` — and **no `destinations`**. That field
is set for outgoing entries; it is declared on the shared `transfer_entry` struct
and never on the incoming side. Two further things the capture showed, both of
which can bite a decoder:

- `payment_id` is **present as a zeroed 8-byte id** (`"0000000000000000"`), not
  omitted. Anything treating a payment id as a spore signal must compare it
  against zero; testing for emptiness would accept a plain payment as mycelium.
- A payment with no per-order subaddress handed out lands on **minor 0**, the
  wallet's primary address — so the unlabelled-subaddress hold (§5) fires on the
  primary address too, and that is a labelling decision the operator has to make
  for the wallet's own main address, not just for issued subaddresses.

Four of those fields decide whether a transfer may be billed:

- **`type` is a string, and `in[]` is not exclusively payments.** The handler
  sets `"in"` for a payment and **`"block"` for a coinbase entry**. A biller must
  require `type == "in"` rather than trusting array membership.
- **`locked` / `unlock_time`**: a received transfer can be not-yet-spendable. Locked
  money is not money yet.
- **`double_spend_seen`**: never provision against one.
- **`confirmations`** — with `suggested_confirmations_threshold` as the wallet's own
  hint — is what the floor in §5 reads.

And a response may **omit** `in` entirely when it is empty: empty categories are
not guaranteed to serialize as `[]` (a real report against Monero's own tracker
shows a result whose only key was `in`). A decoder must treat a missing key as no
transfers, never as an error.

```
create_address   {account_index:0, label:"order:<id>", count:1}
                 -> {address, address_index:{major,minor}}
label_address    {index:{major,minor}, label:"order:<id>"}
get_address      / get_address_index          # map an entry back to an order
get_transfers    {in:true, account_index:0, subaddr_indices:[…],
                  filter_by_height:true, min_height:h, max_height:0}
incoming_transfers                            # alternative output listing
```

**`min_height` does nothing on its own.** v0.18.0.0 gates height filtering on
`filter_by_height`, so a request that passes `min_height` without it silently
re-scans every transfer the wallet has, on every poll. `internal/xmr` already
sets it — this note exists because the sketch is what a new poller copies.

Model: **one fresh subaddress per order**, its `minor` index stored against the
order. Reconcile by that index, and keep `txid`, `subaddr_index.minor`, piconero
amount, height and confirmations.

Two rules that are not style:

- **Never reuse a subaddress across orders.** Reuse is exactly what makes the
  attribution ambiguous, and it links two payments that should not be linked.
- **Do not pre-generate addresses in bulk.** A wallet does not scan arbitrarily
  far ahead by default; generate near the order.

This is better than the DERO flow rather than a port of it: nobody derives a
customer name from a txid, two payers cannot collide on a derived name, and the
payer is never identified at all.

## 4. Evidence: what makes an XMR settlement line chain-backed

`JOB_RECEIPT_V1` §7 says the money moved *only as far as the cited txid verifies
on-chain*, and §12 lists "No chain client" as open — `tally -verified-txids`
trusts a list you built by hand. Monero answers that without any explorer,
server, or chain client of ours, because the *wallet* can prove its own payment:

| Method | Proves |
|---|---|
| `get_tx_proof` → `check_tx_proof` | a signed proof for a `txid` + destination address (+ optional `message`); the checker gets `good`, `received`, `in_pool`, `confirmations`. **The receipt evidence.** |
| `get_tx_key` → `check_tx_key` | the tx secret key matches that txid/address — same "amount was paid there", different artifact |
| `get_spend_proof` → `check_spend_proof` | the wallet made a spend for that txid; needs no destination — a sender-side "funds out" claim |
| `get_reserve_proof` → `check_reserve_proof` | a reserve/balance statement; **not** a job payment |

Bind the proof's `message` field to the **receipt digest**, so the proof is
evidence for *this* record rather than for a payment that could be pointed at any
of them. `tally -verified-txids` then becomes `-proofs <file>`: a real chain check,
performed by whoever holds the transaction key, verifiable by someone holding no
key at all.

The caveats travel with the row, and none of them are footnotes:

- A valid proof is **not** proof the work happened, and (per the official docs)
  **not** proof the funds are still spendable — they could be time-locked or
  already spent.
- A private view key shows the wallet's **entire incoming history**. Never hand
  one over for a single job; a per-job proof is the scoped artifact.
- A proof does not identify the parties. That stays the out-of-band Ed25519 pin.

## 5. The `bill watch` blocker, precisely

`billPollRPC` posts `get_transfers {in:true, min_height:h}` and reads
`result.entries[{height,txid,incoming,amount}]` — DERO's shape. Monero answers
`result.in[]`, so a poller built on `billPollRPC` would read `entries` as empty
**forever** and bill zero mailboxes while looking perfectly healthy. That is why
`-price 2.5xmr` was refused outright at first, and why the rail that answers it is
a separate code path (`cmd/spore/billxmr.go`: `billPollRPCXMR` +
`planXMRPayments`) rather than a flag on the DERO one.

The XMR poller needs five things before it may be allowed:

1. ✅ `result.in[]` pinned by a **captured** fixture. A populated entry from a
   live v0.18.5.1 wallet was captured on 2026-10-27; the field set it settled is
   in §3 and the fixture in `cmd/spore/billxmr_test.go` is shaped from it. A
   response can still omit `in` when it is empty, and a missing key is no
   transfers rather than an error.
2. A **subaddress → customer map**, operator-supplied, because Monero gives no
   sender: which `minor` index belongs to which order. Absent map = refuse.
3. A **confirmation floor** (default 10, never 0), read from `confirmations`. A
   provisioned mailbox cannot be clawed back, and an unconfirmed transfer can be
   reorged away.
4. **The three guards from §3**: `type == "in"` (a coinbase entry in `in[]` is not
   a payment), not `locked`/`unlock_time`, and not `double_spend_seen`.
5. **Hold-and-log** for a transfer whose subaddress is unlabelled — never
   provision on a guess, and never silently drop money.

And one precondition that is not about the poller's logic at all: **Monero's RPC
authenticates with Digest, and answers a valid Basic header with `401`.** The live
wallet advertises
`WWW-authenticate: Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce=…`,
and on 2026-10-27 one credential returned `401` as Basic and `200` as Digest.
`billPollRPCXMR` therefore uses the same `github.com/icholy/digest` transport
`internal/xmr` does; the DERO rail keeps its plain `SetBasicAuth` because DERO's
wallet speaks Basic. This is not a cosmetic difference on this rail — with the
wrong scheme *every* poll fails, so the billing poller is simply dead — and it is
the one failure that must announce itself rather than be read as an empty result,
which is this section's whole subject. Nothing but a live wallet reveals it: a
mock that accepts whatever it is handed, including the old `SetBasicAuth` code,
stays green.

The path stays gated behind `-xmr-unverified` for a narrower reason than before:
auth, the response shape and the decision core are live-verified, but no live XMR
payment has been carried through provisioning into a receipt. The development
target remains an `httptest` mock in the shape of `internal/xmr/xmr_test.go`, so
the reconciliation logic is executable on every push; live verification confirms
the shape, not the logic — and on 2026-10-27 live verification did exactly that
against a real wallet, including the hold-and-log guard refusing two real,
unlabelled payments and pinning the watermark below them.

## 6. Escrow: 2-of-3 multisig is the honest XMR escrow, not HTLC

Spore's escrow is an HTLC on DERO/EVM (`RelayHTLC`, `sap.HTLCClaim`/
`HTLCRefund`), and the capability path already refuses escrow by design
([APPROVAL_RUNBOOK.md](APPROVAL_RUNBOOK.md)). **Monero has no HTLC.** `msg
escrow` is therefore not a port to XMR, and nothing in the CLI should imply it is.

What Monero does have is M-of-N multisig (`prepare_multisig`, `make_multisig`,
`exchange_multisig_keys`, `sign_multisig`, `submit_multisig`), with 2-of-3
(client, provider, arbiter) as the documented escrow shape. The official guide
calls multisig **experimental** and names a real hazard: a participant can
withhold a signed transaction while inviting a second spend attempt, so
co-signers must inspect the transaction they are signing rather than sign a
replacement. Consequences, stated as requirements:

- Multisig escrow is **opt-in and never the default** payment path. Until it
  exists, an XMR job settles directly and the receipt is the record.
- Stagenet first, both cosigners reviewing the tx, and an answer for "the other
  side withheld a signature" before it holds meaningful value.
- Swaps: XMR↔BTC atomic swaps do exist (eigenwallet, formerly UnstoppableSwap);
  COMIT's `xmr-btc-swap` was archived in August 2026 with a warning that its
  cryptography was never formally audited. A swap is a **separate exchange
  workflow**, not an embedded payment primitive — do not wire it into the job path.

## 7. Node and ops status

`deploy/monerod.service` runs pruned with `--restricted-rpc` on
`127.0.0.1:18081`, and the wallet RPC half now runs too: v0.18.5.1 on
**`127.0.0.1:18083`** (as `monero-wallet-rpc.service`, user `monero`, wallet
readable only by that user), behind Digest auth and never bound off loopback.
**Not `18082`** — on this host that port is `monerod`'s own RPC endpoint, which is
why the wallet needed its own; any client pointed at 18082 is talking to the
daemon, not the wallet. [LIVE_NODES.md](LIVE_NODES.md) §1 has the node-side steps.
Monero has no public node API the way DERO does — prune locally and keep the
wallet RPC on loopback.

## 8. Order of work

1. ✅ **Piconero is an exact asset** — `assetDecimals`, refusal of sub-piconero,
   exactness tests, mutations caught.
2. ✅ **Confirm the `result.in[]` shape** against a live wallet RPC (2026-10-27):
   one wallet, two real incoming payments, no code changed by it beyond the §3
   correction. This is what falsified `destinations` on the incoming side, and it
   is the step that caught the auth scheme.
3. ✅ **XMR branch in `bill watch`** behind `-xmr-unverified`: subaddress map,
   confirmation floor, hold-unattributed, mock-RPC test — and, added by step 2,
   a **Digest** transport, because Basic can never authenticate to a real wallet.
4. **Proof in the receipt** — an optional tx-proof block on `sign receipt`, and
   `tally -proofs` verifying instead of trusting a txid list. This is the first
   artifact that turns "claims to have paid" into "this payment exists" for XMR.
5. **The live round trip** — subaddress → payment → `get_transfers` → provisioning
   → receipt with a proof, recorded in LIVE_NODES §1. That single run is what
   moves XMR from mock-verified to live-verified. **Partially done (2026-10-27):**
   auth, the `get_transfers` decode, the guards and the watermark have now run
   against a real wallet's real payments; provisioning a mailbox and attaching a
   proof to the receipt have not.
6. **Multisig escrow**, stagenet first (§6) — and only then any UI that says
   "escrow" over XMR.

## 9. What would falsify this document

- The field set in §3 is verified against Monero **v0.18.0.0 source** (the
  `transfer_entry` struct and the incoming `fill_transfer_entry`) **and** against
  a populated `result.in[]` entry captured from a live v0.18.5.1 wallet on
  2026-10-27. The raw capture stays box-side: the wallet's subaddress and the
  txids are redacted here by the same rule that redacts the node's address. That
  capture **did** change the document, which is why step 2 was run — `destinations`
  is not on an incoming entry (§3), and `payment_id` arrives as a zeroed id rather
  than being omitted. Still not observed, and still able to falsify §3 or §5: what
  a build emits for a **locked** or `double_spend_seen` transfer (both guards are
  exercised by fixtures and by a mock, not by a real wallet), and whether some
  0.18.x patch renames one of these fields.
- The Digest-only auth in §5 is one build's behaviour. It is what epee does by
  default and it was captured directly, but a wallet started without `--rpc-login`
  needs no transport at all, and a future build could accept Basic as well. The
  rail's behaviour is unchanged either way: the credential it sends must be one
  the server accepts, and a rejection is an error rather than an empty poll.
- Multisig's experimental status and the proof caveats in §4 are the upstream
  docs' claims, cited below — they can move, and this doc should move with them.

Sources read for this plan: Monero v0.18.0.0
[`wallet_rpc_server_commands_defs.h`](https://raw.githubusercontent.com/monero-project/monero/v0.18.0.0/src/wallet/wallet_rpc_server_commands_defs.h)
and
[`wallet_rpc_server.cpp`](https://raw.githubusercontent.com/monero-project/monero/v0.18.0.0/src/wallet/wallet_rpc_server.cpp)
for the `get_transfers` request/response and entry fields (the §3 field list and
the `filter_by_height` trap are read off those), plus
[Monero issue #8140](https://github.com/monero-project/monero/issues/8140) for a
real captured result-key list; the [Monero wallet RPC
reference](https://docs.getmonero.org/rpc-library/wallet-rpc/) and
[CLI reference](https://docs.getmonero.org/interacting/monero-wallet-cli-reference/),
the [multisignature guide](https://docs.getmonero.org/multisignature/), the
[monero-wallet-rpc deployment
notes](https://github.com/monero-project/monero-docs/blob/master/docs/en/interacting/monero-wallet-rpc-reference.md),
[COMIT's archived swap repository](https://github.com/comit-network/xmr-btc-swap)
and [eigenwallet](https://github.com/eigenwallet/core).
