# Monero settlement — XMR as Spore's money rail

**Status: the amount seam ships; the wallet integration does not.** `xmr` is now a
first-class money asset in the CLI (12 decimals, exact, tested). Everything below
§2 still has to be built, and §5 is the specific reason `bill watch` refuses an
`-price 2.5xmr` rather than quietly billing nothing. Nothing here is
live-verified: no XMR payment has moved through this code against a real wallet.

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

Monero's `get_transfers` returns **`result.in[]`** — `{txid, height, amount,
confirmations, subaddr_index, address, note}` — and there is **no sender field at
all**, by design. So the payer is identified by *which address was paid*:

```
create_address   {account_index:0, label:"order:<id>", count:1}
                 -> {address, address_index:{major,minor}}
label_address    {index:{major,minor}, label:"order:<id>"}
get_address      / get_address_index          # map an entry back to an order
get_transfers    {in:true, account_index:0, subaddr_indices:[…], min_height:h}
incoming_transfers                            # alternative output listing
```

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
`result.in[]`, so `entries` would be empty **forever** and the poller would
bill zero mailboxes while looking perfectly healthy. That is the whole reason
`-price 2.5xmr` is refused: the units parse exactly, the poller does not.

The XMR poller needs four things before it may be allowed:

1. `result.in[]` pinned by a **captured** fixture, not by this doc (§9).
2. A **subaddress → customer map**, operator-supplied, because Monero gives no
   sender: which `minor` index belongs to which order. Absent map = refuse.
3. A **confirmation floor** (default 10, never 0). A provisioned mailbox cannot be
   clawed back, and an unconfirmed transfer can be reorged away.
4. **Hold-and-log** for a transfer whose subaddress is unlabelled — never
   provision on a guess, and never silently drop money.

Until a live `monero-wallet-rpc` round trip lands, gate the whole path behind
`-xmr-unverified`, matching the precedent already set in `internal/backend`
("mock-verified only … every result experimental"). The development target is
*not* a live node: it is an `httptest` mock in the shape of
`internal/xmr/xmr_test.go`, so the reconciliation logic is executable on every
push. Live verification then confirms the shape, not the logic.

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

`deploy/monerod.service` already runs pruned with `--restricted-rpc` on
`127.0.0.1:18081`. The missing half is the wallet RPC on `18082`, behind auth or
an SSH tunnel, never bound to the internet; [LIVE_NODES.md](LIVE_NODES.md) §1 has
the remaining steps and the two open decisions (install path, verification
scope). Monero has no public node API the way DERO does — prune locally and keep
the wallet RPC on loopback.

## 8. Order of work

1. ✅ **Piconero is an exact asset** — `assetDecimals`, refusal of sub-piconero,
   exactness tests, mutations caught.
2. **Confirm the `result.in[]` shape** against a live wallet RPC once `monerod`
   is at tip. One request, no code — and it is the thing that can falsify §3/§5.
3. **XMR branch in `bill watch`** behind `-xmr-unverified`: subaddress map,
   confirmation floor, hold-unattributed, mock-RPC test.
4. **Proof in the receipt** — an optional tx-proof block on `sign receipt`, and
   `tally -proofs` verifying instead of trusting a txid list. This is the first
   artifact that turns "claims to have paid" into "this payment exists" for XMR.
5. **The live round trip** — subaddress → payment → `get_transfers` → provisioning
   → receipt with a proof, recorded in LIVE_NODES §1. That single run is what
   moves XMR from mock-verified to live-verified.
6. **Multisig escrow**, stagenet first (§6) — and only then any UI that says
   "escrow" over XMR.

## 9. What would falsify this document

- The `result.in[]` field set in §3/§5 comes from the **official RPC reference**,
  not from a live wallet. Step 2 exists to catch a mismatch; if a real response
  names fields differently, the fixture and this document are both wrong and both
  get fixed before anything bills.
- Multisig's experimental status and the proof caveats in §4 are the upstream
  docs' claims, cited below — they can move, and this doc should move with them.

Sources read for this plan: the [Monero wallet RPC
reference](https://docs.getmonero.org/rpc-library/wallet-rpc/) and
[CLI reference](https://docs.getmonero.org/interacting/monero-wallet-cli-reference/),
the [multisignature guide](https://docs.getmonero.org/multisignature/), the
[monero-wallet-rpc deployment
notes](https://github.com/monero-project/monero-docs/blob/master/docs/en/interacting/monero-wallet-rpc-reference.md),
[COMIT's archived swap repository](https://github.com/comit-network/xmr-btc-swap)
and [eigenwallet](https://github.com/eigenwallet/core).
