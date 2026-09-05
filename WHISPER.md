# Mycelium whisper — no-relay messenger

*Whisper is now the chain-agnostic payload codec (`internal/whisper`: kind byte
0x01 text / 0x02 pointer, length-prefixed) shared by every backend. On DERO —
the tree this was proven on first — it is the native no-relay unicast described
below. The same codec rides EVM/Solana/XMR via `mycelium msg ... -chain`,
sealed by the m³ secure envelope on chains without native encryption. See
`README.md` (chain-status table) and `design.md` (the secure layer).*

Goal (user, verbatim): "novel private comms tacked onto the chain, sc or no sc";
"compostable message/signal through the mempool"; friends self-host, no one
exposes their node or home IP; UI as TELA (app on-chain, no app server).

## Honest core finding (from derohe source)

DERO encrypts every tx payload **point-to-point** to the recipient wallet's key.
There is NO "broadcast a line the whole group reads off the mempool" in a stock
transfer — that's not how the payload crypto works. So the group-broadcast dream
can't ride a single stock transfer; it needs per-member txs or an SC.

**What IS real and novel: no-relay unicast.** A whisper is a real tx. It
propagates via P2P to the recipient's OWN node in ~1-2s (mempool), then confirms
(~18s, one block). The recipient's wallet decrypts it (point-to-point). No box,
no shared store, no relay, no exposed IP — each member only ever talks to their
own wallet + node. This is the flagship.

Payload budget: tx message field is `PAYLOAD0_LIMIT` = 111 bytes CBOR-encoded
Arguments (rpc/rpc.go CheckPack). A whisper line rides as 2 typed args
(`W` uint marker + `T` string text); ~80 bytes text fits after framing. Short
signaling by design — a line, an invite, a ping — not prose.

## Two delivery speeds, same payload

Both parse the SAME 2-arg payload (whisper.BuildArgs/ParseArgs). The only
difference is WHERE the receiver looks:

| | Where receiver sees it | Latency | Status |
|---|---|---|---|
| **L3 — mined anchor** | wallet `get_transfers` in:true (proven path) | ~1 block (~18s) | **BUILT** — `mycelium whisper send/recv`, unit-tested green |
| **L1 — mempool catch** | own node daemon `gettxpool` → `gettransactions` | ~1-2s | **Scaffolded** — `internal/daemon` pool watcher green; needs payload decrypt |

### L1 pool catch — why it needs Rust (and why that's cheap)
To catch a whisper in the pool BEFORE it confirms, the receiver must decrypt a
pool tx's payload themselves. The wallet only decrypts on confirmation. The
decrypt primitive lives in derohe (Research-licensed, can't ship) — but the
user's **derohe-rs** is a clean-room, **BSD-3, mainnet-proven** Rust port that
already has the tx deserializer + payload decrypt + P2P wire
(`crypto/src/rpc_args.rs`, `transaction.rs`, `wallet.rs`). So L1 = a thin Rust
scanner: poll the user's own node `gettxpool` every ~1s, pull new hashes via
`gettransactions`, try decrypt under the user's wallet key, print. ~200 lines on
top of existing crates. Non-onerous because the heavy crypto is already done and
licensed clean. `internal/daemon` (Go) already provides the pool-watch/dedupe +
the `decode_as_json` fetch seam the Rust tool or a Go bridge can reuse.

## CLI (built, green)

```
mycelium whisper send -rpc URL [-rpc-login u:p] -to ADDR -msg TEXT   # no-relay
mycelium whisper recv -rpc URL [-rpc-login u:p] [-interval 3s]       # mined catch
```

## Remaining (not built)
- **B / L1**: Rust pool-scanner (derohe-rs) for ~1-2s catch. See above.
- **L2 / TELA**: the chat UI as an on-chain contract (app hosted on chain, no
  app server). Users open the messenger from their own node's chain state.
- Live mainnet smoke test of whisper send/recv (needs 2 healthy nodes sharing a
  txpool + 2 funded wallets).

## Privacy/security truths (keep visible)
- Content: point-to-point encrypted by DERO; only recipient's wallet decrypts.
- Metadata: "a whisper tx occurred at ~time" is chain-wide visible in every
  mempool/block; ring sig hides sender. Sparse by construction.
- L1 (~1-2s) makes the pool itself the medium — the tx is in EVERY node's pool
  briefly. L3 is quieter (only blocks).
- No free lunch: live GROUP broadcast needs a relay (someone's IP) or an SC, or
  pays one tx per member. Whisper = the no-IP sparse unicast tier.
