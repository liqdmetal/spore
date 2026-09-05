# Mycelium

**A compostable, no-relay messenger on DERO.**

Messages that rot. The body never rides a block in a way that survives key
rotation; what's permanent on-chain is a hash and dead keys. Private comms
tacked onto the chain — no box, no shared store, no relay, no exposed IP.
Each party only ever talks to their own wallet and node.

## What it does

| Mode | Command | How it works |
|---|---|---|
| **Whisper** (no-relay unicast) | `mycelium whisper send/recv` | a short line rides a DERO tx payload, encrypted point-to-point; your node delivers it. No server. |
| Mailbox (Model A) | `mycelium daemon` + `send` | durable per-endpoint inbox; bodies off-chain, anchor on-chain |
| IRC rooms | `mycelium channel` + `chat` | public/private rooms, presence, TTL-bounded lines |
| Web chat | `mycelium web` | same rooms in the browser, optional TLS |

## Privacy model

- **Point-to-point**: DERO encrypts every tx payload to the recipient. Only
  their wallet decrypts.
- **No relay**: a whisper is a real tx that P2P-fans to the recipient's own
  node. No intermediary ever holds both halves of a conversation.
- **Mycelium**: bodies are TTL-evicted; keys are ephemeral and erased; the
  on-chain record is a hash + a dead key. Old messages become unrecoverable.
- **Honest limits**: "a tx happened at ~time" is visible chain-wide (ring sig
  hides the sender). Group *broadcast* still needs a relay or an SC — whisper
  is the no-IP unicast tier. Read `WHISPER.md` and `design.md` for the full
  threat model.

## Build & test

```
go build ./...
go vet ./...
go test ./...
```

## Live on DERO mainnet (verified 2026-09-05)

`mycelium send` → min-postage anchor tx mined; `mycelium daemon` recv → body
decrypted exactly once; bodies survive daemon restart (DiskStore). See
`design.md` Status and `WHISPER.md`.

## Roadmap (see WHISPER.md)

- **L1 mempool catch (~1-2s)**: Rust scanner on derohe-rs (BSD-3, clean-room,
  mainnet-proven) watches the node txpool and decrypts before mining.
- **TELA UI**: the messenger as an on-chain contract (app hosted on the chain,
  no app server).

## License

BSD 3-Clause. Mycelium is clean-room Go; it imports no derohe source. derohe-rs
(the Rust port used for L1) is separately BSD-3-Clause.
