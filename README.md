# Mycelium — m³ · Mycelium Multi-chain Messenger

**The common mycorrhizal network (CMN) for crypto.**

In a forest, trees look separate — but underground they are joined by a shared
mycorrhizal network through which they exchange nutrients and warn each other.
That is the model here:

- **Trees = the users / endpoints.** Each is an independent wallet + node on
  its own chain (DERO, EVM, Solana, Monero…). Separate canopies, self-sovereign.
- **Mycelium = the substrate running underneath.** The private, no-relay
  transport that lets any tree signal another — quietly, point-to-point, no
  relay or box in between.
- **The common mycorrhizal network (m³)** is what emerges: trees on different
  chains, all connected through one underground fabric.

**A compostable, no-relay private messenger.** Messages rot. The body never
rides a block in a way that survives key rotation; what's permanent on-chain is
a hash and dead keys. Private comms tacked onto the chain — no box, no shared
store, no relay, no exposed IP. Each tree only ever talks to its own roots.

## What it is

**Not a chain.** A transport + coordination layer that rides a chain. It needs
only two things any chain provides:

1. An **encrypted point-to-peer payload seam** (the tx message field).
2. A **wallet/signer** holding keys, exposed over RPC.

The core is chain-agnostic: `internal/chain` (the `Chain` interface + `Watch`
poller) is the seam, and `internal/whisper` is the canonical payload codec.
Everything above — the crypto, rendezvous, rooms, body store, UI — sits above
the chain and never touches consensus.

## Chain status

| Tree | Backend | Payload seam | Secrecy | Status |
|---|---|---|---|---|
| **DERO** | `internal/dero` | native point-to-point tx payload | native | **live, mainnet-verified** |
| **EVM-compatible** | `internal/evm` | calldata / events (public) | m³ secure ECDH envelope | **live-verified** on a local anvil node |
| **Solana** | `internal/solana` + BPF mailbox program | program inbox PDA (public) | m³ secure ECDH envelope | **live on mainnet** (program below) |
| **Monero (XMR)** | `internal/xmr` | 8-byte payment id only | signal on-chain + off-chain rendezvous | built, **mock-verified** — node still syncing |
| Zcash / ARRR / Decred / Verge / Zama | — | — | — | not built (future) |

Precisely:

- **DERO** — tree #1. Whisper (no-relay unicast), long nobody-but-us bodies,
  rooms, browser chat. Mainnet-verified. Native point-to-point encryption.
- **EVM** — the Go backend rides any EVM JSON-RPC. **Live-verified on a local
  anvil node** (not a real public EVM chain — same code path, swap in a funded
  account to go live). `contracts/MyceliumMailbox.sol` exists for a scalable
  inbox on busy chains (not yet deployed).
- **Solana** — the Go backend + a Rust BPF mailbox program (per-recipient PDA
  inbox). **Deployed and live-verified on Solana mainnet**: program ID
  `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs` (v2; v1 had a rent bug), RPC
  default `https://api.mainnet-beta.solana.com`. The client currently does
  **self-messaging** (the program requires the recipient to sign) — cross-wallet
  delivery needs both parties running the backend.
- **Monero** — built and mock-verified only. XMR has no per-recipient encrypted
  payload; a tx is a **knock** (short signal ≤8 bytes rides the payment id),
  content goes off-chain rendezvous. Not yet live — a pruned `monerod` is
  **syncing (~60%)** on the Hetzner node to enable a real wallet-rpc verify.

**E2E secure layer.** Chains without native payload encryption (EVM, Solana,
XMR) expose their tx/metadata publicly. `internal/secure` restores privacy: an
XChaCha20-Poly1305 envelope (`kind 0xE0 ‖ eph_pub 32B ‖ nonce 24B ‖
ciphertext`), sealed with X25519 ECDH + HKDF-SHA256. Calldata / inbox records
carry no plaintext — only the recipient's private key decrypts.

## Privacy model

- **Point-to-point**: DERO encrypts every tx payload natively; other chains are
  sealed by the m³ secure envelope.
- **No relay**: a whisper is a real tx that P2P-fans to the recipient's own
  node. No intermediary ever holds both halves of a conversation.
- **Mycelium**: bodies are TTL-evicted; keys are ephemeral and erased; the
  on-chain record is a hash + a dead key. Old messages become unrecoverable.
- **Honest limits**: "a tx happened at ~time" is visible chain-wide (DERO's ring
  sig hides the sender; EVM/Solana/XMR expose tx metadata — content stays
  private only via the envelope). Group *broadcast* still needs a relay or an SC
  — no-relay is unicast by construction. Cross-chain direct messaging is
  impossible (different key crypto); cross-chain = rendezvous/relay + identity
  proof. Read `WHISPER.md` and `design.md` for the full threat model.

## CLI

```
mycelium demo | keygen | daemon | send | channel | chat | web | donate
mycelium whisper send|send-long|recv|keygen          # DERO no-relay unicast
mycelium msg send|recv|send-long|keygen -chain dero|evm|xmr|solana   # multi-chain
```

`msg` dispatches to the right backend via `internal/backend` (default `-chain
dero`). `donate` prints the per-chain donation rail.

## Build & test

```
go build ./...
go vet ./...
go test ./...
```

## Peer setup (message a friend)

Mycelium is **no-relay**: you and a friend each run a wallet, no server in
between. Full walkthrough in [`docs/PEER_SETUP.md`](docs/PEER_SETUP.md). The
short version:

```
1. Download the release binary + install dero-wallet-cli
2. Create + register + fund a DERO wallet (tiny amount)
3. dero-wallet-cli --rpc-server --rpc-bind 127.0.0.1:10103   (leave open)
4. Send:   mycelium whisper send  -to <friend-addr> -msg "hi"
   Receive: mycelium whisper recv  (keep running)
```

## Roadmap (see ROADMAP.md)

- **XMR live-verify** once the Hetzner monerod finishes syncing.
- **MyceliumMailbox.sol** deploy, **Solana cross-wallet delivery**.
- **L1 mempool catch (~1-2s)**: Rust scanner on derohe-rs (BSD-3, clean-room,
  mainnet-proven) watches the node txpool and decrypts before mining.
- **Relay fabric** and **cross-chain identity proof** (gated, hard).

## License

BSD 3-Clause. Mycelium is clean-room Go; it imports no derohe source. derohe-rs
(the Rust port used for L1) is separately BSD-3-Clause.
