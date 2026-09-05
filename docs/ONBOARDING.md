# Mycelium — getting started (onboarding)

*The shortest honest path from zero to a private message, on the chain you
already use. m³ is E2E-encrypted and no-relay: you talk point-to-point, nobody
in the middle.*

## 0. What you're getting into

- **You run your own endpoint** (a wallet + a binary). No server, no box, no
  operator to subpoena.
- **Messages are E2E-encrypted** — DERO natively; EVM/Solana/XMR via mycelium's
  own envelope. Content is private even on public chains.
- **Messages rot** — keys erase after read, bodies expire. Nothing permanent
  but a dead hash.
- **You hold the keys.** Your mycelium key is chain-independent — it's your
  identity on every chain.

Get the binary: `mycelium-windows-amd64.exe` from
[releases](https://github.com/liqdmetal/mycelium/releases), or `go install
github.com/liqdmetal/mycelium/cmd/mycelium@latest`.

---

## 1. If you use DERO (live, mainnet)

**Fastest to a message.** You need a funded, registered DERO wallet + the
wallet's RPC server running.

```
# terminal 1 — keep open (your wallet serves messages)
dero-wallet-cli --wallet-file my.db --rpc-server --rpc-bind 127.0.0.1:10103

# terminal 2
mycelium whisper send -to <friend-dero-addr> -msg "hi"
mycelium whisper recv              # watch for replies
```

Full friend walkthrough: `docs/PEER_SETUP.md`.

---

## 2. If you use an EVM chain (EVM-compatible — live on dev/anvil)

**E2E-encrypted even though EVM calldata is public** (mycelium's secure
envelope keeps the content private). Needs a signing endpoint (anvil/geth or a
wallet-RPC that signs) + our address.

```
# generate an identity keypair once (give the PUB to people, keep PRIV secret)
mycelium msg keygen

mycelium msg send -chain evm -rpc <rpc-url> -from <0x-your-addr> \
  -key <our-priv> -peer-pub <recipient-pub> -to <0x-their-addr> -msg "hi"

mycelium msg recv -chain evm -rpc <rpc-url> -from <0x-your-addr> -key <our-priv>
```

Note: EVM is verified against a local node (any EVM JSON-RPC). Point `-rpc` at
whatever EVM signer you control.

---

## 3. If you use Solana (live on mainnet)

**A mycelium mailbox program is deployed on Solana mainnet** and verified.
Needs a funded Solana signer keypair (your deployer/wallet key).

```
# your Solana signer keypair JSON (e.g. from solana-keygen)
mycelium msg send -chain solana -keyfile <your-keypair.json> -to self -msg "hi"
mycelium msg recv -chain solana -keyfile <your-keypair.json>
```

Program: `GbNWrvkTgRgPp8n1BPoh9Erp47fVFDNtoX6f1FKBraAs`. Currently the client
delivers to your own inbox (self-messaging); cross-wallet delivery needs both
parties running the backend.

---

## 4. If you use Monero (XMR — backend built, live verify pending)

Monero has **no per-recipient message field** (only an 8-byte payment id), so
an XMR message is a **knock, not content** — a short signal that points to
off-chain rendezvous delivery. The backend exists and is mock-tested; live
verification is pending a synced Monero node.

```
mycelium msg send -chain xmr -rpc <monero-wallet-rpc> -to <xmr-addr> -msg "hi"
```

---

## Identity keys (for E2E on non-DERO chains)

```
mycelium msg keygen            # prints pub + priv
mycelium msg keygen -out key   # write priv to file (0600)
```

- **Give your PUB** to people messaging you — they encrypt to it.
- **Keep your PRIV secret** — it decrypts what's sent to you.
- Same key works across EVM/Solana/XMR (chain-independent identity).

## Donations
`mycelium donate --all` shows the per-chain donation rail.

## Commands at a glance

```
mycelium whisper send/recv        DERO no-relay unicast (native E2E)
mycelium msg send/recv -chain X   any chain (X = dero|evm|xmr|solana)
mycelium msg keygen               identity keypair for E2E
mycelium donate [chain]|--all     per-chain donation addresses
mycelium daemon/channel/web       mailbox / IRC rooms / browser chat (DERO)
```

## Honest limits (so you're not surprised)
- **EVM/Solana/XMR content is private, but the tx/event is visible** (metadata).
- **XMR** carries short signals only; content is off-chain.
- **Solana** is self-messaging today (recipient must sign); cross-wallet is next.
- **Group broadcast** still needs a relay/SC — no-relay is point-to-point.
