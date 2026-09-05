# Chat with a friend using mycelium — 5-minute setup

Both you and your friend each need **two things running**: your DERO wallet's
RPC server, and the `mycelium` binary. Everything else is a command.

## 1. Get the binaries

**mycelium** (download, no Go needed):
- Linux/macOS/Windows binaries: https://github.com/liqdmetal/mycelium/releases/latest
- pick your OS, download `mycelium-<os>-<arch>`, `chmod +x` (linux/mac), put it on PATH.

**mycelium-peer** (only needed for LONG messages, not short whispers):
- Build from https://github.com/liqdmetal/mycelium-peer (`cargo build --release`)
  or use the copy already on a shared box.

## 2. Start your wallet RPC

Your friend already runs a DERO wallet. Start it with the RPC server on a known
address, and make sure it has a little balance (for the tiny postage on sends):

```sh
dero-wallet-cli --wallet-file mywallet.db \
  --daemon-address <your node or a public node> \
  --rpc-server --rpc-bind 127.0.0.1:20209
```

> Privacy note: point at **your own** derod for full privacy. A public daemon
> works but trusts that node operator more. Your wallet needs enough DERO to pay
> the ~0.0002 tx fee per send.

Confirm it's up:
```sh
curl http://127.0.0.1:20209/json_rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"getaddress"}'
```

## 3. Chat

**Receive** (leave running in a terminal):
```sh
mycelium whisper recv -rpc http://127.0.0.1:20209/json_rpc
```

**Send** (your friend is Bob; address him by his DERO name or full address):
```sh
mycelium whisper send \
  -rpc http://127.0.0.1:20209/json_rpc \
  -daemon http://127.0.0.1:10102/json_rpc \
  -to bob -msg "meet at the usual place"
```
`-to bob` resolves his DERO name via the daemon. Or pass his full `dero1…`
address and omit `-daemon`. `-msg` is short (~90 chars) — that's a whisper.

When Bob sends back, your `recv` prints it:
```
whisper 1d491ba430c35479…: hey, on my way
```

**That's the no-relay nobody-but-us path.** Every whisper is a real DERO tx,
encrypted point-to-point to the recipient's wallet. No box, no relay, no server
in the middle — each of you only ever talks to your own wallet + node.

## Long messages (files / prose)

Short whispers top out ~90 bytes. For anything longer, see the full guide at
`docs/USER_GUIDE.md` — it's keygen → send-long → serve → recv fetch. Both peers
must be online to transfer the body, and the sender must run `mycelium-peer
serve` so the recipient can pull it.

## Notes
- Your wallet must stay running while you chat (it signs + delivers).
- Names (`-to bob`) need `-daemon`; full `dero1…` addresses don't.
- There is no "point at a server and tada" — the wallet is the engine. That's
  what makes it private.
