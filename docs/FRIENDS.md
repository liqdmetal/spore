# Chat with a friend using spore — 5-minute setup

Both you and your friend each need **two things running**: your DERO wallet's
RPC server, and the `spore` binary. Everything else is a command.

## 1. Get the binaries

**spore** (download, no Go needed):
- Linux/macOS/Windows binaries: https://github.com/liqdmetal/spore/releases/latest
- pick your OS, download `spore-<os>-<arch>`, `chmod +x` (linux/mac), put it on PATH.

**E2 kit and body store** (required for new messages):
- Run `spore init -dir ~/.spore` and keep the identity/state files private.
- Configure the recipient's mailbox or another supported body store.
- New DERO messages use X3DH + Double Ratchet; old native records remain receive-only.

The optional Rust `spore-peer` compatibility transport is only for historical
long-body records and is not used for new E2 sends.


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
spore whisper recv \
  -rpc http://127.0.0.1:20209/json_rpc \
  -identity ~/.spore/identity.key -spk ~/.spore/spk.key \
  -opk-pool ~/.spore/opk-pool.json \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key
```

**Send** (your friend is Bob; use his bundle and pinned signing key):
```sh
printf 'meet at the usual place\n' | spore whisper send \
  -rpc http://127.0.0.1:20209/json_rpc \
  -to bob -identity ~/.spore/identity.key \
  -bundle ./bob-bundle.json -pinned-sig BOB_SIGNING_KEY_HEX \
  -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -ringsize 16
```
`-to bob` resolves his DERO name when `-daemon` is configured. Or pass his
full `dero1…` address. New DERO sends use X3DH + Double Ratchet and default to
ring size 16; pass `-ringsize 8` for the smaller supported transaction.

When Bob sends back, the E2 receiver fetches the body, advances the ratchet,
and prints it. The DERO transaction contains only the opaque pointer.

## Long messages (files / prose)

Short and long DERO sends use the same E2 path. For a file:
```sh
spore whisper send-long \
  -to bob -identity ~/.spore/identity.key \
  -bundle ./bob-bundle.json -pinned-sig BOB_SIGNING_KEY_HEX \
  -file ./body.txt -store https://your-mailbox.example \
  -state-dir ~/.spore/state -state-key ~/.spore/state.key \
  -ringsize 16
```
The body is ratcheted and stored off-chain; no `spore-peer` process is used for
new E2 sends. Historical native/one-shot records remain receive-only.

## Notes
- Your wallet must stay running while you chat (it signs + delivers).
- Names (`-to bob`) need `-daemon`; full `dero1…` addresses don't.
- There is no "point at a server and tada" — the wallet is the engine. That's
  what makes it private.
