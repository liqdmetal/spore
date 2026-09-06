# mycelium-messenger (TELA doc)

The Mycelium messenger surface as a TELA dApp: `tela.json` (manifest) +
`index.html` (the app). Following the structure `tela-toolkit` scaffolds.

## What it is
A functional single-file messenger UI that talks to **your own** DERO wallet RPC
(`--rpc-server`) for whisper send/recv. Runs as a TELA doc — the HTML/JS/CSS live
on-chain and execute locally. Names resolve via the daemon's `DERO.NameToAddress`.

## The honest boundary (read this)
A browser-hosted TELA doc **cannot shell out to `spore-peer`** — browsers have
no process/child-process access. So inside the doc:
- **whisper (short, no-relay)** — fully works: it posts the 2-arg payload via
  your wallet's `transfer` and polls `get_transfers`.
- **long nobody-but-us body** — the doc detects the pointer-whisper and shows
  "fetch via your key", but the actual P2P fetch+decrypt must run on the CLI
  (`spore whisper recv -key … -peer-addr …`) because that shells to
  `spore-peer`. TELA is the UI over your local wallet/daemon, not a full P2P
  client.

That split is structural, not a shortcoming of this file — it's how TELA's
local-execution model works. The doc is the thin signing/display layer.

## Files
```
tela/mycelium-messenger/
  tela.json    name, version, entry=index.html, engine=tela, encrypted:[data/]
  index.html   the messenger (whisper lane + long-pointer detection + setup)
```

## Deploying as a TELA contract (once TELA install tooling / SC is available)
1. Keep this scaffold; the `index.html` + `tela.json` are the doc payload.
2. Install via the DERO SC path used for TELA docs (TELA-DOC-1 + TELA-INDEX-1,
   `install-doc` → `install-index`), or `install_sc` if you deploy the raw doc.
3. The deployed doc, when opened, reads its manifest and serves `index.html` from
   chain state — no app server.
4. A user opening it still needs their wallet `--rpc-server` running (the doc
   signs/reads through it). This is the model: chain hosts the app, wallet hosts
   the keys.

## CORS note
The doc calls your wallet `/json_rpc`. If the wallet binds `127.0.0.1`, serve the
doc from a same-origin page OR go through the `spore web` proxy (which adds
`/whisper/*` endpoints + CORS). Otherwise the browser blocks cross-origin calls
to the wallet.

## Local preview
Open `index.html` directly in a browser, or via the Hermes preview pane. The
config modal lets you point at your wallet/daemon/address.
