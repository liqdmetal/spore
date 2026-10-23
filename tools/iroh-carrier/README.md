# spore-iroh

`spore-iroh` is an experimental, self-hosted Iroh sidecar for Spore's content-addressed body-store seam. It stores blobs locally, serves them from an explicitly operated provider, and fetches them from explicit peer tickets. It is not a public storage network or a production-certified transport.

## Status and verification boundary

This revision passed local Windows/MSVC Rust unit and process-level loopback tests, a release-binary loopback transfer with four concurrent add processes and four parallel GET processes, and the Go Iroh-store / CLI-configuration checks. CI and release matrices are configured, but no hosted run was performed. Clippy was not installed in the local Rust toolchain, so the local quality script reported it as skipped.

No public-network test was run. Iroh `1.2.0` and `iroh-blobs 0.103.0` are pinned; `iroh-blobs` is pre-1.0. Treat this as an experimental transport until dependency maturity, public-network behavior, recovery, and security have been independently reviewed.

## Network and security model

The sidecar uses Iroh's Minimal endpoint preset. It omits the default relay and address-lookup integrations: peers dial directly using provider tickets exchanged out of band. There is no built-in DHT, relay fallback, NAT traversal, or anonymous routing. A provider must be reachable at the addresses in its live ticket; endpoint addresses and fetch timing are visible to the peer.

A provider ticket is an address, not an access-control token. A peer with the ticket and a blob hash can request matching content from that provider. Serve only public data or end-to-end ciphertext. Do not use this as an authorization boundary, and do not put plaintext, credentials, or private keys in the blob store.

The `info` command prints a diagnostic endpoint ticket and closes that endpoint; it is not a live provider. `blob serve` prints its current `provider_ticket` and keeps the endpoint running. Share the live ticket from `blob serve` over a separate trusted channel; replace it if the provider's reachable address changes.

Wraps Iroh `1.2.0` and `iroh-blobs 0.103.0` (MIT/Apache-2.0).

## CLI contract

```text
spore-iroh --version
spore-iroh info
spore-iroh blob add <file>
spore-iroh blob get <hash>
spore-iroh blob serve
```

- `--version` reports the sidecar capability marker and pinned Iroh versions; the Go adapter checks it before use.
- `blob add` imports a file up to 20 MiB and prints its Iroh BLAKE3 locator.
- `blob get` emits verified blob bytes on stdout; diagnostics go to stderr.
- `blob serve` keeps the local store available to peers and services add/get requests from other sidecar processes.
- `info` is diagnostic only: it prints a ticket and closes that endpoint. Use the live ticket printed by `blob serve`.

The Spore E2 store keeps a local mapping from the Spore SHA-256 CID to the Iroh BLAKE3 locator and re-verifies fetched bytes against the CID. E2 Pointer V2 carries the locator so the receiver does not need the sender's local index.

## Provider and receiver flow

1. Start `spore-iroh blob serve` on the provider with `SPORE_IROH_STORE` set to its persistent local store root. Keep the process running; it prints a live `provider_ticket`.
2. Send that ticket and the blob locator to the receiver over a separate trusted channel. A restart or address change may require sharing a replacement ticket.
3. Set the receiver's `SPORE_IROH_PROVIDERS` to the comma-separated live ticket list. `blob get <hash>` then tries the local store and configured providers in order.
4. For Spore E2, select `-store iroh://`; the Go adapter uses the same sidecar contract and validates the returned payload against the E2 SHA-256 CID.

Iroh's BLAKE3 locator is a transport address and is not interchangeable with Spore's SHA-256 CID. E2 Pointer V2 carries both values explicitly.

## Configuration

| Variable | Purpose | Default / limit |
|---|---|---|
| `SPORE_IROH_STORE` | Iroh blob and control-state root | Platform user data directory; set explicitly to share a store with the provider process |
| `SPORE_IROH_PROVIDERS` | Comma-separated provider tickets used for remote `blob get` | Empty; at most 8 tickets and 16 KiB total; exchange tickets out of band |
| `SPORE_IROH_BIND_ADDR` | Optional local IP:port for the endpoint | Iroh-selected address; port `0` requests an ephemeral port |
| `SPORE_IROH_BIN` | Go adapter's sidecar executable override | `spore-iroh` resolved from `PATH` |
| `SPORE_IROH_INDEX` | Go adapter's local locator-index path override | `<store-root>/iroh-index.json` |

When using Spore's Go E2 commands, `-store iroh://` selects this backend. Keep the provider's `blob serve` process and its `SPORE_IROH_STORE` pointed at the same store used by its local sidecar commands. Set `SPORE_IROH_PROVIDERS` on the receiving side to the provider's live ticket or tickets.

## Build and test

Requires Rust 1.91 or newer. From this directory:

```sh
cargo fmt --all -- --check
cargo test --offline --locked --all-targets -- --test-threads=1
cargo build --offline --locked --release --bin spore-iroh
cargo test --offline --locked --release --test loopback_transfer -- --test-threads=1
```

The process-level loopback tests exercise provider and consumer sidecars on loopback, including concurrent independent writers and readers. They do not exercise public discovery, relays, NAT traversal, or internet reachability.

GitHub Actions CI is configured to run format, Clippy, all-target tests, and a release-binary loopback test on Ubuntu, Windows, and macOS. The release workflow builds Linux/amd64, Windows/amd64, macOS/amd64, and macOS/arm64 sidecar artifacts, generates SHA-256 checksums, and includes those artifacts in release provenance subjects.

## Resource bounds and remaining limits

| Bound | Value |
|---|---:|
| Blob body | 20 MiB |
| Provider configuration | 16 KiB / 8 tickets |
| Per-provider fetch attempt | 25 seconds, sequential |
| Provider response wait | 220 seconds (8 attempts plus 20 seconds) |
| Go adapter outer get deadline | 5 minutes |
| Pending control requests | 8 |
| Concurrent control operations | 8 |
| Pending body reservation | 80 MiB |
| Control response file | 2 KiB |
| Stale control/response cleanup | 10-minute TTL; 60-second sweep while idle |
| Queue-lock admission wait | 20 seconds |

Control requests and response bodies use bounded files under the store root. On Unix, the sidecar creates private directories/files; on Windows it relies on inherited user-profile ACLs. Blob payloads are not encrypted at rest by this sidecar.

`iroh-blobs 0.103.0` is pre-1.0 and no public-network, relay, NAT, or crash-recovery test has been performed. `blob rm` is not implemented: deleting a local copy cannot erase copies another node has fetched.

## Supported E2 body path in Spore

| Body store | Sender | Receiver | Status |
|---|---|---|---|
| HTTP mailbox (`-store http(s)://`) | Mailbox or operator | Same store | Supported |
| Nostr commons (`-store nostr://…`) | Public relays | Relay pool | Supported, best-effort retention |
| Direct peer (`disk://` + `peer://`) | Sender's Go `spore-peer serve` | Sender's reachable endpoint | Supported; loopback E2 round trip tested |
| Iroh (`-store iroh://`) | Local Iroh store and provider | Paired provider(s) | E2 V2 code wired; local Go and Rust loopback checks pass; public-network behavior unverified |

The index is local to each Spore installation; it is not a replication mechanism. E2 V2 carries the Iroh locator so the receiver can fetch from its configured providers without the sender's index, then verifies the returned bytes against the original SHA-256 CID. A blob remains available only while at least one reachable provider retains it.