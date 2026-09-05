# Mycelium Solana program — per-recipient PDA inbox

A durable inbox for mycelium messages on Solana. Recipients have a PDA account
that stores their messages as opaque mycelium **E2E-encrypted envelopes** —
the program never sees plaintext and never holds a key.

```
pda = PDA(program_id, ["mycelium", recipient_pubkey])
```

Each inbox stores a list of `StoredMessage { from, data, seq }` where `data`
is the client's `internal/secure` envelope (kind || eph_pub || nonce ||
ciphertext).

## Instructions
| Tag | Name | Accounts | Data |
|---|---|---|---|
| 0 | `deliver` | recipient (signer), inbox (PDA, writable), payer, system_program | `data` (the envelope bytes) |
| 1 | `burn` | recipient (signer), inbox (PDA, writable) | `seq` (u64 LE) — empties message (compost) |

- **Anyone** can `deliver` to a recipient (like sending email to an address).
- **Only the recipient** (signer matching their inbox PDA) can `burn`.
- Messages are appended in order; `seq` = index.
- `burn` empties the data (compost semantics) — content is gone, not hidden.

## Status
- Source + unit tests (`tests/mailbox_test.rs`): **cargo test green** — PDA
  determinism, borsh inbox round-trip, empty-inbox parse.
- BPF artifact `mycelium_mailbox.so` (88 KB): **built with cargo-build-sbf
  v4.3.0** on the Hetzner node. Ready to deploy.
- **NOT yet deployed** to a Solana cluster (needs the Solana CLI + a cluster /
  funded deployer key).

## Build
```bash
# native unit tests (no BPF toolchain needed)
cargo test

# BPF program (needs cargo-build-sbf in PATH)
cargo-build-sbf
# -> target/deploy/mycelium_mailbox.so + keypair
```

## Integration (client side)
The Go `internal/solana` backend (in the main mycelium repo) is the next step:
`PostPayload` sends a tx calling `deliver` to the recipient's inbox PDA;
`ListIncoming` reads the recipient's inbox PDA via `getAccountInfo` and returns
stored envelopes. See the main repo ROADMAP.
