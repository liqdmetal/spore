# Spore Production Roadmap

*Derived from `../spore-stack-audit-2026-09-07.md`. Defines what separates a production-ready private messenger from a research artifact, the minimum viable trust model, and the ordered work to get there.*

---

## 1. The line between research artifact and product

A research artifact says "the crypto is sound." A product must be able to say all of the following simultaneously:

1. **An attacker who can reach your network cannot read, delete, or spend.** (Today: false — C1/C2/C3 in the audit.)
2. **You can prove a message came from the person you think it did.** (Today: false — no sender authentication.)
3. **Delivery works end-to-end on every live chain.** (Today: Solana receive broken past message #1; burn bricked; spore-peer rejects ~1.6% of bodies.)
4. **The data-at-rest story matches the data-on-chain story.** ("Messages rot" is currently falsified by `messages.log`.)
5. **An ordinary user cannot configure it into an unsafe state by default.** (Today: every dangerous surface is the default.)

Rule of thumb: ship nothing that listens on a socket until (1) and (5) hold.

## 2. Minimum viable trust model — what the user trusts, nothing else

The minimum viable trust model is the floor, not the ceiling. The user trusts exactly four things and nothing more:

- the code they ran (audit + reproducible build or signed release),
- their own keys (device-local, never leaves),
- the chain's security model (DERO ring sigs, EVM/Solana consensus) for delivery and ordering,
- their own capacity to read a doc and not paste a secret into a chat.

A hosted service is the opposite of that model: it asks the user to trust a third party with reachability. That's a different product (Model B), sold separately with its own honest limits. The core product is the zero-server path.

## 3. The six invariants (the audit translates these into test gates)

Relying on names is fragile; the testable properties are the contract.

| # | Name | What it means in plain terms | The audit's test label |
|---|---|---|---|
| T1 | Authenticity | A message in your inbox is one your contact's key produced, not a network injection. Until this lands, "from Alice" is a claim, not a fact. | Sender Authentication (H1) |
| T2 | Confidentiality | No party other than the sender and receiver endpoints ever holds the plaintext or the key material that can recover it. | Confidentiality review |
| T3 | Least exposure | Every network listener defaults to loopback. Binding to a real interface is an explicit, justified choice, not the default. | Loopback-by-default audit (C1/C2) |
| T4 | Rottable at rest | Anything the user can recover, an attacker who later takes the disk cannot — or the retention is explicit and bounded (a log with a retention policy the user chose), not indefinite. | Data-at-rest review (H5) |
| T5 | Best-effort availability, never trusted delivery | Any relay, mailbox, or peer can silently drop bodies. The protocol does not depend on their honesty for secrecy or authenticity; it only depends on them for latency and reach. Withholding is equivalent to nonexistence from the protocol's point of view — the user retries, gives up, or uses a paid path. | Availability / DoS review |
| T6 | Content-addressing everywhere bodies land | A body is accepted only if sha256(body) == the CID the pointer references. No body is served because "it looks like the right size" or "the relay said so." | spore-peer framing audit (H4) |

These six are the product. Everything else is implementation detail or UX.

## 4. P0 — get the floor (the stuff that, if missing, means this is not a product)

P0 is the non-negotiable floor. Items below are not "nice to have" — each one is a gate that says "this is still research."

**P0-1 — loopback by default, token-gated when it must cross one.** Every listener that can touch user data binds to `127.0.0.1` unless the user explicitly opts into a real interface, and anything that crosses a network boundary authenticates the other side with a bearer token or equivalent. This closes the "anyone on the LAN can talk to your daemon" class of bug. Audit items C1/C2.

**P0-2 — a malicious or mistaken remote store cannot hand you garbage and have you treat it as mail.** spore-peer (and any future body-fetch path) must check that a fetched body hashes to the CID in the pointer before it becomes plaintext. The old behavior — accepting a body because it arrived — is the class of bug that lets a hostile peer feed you ciphertext that decrypts to garbage or, worse, to something that looks like mail. Audit item H4. The honest caveat: the frame protocol as implemented today rejects ~1.6% of valid bodies because it once treated "starts with ASCII 4/5" as an error signal. That is now fixed, but it is the exact shape of the bug class — verify framing by CID, not by content sniffing.

**P0-3 — the Solana burn path must actually work, and the mailbox must not hand out the same message twice.** Two delivery bugs made it into a release: `burn` was bricked (a body delivered once could be re-served), and the mailbox could hand out the same message to the same recipient more than once under some conditions. Both are delivery-integrity bugs, not "edge cases." Fix + bank-level tests.

**P0-4 — no plaintext secrets in default logs, no default listeners on real interfaces, no default curl of a hard-coded remote.** The audit found plaintext secrets in logs, listeners on real interfaces by default, and a default outbound connection to a hard-coded remote. All three are "the default configuration leaks or exposes" bugs. Fix the defaults; a power user who wants different behavior can opt in.

**P0-5 — the "messages rot" claim must be true, including the things you write to disk for convenience.** A log file that grows without bound and contains message metadata is not "compostable." If you ship a feature that persists anything message-related, it either has a retention policy the user controls or it is not a compostable messenger.

**P0-6 — sender authentication.** This is T1. Until the product can tell the user "this message came from the key you think it came from," the messenger is unauthenticated. This is the single biggest gap between "we can send bytes" and "this is a messenger you can trust." Tracked separately (signed prekeys, envelope v2). See §8.

**P0-7 — reproduce the build / sign the release.** A user cannot audit a binary they cannot rebuild or verify. Either the build is reproducible or the release is signed and the signing key's trust story is documented. Pick one and make it real.

## 5. P1 — make it a real messenger (sender authentication, documented honest limits, one full live chain end-to-end)

P1 is what turns the floor into a product. P0 says "the defaults don't leak and bodies aren't garbage." P1 says "the messenger is actually authenticated and the user knows what 'private' does and does not mean."

**P1-1 — sender authentication lands.** T1 holds. The user can pin contacts, the product verifies the sender's key against the pin, and the honest-caveat doc says what authentication does not cover (device compromise, metadata, the out-of-band step). This is the gating item for "this is a messenger" rather than "this is a pipe."

**P1-2 — document the honest limits on every live chain, in the product, not in a design doc.** For each live chain the product supports, say what "private" means on that chain and what it does not. DERO native payload encryption is real; EVM/Solana carry ciphertext but the metadata (who sent to whom, when) is visible on-chain; spore-peer is a transport, not a trust anchor. This is not marketing honesty; it is the difference between a user who understands their threat model and one who does not.

**P1-3 — one full end-to-end path on a live chain, documented, with the honest caveats attached.** A real DERO or Solana send → receive → burn, run by a human following the docs, with the known limits stated next to it. Not a script. Not a testnet-only path. A human should be able to follow the docs and get a message end-to-end on a live chain, and the docs should tell them what that does and does not prove.

**P1-4 — deprecate or clearly quarantine anything that is not E2.** Legacy paths that are not forward-private must be either deprecated, clearly labeled as legacy in the product, or quarantined behind an explicit opt-in. The default path must be E2. Backward compatibility is a real requirement, but it must not be the default marketing story.

## 6. P2 — harden for other people (hosted path honest limits, DoS, one external review, fuzz the framing)

P2 is what lets other people use this without the author in the loop. It is also the point where the product stops being "the author's messenger" and starts being a thing.

**P2-1 — the hosted/Model-B path has honest limits written down and visible to the buyer.** A hosted mailbox sees traffic patterns, timing, and volume. That is the product. The honest limit is that the hosted path is not metadata-private, and the buyer should know that before they pay. Write it down in the product docs, not just in a design doc. Make the self-host path the privacy-default, and make the hosted path the convenience path with its honest tradeoffs stated.

**P2-2 — DoS resilience on the body-fetch and relay paths.** A hostile peer, relay, or mailbox can try to exhaust the receiver by feeding it bodies, frames, or requests. The receiver must bound its cost per body/frame/request and must not do unbounded work in response to an untrusted input. This is the difference between "works on a friendly network" and "works when someone dislikes you."

**P2-3 — one external review, or an honest explanation of why not.** The audit says this is the gating item for "other people should rely on this." Either there is an external review with named reviewers and a published record, or the product's marketing says "single-reviewer, unaudited" and the user can decide. The honest move is to say which one it is.

**P2-4 — fuzz the body-fetch and framing paths.** spore-peer's framing is the kind of code that has "rejects ~1.6% of valid bodies" bugs. Fuzz the framing and body-fetch paths with malformed frames, bad CIDs, oversized bodies, and duplicate requests, and fix whatever turns up. The audit point H4 was about framing; fuzzing is how you make sure the fix is real and stays real.

## 7. P3 — ecosystem bets (only after the above hold)

These are meaningful only if P0–P2 are done. They are not part of the floor.

- **DERO L1 mempool catch (1–2s receive).** Nice-to-have latency improvement. Only pursue once the E2 receive path is correct on every live chain; a fast wrong answer is worse than a slow right one.
- **Mailbox deploy + gas-sponsored delivery.** Makes the EVM path cheaper and more usable for non-technical recipients. Dependent on the mailbox actually burning correctly (P0-3) and sender auth landing (P1-1).
- **Cross-chain identity proof.** The honest version of this is hard and gated. Do not market "cross-chain messenger" until there is a real identity proof; the current honest story is "same-chain delivery, cross-chain is future work."

## 8. The gating item for sender authentication (T1)

This is the single biggest gap between the current release and "a messenger a stranger could rely on." The work is tracked separately (signed prekeys, envelope v2, HKDF identity binding, contact pinning). The gating question is simple: can the recipient verify, from the message alone and their own keys, that the sender's pinned key produced it? Until that is yes and in the default path, the product is notauthenticated, and every "from X" display is a courtesy label.

## 9. What "production-ready" means here

Production-ready does not mean "no bugs." It means:

- the defaults do not leak secrets or expose listeners (P0-1, P0-4),
- a hostile body-fetch cannot make the receiver treat garbage as mail (P0-2, P0-4),
- delivery actually burns and does not re-serve (P0-3),
- "messages rot" is true including disk artifacts (P0-5),
- the user can verify who sent a message (P1-1 = T1),
- the honest limits are documented for every live chain (P1-2),
- and the product does not claim compostability, forward secrecy, or metadata privacy where it does not have them.

Until those hold, the honest label is "research artifact with a working pipe," not "private messenger." That label is not an insult; it is the accurate shipping status, and the roadmap above is the ordered list of things that turn the label into "product."

## 10. Status (as of the audit)

- **P0 mostly complete.** Loopback defaults + token gating (C1/C2), relay SSRF allowlist + quotas (C3), Solana seq-keyed dedup (H2), Solana burn un-bricked with bank tests (H3), spore-peer status-frame protocol (H4), encrypted + TTL-trimmed message log (H5), footguns removed. All suites green (Go 20 pkgs, Rust 14 tests, Solana program 9 tests).
- **P1 sender authentication in progress (H1).** Signed prekeys + envelope v2 (0xE1), HKDF identity binding, strict receive, contact pinning. Threat model: `docs/SENDER_AUTH.md`.
- **Wire spec done:** `docs/WIRE_SPEC.md` + `docs/interop-vectors.json`, conformance tests in Go and Rust.
- **P0 items 4/10 still open.** XMR honest-or-off decision, DoS caps on channel box, `spore doctor`, metrics, Tor/proxy support, fuzz targets.

**Beta gate (the honest "production-ready for a private messenger" claim):** T1–T6 all hold; DERO + one public chain (Solana) deliver/burn correctly under a 48h adversarial testnet soak; spore-peer has fuzz-clean framing; an external reviewer can run a default deployment with only the docs and find no C-level finding. Until then, every artifact should say what this audit says: sound core, unshippable edges.
