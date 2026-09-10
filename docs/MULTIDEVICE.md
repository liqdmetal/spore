# Multi-device (Tier-3)

One identity, N devices. Your `identity.key` and `spk.key` are the account;
each device additionally carries a **device id** so the two can tell each
other apart.

```
spore e2-device id       -state-dir D            # this device's id
spore e2-device status   -state-dir D            # sessions, last writer, sends
spore e2-device export   -state-dir D -state-key F -out bundle
spore e2-device import   -state-dir D -state-key F -in bundle
```

## What syncs

Every ratchet session in the state directory: the double-ratchet state, the
skipped-key sets, and the session's position in its receiving chain. A device
that imports a bundle can decrypt and continue the same conversations.

The bundle is encrypted with a key derived from the account's **state key**,
so it can travel over any channel — email, chat, a USB stick — and only a
device that already holds that state key can open it. Import refuses a bundle
sealed under a different state key, and refuses a tampered one.

## The hazard: key reuse, not transport

A double ratchet is a **linear chain with a send counter**. If two devices send
on the same session from the same counter, they derive the *same message key*.
That is not a privacy leak — it is a break: two ciphertexts under one keystream
leak the XOR of both plaintexts, and any authentication tag becomes forgeable.

So the design is **sync before you send**:

- Each session's ledger records its **last writer** and how many messages
  **this device** has sent since it last synced.
- A continuation is **refused** when the session state was last written by
  another device while this one still has unsent history.
- **Import flags a collision** when the importing device had also sent since
  its last sync — both devices advanced one chain, so the indices may already
  have met. It prints the session id and the other device's id.
- A flagged session **refuses to send** until you start a new one with that
  contact.

Single-device use is unaffected: this device is always the last writer, so the
guard never fires. There is no false alarm by construction.

## Honest limits

**This detects collisions; it cannot prevent them.** Two devices that both send
*without ever syncing* will reuse keys, and nothing purely local can see that
happening — the ledger only learns about the other device when a bundle is
imported. True prevention needs per-device send chains (each device derives its
own sending chain from the session root), which is a wire change and a new
session version, not a local guard. Until then the rule is:

> Sync before you send from a second device. If a collision is reported, start
> a new session with that contact — do not keep sending on the flagged one.

**Rollback protection is local.** The state store's append-only ledger detects
a restored older snapshot, but an attacker with unrestricted write access to the
whole state directory can defeat it. Closing that needs an external anchor
(hardware counter, remote checkpoint) which this does not have.

**The ledger starts empty.** Sends made before this feature existed are not
counted, so a device upgrading mid-conversation has no send history for its
existing sessions. It will be flagged clean on first import. Sync once
deliberately after upgrading.

## Recovery

If a session is flagged and you must keep talking to that contact, start a
fresh session — `spore msg send-e2` opens a new one — rather than continuing the
flagged session. The old session's state will be reaped by the normal TTL.
