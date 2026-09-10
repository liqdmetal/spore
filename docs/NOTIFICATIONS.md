# Spore arrival notifications

Spore notifications solve the day-to-day availability problem: the recipient does **not** need to keep a wallet, node, or CLI process running. A hosted mailbox can alert when ciphertext is accepted; a local receiver can alert after decryption. In both cases, the alert is only a wake-up signal.

Notifications are deliberately **not message transport** and do not decrypt anything on a server. Email/SMS/webhook providers receive only:

- `Spore: new private message`
- a short transaction identifier in webhook JSON
- no plaintext, ciphertext, keys, wallet credentials, or sender address

The recipient still opens a Spore client to fetch and decrypt the body locally. Hosted `mailbox host -notify-file` alerts when an authenticated ciphertext body is accepted; `recv-e2 -ntfy/-notify-email/-notify-sms` alerts after the local client decrypts it. These are two separate trust points.

## Hosted beta (private ntfy server)

The hosted beta runs its own private ntfy server at `https://notify.mycoid.net`. It is **not** the public `ntfy.sh` service — topics are unlisted and the publisher authenticates with a bearer token, so a stranger cannot subscribe or poll your alert topic.

There are **two separate notification paths**, and both are metadata-only:

### A) Hosted notification (the mailbox host raises the alert)

The operator provisions each user's notification route in a non-secret JSON map, e.g. `/srv/spore/notify.json`:

```json
{
  "alice": {
    "webhook": "https://notify.mycoid.net/spore-alice"
  }
}
```

The live mailbox service on Hetzner is started with:

```bash
spore mailbox host \
    -users /srv/spore/users \
    -listen 127.0.0.1:18443 \
    -tokens /srv/spore/tokens.json \
    -notify-file /srv/spore/notify.json \
    -rpc http://127.0.0.1:20209/json_rpc \
    -rpc-login USER:PASSWORD \
    -privacy
```

The publisher authenticates to ntfy with a bearer token loaded from the service environment, **never from argv or the JSON file**:

```bash
# /etc/spore/ntfy-publisher.env  (redact before sharing)
SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]
```

When an authenticated ciphertext body is PUT to `/u/alice/put/<cid>`, the mailbox host enqueues a durable metadata-only event (`txid`, `subject`, `received_at`) to an at-least-once outbox, and the outbox POSTs it to `https://notify.mycoid.net/spore-alice` with `Authorization: Bearer [REDACTED]`. The ntfy message body is something like:

- topic: `spore-alice`
- payload: `{"event":"message.available","txid":"...","subject":"Spore private message pending","received_at":"..."}`

No ciphertext, no plaintext, no keys, no wallet credentials.

### B) Client-side notification (your `recv-e2` raises the alert)

If you run `recv-e2` on a phone, desktop, or small home service and want the **client** to post the wake-up instead of the hosted mailbox, use the `-ntfy` webhook alias:

```bash
spore msg recv-e2 \
  -identity ~/.spore/identity.json \
  -spk ~/.spore/spk.json \
  -store https://spore.mycoid.net/u/<name> \
  -store-token [REDACTED] \
  -state-dir ~/.spore/state \
  -state-key ~/.spore/state.key \
  -auto-ack \
  -maildb ~/.spore/mail.json \
  -out-dir ~/inbox \
  -ntfy https://notify.mycoid.net/<secret-topic>
# SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]  in the process environment, not on the command line
```

`recv-e2` posts the alert **after** local decryption. The ntfy topic URL and bearer token are credentials; keep them unguessable and use HTTPS.

### Self-hosted ntfy (operator option)

An operator who does not want to use the public service can run their own. The Hetzner deployment uses a minimal private config plus systemd:

```bash
# /etc/ntfy/server.yml — illustrative; redact secrets before deploying
base-url: "https://notify.mycoid.net"
listen-http: "127.0.0.1:2586"
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"
behind-proxy: true
web-root: "disable"
cache-duration: "24h"
```

```ini
# /etc/systemd/system/ntfy.service  (illustrative)
[Service]
ExecStart=/usr/local/bin/ntfy serve --config /etc/ntfy/server.yml
User=ntfy
Group=ntfy
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/ntfy /var/cache/ntfy
Restart=on-failure
RestartSec=3
```

Do **not** expose an unauthenticated ntfy topic to the open internet for Spore alerts — anyone could subscribe and learn that a message arrived. ntfy auth credentials, webhook bearer tokens, SMTP passwords, and Twilio tokens are loaded from environment variables or a secrets file, never embedded in the notification payload or in command-line arguments.

## Generic webhook / ntfy (any provider)

The existing `-ntfy` flag is a generic POST webhook alias. Use a secret topic URL or your own HTTPS endpoint:

```text
spore msg recv-e2 ... \
  -ntfy https://ntfy.example/secret-topic
```

An optional bearer token is read from `SPORE_NOTIFY_WEBHOOK_TOKEN`; it is never placed in argv:

```text
set SPORE_NOTIFY_WEBHOOK_TOKEN=[secret]
```

The webhook receives metadata only. Treat the topic URL and bearer token as credentials.

## SMTP email

```text
spore msg recv-e2 ... \
  -notify-email you@example.com \
  -notify-smtp-host smtp.example.com \
  -notify-smtp-port 587 \
  -notify-smtp-from spore@example.com \
  -notify-smtp-user spore@example.com
```

Set the password in the process environment, not the command line:

```text
set SPORE_NOTIFY_SMTP_PASSWORD=[secret]
```

The SMTP implementation uses STARTTLS when the port is 587. Do not use plaintext SMTP on an untrusted network.

## Twilio SMS

```text
spore msg recv-e2 ... \
  -notify-sms +155****4567 \
  -notify-twilio-sid AC... \
  -notify-twilio-from +155****4321
```

Set the auth token in the process environment:

```text
set SPORE_NOTIFY_TWILIO_AUTH_TOKEN=[secret]
```

SMS content is intentionally generic because SMS providers and phone carriers are not private channels.

## Operational model

- Run `recv-e2` on a phone, desktop, or small home service that owns the decryption keys.
- Point email/SMS/webhook notifications at that receiver.
- The notification provider only wakes the person; it does not deliver the private body.
- If the receiver is offline, the E2 body remains available at the mailbox until its configured TTL.
- Provider failure is logged and never blocks chain scanning or local decryption.

## Security rules

- Never put SMTP passwords, Twilio tokens, webhook bearer tokens, wallet RPC credentials, or plaintext in argv.
- Use a dedicated notification address/number when operational separation matters.
- Keep webhook topics unguessable and use HTTPS.
- Email/SMS alerts are metadata leakage: timing and the fact that a message arrived are visible to the provider.
- The notification bridge does not make arbitrary email addresses Spore identities. A recipient still needs one-time identity/prekey onboarding.
