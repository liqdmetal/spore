# Private ntfy for the Spore hosted beta

The hosted beta runs its own private ntfy server at `https://notify.example.net` so arrival alerts do not go through the public `ntfy.sh` service. Topics are unlisted and the publisher authenticates with a bearer token, so a stranger cannot subscribe or poll an alert topic.

This doc describes the **actual** deployment on Hetzner and the **actual** Spore notification paths. It does not invent flags. If a flag or env var is not in the code, it is not supported.

## Two notification paths, both metadata-only

### A) Hosted notification — the mailbox host raises the alert

The operator puts each user's alert route in a non-secret JSON map used by `mailbox host -notify-file`:

```json
{
  "alice": {
    "webhook": "https://notify.example.net/spore-alice"
  },
  "bob": {
    "webhook": "https://notify.example.net/spore-bob"
  }
}
```

The service is started with `-privacy` and a bearer token in its environment:

```ini
# /etc/systemd/system/spore-mailbox.service  (illustrative; redact secrets)
[Service]
EnvironmentFile=/etc/spore/wallet-rpc.env
ExecStart=/usr/local/bin/spore-linux mailbox host \
    -users /srv/spore/users \
    -listen 127.0.0.1:18443 \
    -tokens /srv/spore/tokens.json \
    -notify-file /srv/spore/notify.json \
    -rpc http://127.0.0.1:20209/json_rpc \
    -rpc-login ${RPC_LOGIN} \
    -interval 5s \
    -privacy
User=spore
Group=spore
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/srv/spore
```

```ini
# /etc/systemd/system/spore-mailbox.service.d/ntfy.conf
[Service]
EnvironmentFile=/etc/spore/ntfy-publisher.env
```

```bash
# /etc/spore/ntfy-publisher.env  (redact before sharing)
SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]
```

When an authenticated ciphertext body is PUT to `/u/alice/put/<cid>`, the mailbox host enqueues a durable metadata-only event to an at-least-once outbox, and the outbox POSTs it to the user's ntfy topic with `Authorization: Bearer [REDACTED]`. The ntfy payload is something like:

```json
{"event":"message.available","txid":"...","subject":"Spore private message pending","received_at":"..."}
```

No ciphertext, no plaintext, no keys, no wallet credentials.

### B) Client-side notification — your `recv-e2` raises the alert

If you run `recv-e2` on a phone, desktop, or small home service, you can have **your** process POST the wake-up after local decryption:

```bash
spore msg recv-e2 \
  -identity ~/.spore/identity.json \
  -spk ~/.spore/spk.json \
  -store https://mailbox.example.net/u/<name> \
  -store-token [REDACTED] \
  -state-dir ~/.spore/state \
  -state-key ~/.spore/state.key \
  -auto-ack \
  -maildb ~/.spore/mail.json \
  -out-dir ~/inbox \
  -ntfy https://notify.example.net/<secret-topic>
# SPORE_NOTIFY_WEBHOOK_TOKEN=[REDACTED]  in the process environment, not on the command line
```

`-ntfy` is a generic POST webhook alias. The ntfy topic URL and bearer token are credentials. Keep them unguessable and use HTTPS.

## ntfy server (operator self-host option)

An operator who does not want to use any public service can run their own. The Hetzner deployment uses a minimal private config with auth-default-access set to deny-all:

```yaml
# /etc/ntfy/server.yml — illustrative; redact before deploying
base-url: "https://notify.example.net"
listen-http: "127.0.0.1:2586"
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"
behind-proxy: true
web-root: "disable"
cache-duration: "24h"
```

```ini
# /etc/systemd/system/ntfy.service  (illustrative; redact secrets)
[Unit]
Description=Private ntfy notification server
After=network-online.target
Wants=network-online.target

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

[Install]
WantedBy=multi-user.target
```

Do **not** expose an unauthenticated ntfy topic to the open internet for Spore alerts — anyone could subscribe and learn that a message arrived. ntfy auth credentials, webhook bearer tokens, SMTP passwords, and Twilio tokens are loaded from environment variables or a secrets file, never embedded in the notification payload or in command-line arguments.

## What is live right now

- `https://notify.example.net` serves the private ntfy instance.
- `https://mailbox.example.net` serves the hosted mailbox.
- `ntfy serve` runs under systemd as the `ntfy` user with a deny-all auth policy.
- `spore mailbox host` runs under systemd as the `spore` user with `-privacy`, a shared wallet RPC login from an env file, and a `-notify-file` map pointing each user at a private ntfy topic.
- The publisher bearer token lives in `/etc/spore/ntfy-publisher.env` and is never in the repo.

## Security rules

- Never put SMTP passwords, Twilio tokens, webhook bearer tokens, wallet RPC credentials, or plaintext in argv.
- Keep ntfy topics unguessable and use HTTPS.
- Email/SMS alerts are metadata leakage: timing and the fact that a message arrived are visible to the provider.
- The notification bridge does not make arbitrary email addresses Spore identities. A recipient still needs one-time identity/prekey onboarding.
- Provider failure is logged and never blocks chain scanning or local decryption.
