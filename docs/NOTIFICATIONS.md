# Spore arrival notifications

Spore notifications solve the day-to-day availability problem: the recipient does **not** need to keep a wallet, node, or CLI process running. A hosted mailbox can alert when ciphertext is accepted; a local receiver can alert after decryption. In both cases, the alert is only a wake-up signal.

Notifications are deliberately **not message transport** and do not decrypt anything on a server. Email/SMS/webhook providers receive only:

- `Spore: new private message`
- a short transaction identifier in webhook JSON
- no plaintext, ciphertext, keys, wallet credentials, or sender address

The recipient still opens a Spore client to fetch and decrypt the body locally. Hosted `mailbox host -notify-file` alerts when an authenticated ciphertext body is accepted; `recv-e2 -ntfy/-notify-email/-notify-sms` alerts after the local client decrypts it. These are two separate trust points.

## Webhook / ntfy

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
  -notify-sms +15551234567 \
  -notify-twilio-sid AC... \
  -notify-twilio-from +15557654321
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
