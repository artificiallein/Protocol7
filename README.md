# Protocol 7

Protocol 7 — end-to-end encrypted messenger using ordinary email infrastructure as an untrusted transport layer.

**Encrypt locally. Transport anywhere. Decrypt locally.**

> **Status: experimental Milestones 2–5.** Local identity storage, an unaudited signed/encrypted-envelope path, TOFU contact logic and a test-only fake transport are implemented. Durable contact storage, replay persistence, email transport and messenger UI do not exist. Do not use it for private communication.

## Intended behavior

Protocol 7 will encrypt messages locally before SMTP, receive encrypted envelopes via IMAP, and decrypt locally. Separate public-key identities will identify contacts; the email provider will only carry encrypted bytes and must not decide which keys are trusted. SMTP acceptance will not imply delivery or reading.

Protocol 7 will **not** hide the fact of communication, sender or recipient email addresses, message times, traffic size, frequency, or the user's IP address from their email provider. It is not an anonymity system. An active provider can block or delay messages and can substitute an unverified public key. Users must verify fingerprints out of band before treating a contact as authenticated.

## Implemented

- Separate Ed25519 signing and Curve25519 encryption identities.
- OS-backed private-key storage abstraction and adapter.
- P7/1 message serialization, signed libsodium sealed boxes and strict envelope parsing.
- Contact IDs independent of email, TOFU pinning, bounded QR verification payloads, key-change warnings and explicit verified-key promotion.
- A test-only `FakeTransport` that can route, delay, drop, duplicate and modify opaque encrypted envelopes.
- Negative tests for wrong recipients, tampering, unsupported versions and parser limits.
- No durable contact database, SMTP, IMAP, replay persistence, attachments, or messenger screens yet.

## Development

Install a stable [Flutter SDK](https://docs.flutter.dev/install) and run:

```sh
flutter pub get
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build web
```

The web target is a Phase 1 compile check, not a supported secure messaging deployment. Platform scaffolds for Android, iOS, and desktop will be generated and tested as those targets are implemented. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the next milestones.

Security reports: [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
