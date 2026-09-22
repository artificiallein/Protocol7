# Architecture (Phase 1 draft)

## Layers

`presentation` → `application` → `domain` interfaces. Infrastructure implements the interfaces and is wired at the composition root. Protocol serialization and cryptography operate on byte arrays and identity types; transport carries already encrypted envelopes. The UI must not import mail, key storage, or cryptography packages. SMTP and IMAP adapters must not access plaintext, private keys, or serializers.

| Proposed area | Responsibility |
| --- | --- |
| `lib/presentation/` | Screens, security state display, user input |
| `lib/application/` | Send and receive use cases, queue and sync orchestration |
| `lib/domain/` | Identity, contact, conversation, message and trust types; port contracts |
| `lib/protocol/` | Versioned, bounded serialization and envelope validation |
| `lib/security/` | CryptoService and fingerprint policy behind ports |
| `lib/infrastructure/mail/` | Email carrier, independent SMTP and IMAP adapters |
| `lib/infrastructure/storage/` | OS-backed secret storage, local repositories and replay index |

These directories are planned interfaces, not implemented modules. The current `lib/main.dart` is only a non-functional scaffold; `src/` and `tests/` are placeholders, with Dart code and tests in `lib/` and `test/`.

## Outbound boundary

`SendMessage`: validate input and chosen recipient identity → serialize versioned plaintext → sign context and payload → encrypt for pinned recipient → validate opaque envelope for transport → enqueue opaque bytes → TLS SMTP. Persist `sentToServer` only after SMTP acceptance, never `delivered`. Credentials come from secure storage, not account records.

## Inbound boundary

TLS IMAP → bounded MIME extraction → strict envelope and version checks → decrypt locally → verify sender signature against pinned key → parse and validate inner message → atomic replay-index update and local persistence → display security state. Unknown or changed keys must be surfaced as unverified/security events; no mail header may silently establish identity. Exact signature binding and parser limits must be finalized before implementation.

## Invariants and seams

- `MessageTransport` deals only in opaque envelopes and can be replaced with `FakeTransport` without changing crypto or UI behavior.
- `CryptoService` has no SMTP/IMAP dependency; `SecureKeyStorage` holds private material only under OS protected storage.
- `MessageSerializer` and `ProtocolVersion` reject unknown formats; a `PayloadCarrier` maps envelope bytes to a neutral email MIME body.
- Database records may contain decrypted content and therefore need local protection; never place a private key or mail secret in the general database.
- Reconnection, queue retries and deduplication happen in the application layer; forged mail or a failed decrypt cannot reach normal conversation display.

The dependency structure and threat boundary will be tested when interfaces and adapters are introduced. See [ROADMAP.md](ROADMAP.md).
