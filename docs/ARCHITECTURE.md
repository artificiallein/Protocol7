# Architecture

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

The domain ports, identity and contact-trust application services, secure-storage adapter, P7/1 protocol/QR codecs, libsodium crypto adapter and test-only fake transport are implemented. The current `lib/main.dart` remains a non-functional UI scaffold; `src/` and `tests/` are placeholders, with Dart code and tests in `lib/` and `test/`.

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

## Contact trust boundary

`ContactTrustService` accepts public identities only after recomputing their P7/1 fingerprint. It serializes trust mutations so concurrent first observations cannot silently race inside one service instance. The first key is unverified; a changed candidate cannot replace the active key without an explicit matching QR verification. `ContactRepository`, `KnownKeyRepository` and `SecurityEventRepository` keep storage choices outside application logic. The provided `InMemoryTrustStore` is for tests/development only; a durable transactional implementation is a release prerequisite.

## Fake transport boundary

`FakeTransportNetwork.testing()` creates addressable `MessageTransport` endpoints and carries cloned `EncryptedEnvelope` objects only. It can deterministically delay, drop, duplicate or mutate delivery for adversarial tests. Transport sender/recipient addresses are explicitly untrusted metadata: neither the fake transport nor a later email adapter may establish contact identity. The production composition root does not instantiate this network.

The dependency structure and threat boundary will be tested when interfaces and adapters are introduced. See [ROADMAP.md](ROADMAP.md).
