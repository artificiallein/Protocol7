# Protocol P7/1 (draft; not interoperable yet)

`P7/1` is the proposed first protocol label, with integer `protocolVersion: 1`. This is a design draft and **does not specify an implementable cryptographic wire format**. A receiver must reject unknown versions without guessing or falling back.

## Proposed inner message

After authenticated decryption, a bounded message contains `protocolVersion`, a cryptographically random `messageId`, `conversationId`, `senderIdentityId`, `createdAt`, `messageType`, `body`, `attachments` and optional `replyTo`. Stable JSON field names are a candidate, but canonical serialization for signatures and byte limits must be finalized. Attachment metadata, including filenames and original MIME types, belongs inside encryption.

## Proposed outer envelope

Opaque email payload carries `protocolVersion`, random `messageId`, sender public identity announcement (untrusted until verified), `cryptoMetadata`, `ciphertext`, and authentication data/signature. The outer ID and version must match authenticated inner values; implementation must bind recipient and sender identities and reject alteration. Details of the actual encrypted envelope, canonical encoding, size caps, and suite identifier are pending review in [CRYPTO_DESIGN.md](CRYPTO_DESIGN.md).

## Email carrier

The intended Subject is exactly `Protocol 7 Message`; no user-supplied text or original filename appears in headers. A dedicated `application/x-protocol7` MIME part is proposed for the opaque envelope, with a transport-safe encoding. SMTP/IMAP implementations must require TLS for credentials, parse bounded payloads, and never trust mail headers as cryptographic identity. The exact MIME profile and decoder limits remain open. No P7/1 mail is sent by Phase 1.

## Security behavior

Invalid version, signature, authenticated decryption, recipient/sender binding or replay state must fail closed. First-seen keys remain unverified and key changes do not auto-replace trusted material. Mail deletion, ordering and delay are outside the authenticity guarantee. No compatibility promise applies until this draft is finalized and test vectors exist.
