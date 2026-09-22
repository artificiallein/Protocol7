# Protocol P7/1 (experimental)

`P7/1` uses integer `protocolVersion: 1`. Receivers reject every unknown version and crypto suite without guessing or fallback. This milestone implements local serialization and encrypted-envelope tests only; no email transport exists.

## Inner message JSON

UTF-8 JSON uses these stable fields in this order: `protocolVersion`, `messageId`, `conversationId`, `senderIdentityId`, `createdAt`, `messageType`, `body`, `attachments`, `replyTo`. Dates are UTC ISO-8601 strings. Message and conversation identifiers are bounded strings; generated message IDs are 16 random bytes encoded as unpadded base64url. The entire serialized message is limited to 64 KiB and the body to 32 Ki characters.

Attachment entries currently describe `id`, `filename`, `mimeType` and `size` inside the encrypted message. Attachment bytes and streaming are not implemented; callers must not claim attachment security yet.

## Signature input

The Ed25519 detached signature covers the following exact concatenation:

1. UTF-8 `Protocol 7 signed envelope` plus NUL;
2. protocol version as uint32 big-endian;
3. crypto suite, message ID, sender identity ID and recipient identity ID, each UTF-8 with a uint32 big-endian byte-length prefix;
4. sender Ed25519 public key and Curve25519 encryption public key (32 bytes each);
5. plaintext byte length as uint32 big-endian, followed by exact serialized plaintext bytes.

The selected suite name is `P7/1-libsodium-sealedbox-ed25519-blake2b`. Signature verification alone does not establish trust in a newly announced key.

## Encrypted envelope JSON

The bounded UTF-8 JSON envelope contains:

- `protocolVersion` and random `messageId`;
- `senderPublicIdentity`: `identityId`, base64url signing/encryption public keys, fingerprint, UTC `createdAt`, and `cryptoVersion`;
- `cryptoMetadata.suite`;
- base64url `ciphertext` from libsodium `crypto_box_seal`;
- base64url Ed25519 detached `signature`.

The envelope is limited to 256 KiB. Decoders validate types, string lengths, base64 sizes, version and suite before crypto processing. The sender identity is an untrusted assertion until checked against a pinned/verified contact key.

## Receive behavior

Parse bounded envelope → validate version/suite/key sizes → sealed-box open with the local recipient key → verify the signature and all bindings → deserialize bounded message → verify that inner message and outer routing identifiers agree in the future receive use case → atomically reject replay → store/display.

Milestone 3 implements through signature verification and deserialization. Contact pinning, the orchestration checks between inner and outer IDs, persistent replay rejection, email MIME (`application/x-protocol7`) and transport are later milestones.
