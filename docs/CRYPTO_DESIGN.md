# Cryptographic design (P7/1 experimental)

## Status and dependency decision

Milestones 2 and 3 implement an **experimental, unaudited** P7/1 identity and encrypted-envelope path. It is not a production security claim.

The implementation pins [`sodium` 4.1.0+1](https://pub.dev/packages/sodium/versions/4.1.0%2B1), a Dart binding to libsodium 1.0.22, and uses only its high-level APIs. The binding supports Android, iOS, Linux, macOS, Windows and web and exposes protected native-memory keys on VM targets. Its package licensing is BSD-3-Clause/ISC. [`flutter_secure_storage` 11.2.0](https://pub.dev/packages/flutter_secure_storage/versions/11.2.0) (BSD-3-Clause) provides platform-backed at-rest storage. These exact direct versions are pinned so dependency changes require review.

`cryptography` was evaluated but not selected for P7/1. The libsodium sealed-box API avoids defining our own X25519 + KDF + AEAD construction. Dependencies and transitive advisories still require continuous review.

## Identity

Each identity has two independently generated libsodium key pairs:

- Ed25519 signing public/secret keys;
- Curve25519 `crypto_box` encryption public/secret keys.

`identityId` is 16 random bytes from `randombytes_buf`, encoded as unpadded base64url. It is independent of email. `cryptoVersion` is `1`; `createdAt` is UTC. The public identity contains both public keys and a fingerprint. A private `UserIdentity` redacts secret material from `toString()` and can overwrite its Dart byte arrays with `destroy()`; copies and runtime/OS behavior mean perfect zeroization cannot be promised.

The fingerprint is a 16-byte unkeyed libsodium BLAKE2b (`crypto_generichash`) output over:

1. UTF-8 `Protocol 7 fingerprint` followed by NUL;
2. crypto version as a four-byte unsigned big-endian integer;
3. 32-byte Ed25519 public key;
4. 32-byte Curve25519 public key.

It is rendered as eight groups of four uppercase hexadecimal characters. Fingerprints authenticate nothing until compared over an independent trusted channel. TOFU and contact verification remain Milestone 4.

## Private-key storage

`FlutterSecureKeyStorage` stores identity fields under an application-specific namespace using `flutter_secure_storage`. Signing and encryption secret keys are separate base64url values, not JSON and never part of the general database. A completion marker is deleted first and written last; partial writes are removed on failure. Load validates the fingerprint and proves that each private key matches its stored public key before returning the identity.

Platform protections differ: Keychain on Apple platforms; Keystore-backed RSA-OAEP/AES-GCM storage by default on Android; platform mechanisms on desktop; and HTTPS-only web storage. Browser memory cannot receive libsodium native-memory protections. Production platform manifests, backup policy, access-control choices, device-lock behavior and physical-device integration tests remain release gates.

## Signed sealed envelope

P7/1 performs the required `serialize → sign → encrypt` order:

1. The stable JSON message bytes are bounded to 64 KiB.
2. Ed25519 signs a domain-separated binary input that binds the protocol version, suite, message ID, sender identity ID and both public keys, recipient identity ID, and plaintext bytes. Variable strings and plaintext use four-byte unsigned big-endian length prefixes.
3. `crypto_box_seal` encrypts the plaintext to the recipient's Curve25519 public key. Libsodium generates and embeds the ephemeral public key and derives its nonce internally.
4. The outer envelope carries the sealed ciphertext and detached signature. On receive, authenticated sealed-box open occurs first, then signature verification, matching the required decryption flow.

Any changed clear envelope binding makes signature verification fail. `crypto_box_seal` rejects ciphertext modification. Unknown versions and suites, invalid key/ciphertext sizes and oversized data fail closed. The application must later compare the sender public identity against a pinned contact key before displaying a trusted state.

## Limits and residual risks

- A server sees the sender public identity, fingerprint, detached signature, message ID, suite, ciphertext length and all normal email metadata. It does not see message JSON.
- Static recipient-key compromise can decrypt previously recorded sealed boxes; P7/1 does not claim forward secrecy or post-compromise security.
- Replay persistence is not part of Milestone 3. A random, signed message ID is present for the later atomic replay index.
- Attachments, streaming, backup/restore and key rotation are not implemented.
- Web requires an explicitly bundled `sodium.js`, HTTPS secure storage and a separate security review. The current web build is only a compile check.
- The protocol has no independent audit or interoperability vectors yet and must not be marketed as production-ready.
