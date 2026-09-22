# Cryptographic design (draft; no implementation)

## Decision status

**Unapproved for deployment.** Use established, reviewed library primitives and stable standard constructions; no custom algorithms, ratchets, key exchanges or random generators. Final library/version, cryptographic suite, domain separation, wire format, test vectors and independent security review are required before a CryptoService is implemented.

Flutter/Dart candidates for evaluation include [`cryptography`](https://pub.dev/packages/cryptography) with its platform integration and [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage) for OS backed secrets. Candidates must be checked for current maintenance and releases, advisory history, license, mobile and desktop behavior, tests, interoperability, side channel properties, secure random behavior and documentation. A mail library (candidate: [`enough_mail`](https://pub.dev/packages/enough_mail)) is a separate transport decision and must not perform content cryptography. No candidate is a dependency in Phase 1.

## Proposed identity and trust

A random, stable `identityId` identifies the cryptographic identity independently of the email transport address. Proposed identity includes separate signing and recipient encryption public keys, corresponding private keys, a creation time and a crypto suite version. Private material is created on device and stored only in OS-backed secure storage, never in SQLite, preferences, logs, Git or mail. A human fingerprint must bind a canonical encoding of both public keys, identity ID and version with a documented cryptographic hash and explicit domain separation. Never treat an email address or a self-asserted key announcement as authentication.

TOFU stores the first key as **unverified**. Changed keys produce `KEY_CHANGED`, retain key history and stop automatic trust. QR and manually compared fingerprints are planned out-of-band verification. A compromised initial announcement remains a residual risk until verification.

## Candidate message flow

Sender serializes and signs the inner message plus context (version, sender identity, recipient identity, message ID and intended protocol domain), then encrypts the signed object using an authenticated recipient encryption scheme. Recipient checks outer bounds and version, decrypts, verifies the signature against the pinned sender key, validates bindings and inner fields, and atomically records replay state before display. Exact construction, nonce strategy, AEAD associated data, signing order, algorithms and error behavior must be reviewed and specified before code. The outer message ID needed for replay is an opaque random value and must be bound to the authenticated inner payload.

For attachments, encrypt bytes and original filename/MIME/size as a bounded, authenticated payload before SMTP. Streaming and memory limits need an explicit design. Do not infer forward secrecy or post compromise recovery from static identity keys. Do not implement a homemade ratchet.

## Review gate

Before milestone 3: choose exact maintained library versions and licenses; inspect release/advisory history and platform implementation; specify key formats and encrypted storage semantics; publish interoperable vectors and negative tests; review authenticated recipient/sender binding, replay persistence, downgrade resistance, parsing limits, and secret zeroization limits in Dart. Only then implement or claim encryption.
