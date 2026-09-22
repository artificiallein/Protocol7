# Roadmap

| Milestone | Scope | Exit check |
| --- | --- | --- |
| 1 | Repository, security/architecture docs, formatter, analyzer, tests and CI | Scaffold compiles; tests and CI pass |
| 2 ✅ | Identity and OS-backed private-key storage | Implemented and tested; physical-device checks remain |
| 3 ✅ | Experimental crypto suite and message envelope | Alice/Bob round trip, wrong recipient and tamper fail in CI |
| 4 | Contacts, TOFU, key changes and verification | Unknown/changed keys visibly unverified |
| 5 | FakeTransport | Crypto and UI logic independent of mail |
| 6 | First encrypted local message | Sign/encrypt/decrypt/verify/replay checks pass |
| 7 | TLS SMTP | Only ciphertext accepted by server |
| 8 | TLS IMAP and bounded parsing | Unknown/malformed mail rejected safely |
| 9 | Two-client email end-to-end | Alice sends, Bob decrypts locally |
| 10 | Bounded encrypted attachments | Bytes, filename and MIME type hidden |
| 11 | Messenger UI and onboarding | Verification and metadata exposure clear |
| 12 | Security hardening | Review, adversarial tests and dependency audit |

Milestones 2 and 3 are implemented as an unaudited local cryptographic path. Milestone 4 is next. Future milestones still require independent review and OS integration testing before any production privacy claim. Group chats, calls, steganography and a custom ratchet are outside the initial MVP.
