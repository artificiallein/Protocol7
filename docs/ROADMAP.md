# Roadmap

| Milestone | Scope | Exit check |
| --- | --- | --- |
| 1 | Repository, security/architecture docs, formatter, analyzer, tests and CI | Scaffold compiles; tests and CI pass |
| 2 | Identity and OS-backed private-key storage | Identity survives restart; no keys in ordinary storage |
| 3 | Approved crypto suite and message envelope | Alice/Bob round trip, wrong recipient and tamper fail |
| 4 | Contacts, TOFU, key changes and verification | Unknown/changed keys visibly unverified |
| 5 | FakeTransport | Crypto and UI logic independent of mail |
| 6 | First encrypted local message | Sign/encrypt/decrypt/verify/replay checks pass |
| 7 | TLS SMTP | Only ciphertext accepted by server |
| 8 | TLS IMAP and bounded parsing | Unknown/malformed mail rejected safely |
| 9 | Two-client email end-to-end | Alice sends, Bob decrypts locally |
| 10 | Bounded encrypted attachments | Bytes, filename and MIME type hidden |
| 11 | Messenger UI and onboarding | Verification and metadata exposure clear |
| 12 | Security hardening | Review, adversarial tests and dependency audit |

Phase 1 stops after the scaffold and drafts. Future milestones need review of concrete protocols and OS integration before any privacy claim. Group chats, calls, steganography and a custom ratchet are outside the initial MVP.
