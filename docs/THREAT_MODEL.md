# Threat model (Phase 1 draft)

## Scope and assets

The future client handles message and attachment plaintext, attachment names and MIME types, identity private keys, contact trust decisions, and email credentials. The protected path is local plaintext → local encryption → SMTP/IMAP as untrusted byte transport → local authenticated decryption. This document states requirements; Phase 1 has no implementation and offers no protection.

## Adversaries and capabilities

- An active mail provider or network adversary can read headers and unencrypted traffic, observe timing and size, retain or correlate mail, replace a key announcement, modify or replay ciphertext, inject malformed messages, delete/delay messages, and deny service. TLS protects credentials on the wire but the provider remains untrusted.
- A malicious correspondent can send crafted payloads, claim arbitrary display names or transport addresses, and attempt resource exhaustion.
- A compromised or unlocked device, malicious OS, endpoint malware, screen capture, or stolen unlocked credential store can expose plaintext and keys. Endpoint compromise is outside the provider threat boundary.

## Required guarantees and conditions

Message text, file bytes, filenames, attachment MIME types, and sensitive message metadata must be encrypted before SMTP. Authenticated encryption and sender authentication must reject modification and forged messages **only after** the recipient has independently verified the sender's key. TOFU retains the first observed key as unverified; a malicious server can win that first observation. A changed key never silently replaces a pinned key. The receive path must reject unsupported versions, invalid signatures, malformed envelopes, and replay before showing a message as trusted; processed IDs must be persisted safely. Parser byte/count/depth limits and safe attachment extraction must prevent routine crash or path traversal. Retention, rollback resistance across device resets, and denial of service cannot be guaranteed by email transport.

## Trust boundaries

| Boundary | Required control |
| --- | --- |
| User input → local application | Validate limits, avoid logging plaintext, protect local storage |
| Client → SMTP provider | Encrypt and authenticate before transfer; TLS for credentials |
| Provider → client via IMAP | Treat all bytes and claimed keys as hostile; parse with bounds |
| Contact announcement → key store | Pin first key as unverified; warn on changes; verify out of band |
| Key store → message display | Require successful decryption, signature checks, replay checks and version validation |

## Exclusions and residual exposure

Email addresses, headers, correspondents, provider visible IP, mail routing, send time, traffic size and frequency remain visible. The provider can block, delay, reorder or erase traffic, and compromise unverified key discovery. Forward secrecy and post compromise security are **not** assumed in the initial design. Local database, OS backups, crash reports, notifications and screenshot handling require separate review before release.

## Acceptance tests for later phases

Cross-recipient decryption fails; ciphertext modification and wrong signatures fail closed; changed keys require explicit user action; repeated message IDs are rejected after restart; unknown versions and oversized or malformed inputs are rejected; SMTP capture contains no message text, filename, file bytes, or credentials; offline and dropped messages do not get false delivery status.
