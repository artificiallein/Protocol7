# Contributing

Phase 1 accepts architecture and tooling fixes. Please keep transport, cryptography, and UI implementation in separate changes after their designs are reviewed. Never commit real keys, passwords, tokens, or plaintext user data in fixtures or logs.

Run `dart format --output=none --set-exit-if-changed lib test`, `flutter analyze`, `flutter test`, and `flutter build web` before submitting changes. Explain security assumptions and tests when changing a trust boundary. See [SECURITY.md](SECURITY.md) for private security reports.
