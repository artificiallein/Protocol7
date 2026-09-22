# Security policy

Protocol 7 is an experimental, unaudited implementation, not a released secure messenger. Milestones 2–3 implement local identity storage and signed sealed envelopes, but contact verification, replay persistence and email transport are absent.

Please avoid publicly posting exploitable vulnerabilities or real secrets. Use GitHub's private vulnerability reporting feature for this repository if enabled, or contact the repository maintainers privately through a trusted channel. Do not send sensitive content through this application.

Security reviews should cover key authenticity, local key storage, parsing limits, authentication before display, replay, malicious transport behavior, dependency advisories, and metadata leakage. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
