import 'identity.dart';
import 'security_state.dart';

final class Contact {
  const Contact({
    required this.id,
    required this.displayName,
    required this.transportAddress,
    this.identityId,
    this.currentFingerprint,
    this.verificationStatus = KeyVerificationStatus.unverified,
  });

  final String id;
  final String displayName;
  final String transportAddress;
  final String? identityId;
  final String? currentFingerprint;
  final KeyVerificationStatus verificationStatus;
}

final class Conversation {
  const Conversation({required this.id, required this.contactId});
  final String id;
  final String contactId;
}

final class KnownKey {
  const KnownKey({
    required this.contactId,
    required this.publicIdentity,
    required this.firstSeenAt,
    required this.lastSeenAt,
    required this.verificationStatus,
    this.revokedAt,
    this.previousFingerprint,
  });

  final String contactId;
  final PublicIdentity publicIdentity;
  final DateTime firstSeenAt;
  final DateTime lastSeenAt;
  final KeyVerificationStatus verificationStatus;
  final DateTime? revokedAt;
  final String? previousFingerprint;
}

final class SecurityEvent {
  const SecurityEvent({
    required this.type,
    required this.createdAt,
    required this.details,
  });

  final SecurityEventType type;
  final DateTime createdAt;
  final String details;
}

enum TransportSecurity { implicitTls, startTls }

final class TransportAccount {
  const TransportAccount({
    required this.email,
    required this.smtpHost,
    required this.smtpPort,
    required this.smtpSecurity,
    required this.imapHost,
    required this.imapPort,
    required this.imapSecurity,
    required this.username,
  });

  final String email;
  final String smtpHost;
  final int smtpPort;
  final TransportSecurity smtpSecurity;
  final String imapHost;
  final int imapPort;
  final TransportSecurity imapSecurity;
  final String username;
}
