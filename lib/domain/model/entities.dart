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

  Contact copyWith({
    String? displayName,
    String? transportAddress,
    String? identityId,
    String? currentFingerprint,
    KeyVerificationStatus? verificationStatus,
  }) => Contact(
    id: id,
    displayName: displayName ?? this.displayName,
    transportAddress: transportAddress ?? this.transportAddress,
    identityId: identityId ?? this.identityId,
    currentFingerprint: currentFingerprint ?? this.currentFingerprint,
    verificationStatus: verificationStatus ?? this.verificationStatus,
  );
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

  KnownKey copyWith({
    DateTime? lastSeenAt,
    KeyVerificationStatus? verificationStatus,
    DateTime? revokedAt,
    bool clearRevokedAt = false,
    String? previousFingerprint,
  }) => KnownKey(
    contactId: contactId,
    publicIdentity: publicIdentity,
    firstSeenAt: firstSeenAt,
    lastSeenAt: lastSeenAt ?? this.lastSeenAt,
    verificationStatus: verificationStatus ?? this.verificationStatus,
    revokedAt: clearRevokedAt ? null : revokedAt ?? this.revokedAt,
    previousFingerprint: previousFingerprint ?? this.previousFingerprint,
  );
}

final class SecurityEvent {
  const SecurityEvent({
    required this.type,
    required this.createdAt,
    required this.contactId,
    this.previousFingerprint,
    this.currentFingerprint,
  });

  final SecurityEventType type;
  final DateTime createdAt;
  final String contactId;
  final String? previousFingerprint;
  final String? currentFingerprint;
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
