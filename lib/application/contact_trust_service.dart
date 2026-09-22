import 'dart:async';

import '../core/protocol_constants.dart';
import '../domain/model/entities.dart';
import '../domain/model/identity.dart';
import '../domain/model/security_state.dart';
import '../domain/ports/contact_repository.dart';
import '../domain/ports/crypto_service.dart';
import '../protocol/key_verification_qr_codec.dart';

enum TrustObservationKind { firstUse, knownKey, keyChanged }

final class TrustObservation {
  const TrustObservation({required this.kind, required this.contact});

  final TrustObservationKind kind;
  final Contact contact;
}

final class ContactTrustService {
  ContactTrustService({
    required this.cryptoService,
    required this.contactRepository,
    required this.knownKeyRepository,
    required this.securityEventRepository,
    this.qrCodec = const KeyVerificationQrCodec(),
  });

  final CryptoService cryptoService;
  final ContactRepository contactRepository;
  final KnownKeyRepository knownKeyRepository;
  final SecurityEventRepository securityEventRepository;
  final KeyVerificationQrCodec qrCodec;

  Future<void> _tail = Future<void>.value();

  Future<Contact> addContact({
    required String displayName,
    required String transportAddress,
  }) => _exclusive(() async {
    final normalizedName = displayName.trim();
    final normalizedAddress = transportAddress.trim();
    if (normalizedName.isEmpty || normalizedName.length > 128) {
      throw const ContactTrustException('Invalid contact display name.');
    }
    if (normalizedAddress.isEmpty ||
        normalizedAddress.length >
            ProtocolConstants.maxTransportAddressCharacters) {
      throw const ContactTrustException('Invalid transport address.');
    }

    for (var attempt = 0; attempt < 4; attempt++) {
      final id = cryptoService.generateContactId();
      if (await contactRepository.findContact(id) == null) {
        final contact = Contact(
          id: id,
          displayName: normalizedName,
          transportAddress: normalizedAddress,
        );
        await contactRepository.saveContact(contact);
        return contact;
      }
    }
    throw const ContactTrustException('Could not allocate a contact ID.');
  });

  Future<TrustObservation> observeIdentity({
    required String contactId,
    required PublicIdentity announcedIdentity,
    DateTime? seenAt,
  }) => _exclusive(() async {
    await _validatePublicIdentity(announcedIdentity);
    final contact = await _requireContact(contactId);
    final now = (seenAt ?? DateTime.now()).toUtc();
    final activeFingerprint = contact.currentFingerprint;

    if (activeFingerprint == null) {
      final knownKey = KnownKey(
        contactId: contactId,
        publicIdentity: announcedIdentity,
        firstSeenAt: now,
        lastSeenAt: now,
        verificationStatus: KeyVerificationStatus.unverified,
      );
      final updated = contact.copyWith(
        identityId: announcedIdentity.identityId,
        currentFingerprint: announcedIdentity.fingerprint,
        verificationStatus: KeyVerificationStatus.unverified,
      );
      await knownKeyRepository.saveKnownKey(knownKey);
      await contactRepository.saveContact(updated);
      await _recordEvent(
        type: SecurityEventType.newKeyDetected,
        contactId: contactId,
        currentFingerprint: announcedIdentity.fingerprint,
        at: now,
      );
      return TrustObservation(
        kind: TrustObservationKind.firstUse,
        contact: updated,
      );
    }

    if (activeFingerprint == announcedIdentity.fingerprint) {
      final known = await knownKeyRepository.findKnownKey(
        contactId,
        activeFingerprint,
      );
      if (known == null ||
          !_sameIdentity(known.publicIdentity, announcedIdentity)) {
        throw const ContactTrustException(
          'Pinned fingerprint does not match stored public key material.',
        );
      }
      await knownKeyRepository.saveKnownKey(known.copyWith(lastSeenAt: now));
      return TrustObservation(
        kind: TrustObservationKind.knownKey,
        contact: contact,
      );
    }

    final existingCandidate = await knownKeyRepository.findKnownKey(
      contactId,
      announcedIdentity.fingerprint,
    );
    if (existingCandidate != null &&
        !_sameIdentity(existingCandidate.publicIdentity, announcedIdentity)) {
      throw const ContactTrustException(
        'Known fingerprint does not match public key material.',
      );
    }
    final candidate = existingCandidate?.copyWith(
          lastSeenAt: now,
          verificationStatus: KeyVerificationStatus.changed,
          clearRevokedAt: true,
          previousFingerprint: activeFingerprint,
        ) ??
        KnownKey(
          contactId: contactId,
          publicIdentity: announcedIdentity,
          firstSeenAt: now,
          lastSeenAt: now,
          verificationStatus: KeyVerificationStatus.changed,
          previousFingerprint: activeFingerprint,
        );
    final changedContact = contact.copyWith(
      verificationStatus: KeyVerificationStatus.changed,
    );
    await knownKeyRepository.saveKnownKey(candidate);
    await contactRepository.saveContact(changedContact);
    if (existingCandidate == null) {
      await _recordEvent(
        type: SecurityEventType.keyChanged,
        contactId: contactId,
        previousFingerprint: activeFingerprint,
        currentFingerprint: announcedIdentity.fingerprint,
        at: now,
      );
    }
    return TrustObservation(
      kind: TrustObservationKind.keyChanged,
      contact: changedContact,
    );
  });

  Future<Contact> verifyFromQr({
    required String contactId,
    required String qrPayload,
    DateTime? verifiedAt,
  }) => _exclusive(() async {
    final identity = qrCodec.decode(qrPayload);
    await _validatePublicIdentity(identity);
    final contact = await _requireContact(contactId);
    final now = (verifiedAt ?? DateTime.now()).toUtc();
    final activeFingerprint = contact.currentFingerprint;
    final scanned = await knownKeyRepository.findKnownKey(
      contactId,
      identity.fingerprint,
    );

    if (activeFingerprint == null) {
      final verifiedKey = KnownKey(
        contactId: contactId,
        publicIdentity: identity,
        firstSeenAt: now,
        lastSeenAt: now,
        verificationStatus: KeyVerificationStatus.verified,
      );
      final verifiedContact = contact.copyWith(
        identityId: identity.identityId,
        currentFingerprint: identity.fingerprint,
        verificationStatus: KeyVerificationStatus.verified,
      );
      await knownKeyRepository.saveKnownKey(verifiedKey);
      await contactRepository.saveContact(verifiedContact);
      await _recordVerification(contactId, null, identity.fingerprint, now);
      return verifiedContact;
    }

    if (identity.fingerprint == activeFingerprint) {
      if (scanned == null || !_sameIdentity(scanned.publicIdentity, identity)) {
        throw const VerificationMismatchException();
      }
      if (scanned.verificationStatus == KeyVerificationStatus.verified &&
          contact.verificationStatus == KeyVerificationStatus.verified) {
        return contact;
      }
      final verifiedContact = contact.copyWith(
        verificationStatus: KeyVerificationStatus.verified,
      );
      await knownKeyRepository.saveKnownKey(
        scanned.copyWith(
          lastSeenAt: now,
          verificationStatus: KeyVerificationStatus.verified,
        ),
      );
      await contactRepository.saveContact(verifiedContact);
      await _recordVerification(contactId, null, activeFingerprint, now);
      return verifiedContact;
    }

    if (scanned == null ||
        scanned.verificationStatus != KeyVerificationStatus.changed ||
        !_sameIdentity(scanned.publicIdentity, identity)) {
      throw const VerificationMismatchException();
    }
    final oldKey = await knownKeyRepository.findKnownKey(
      contactId,
      activeFingerprint,
    );
    if (oldKey == null) {
      throw const ContactTrustException('Pinned key record is missing.');
    }

    await knownKeyRepository.saveKnownKey(
      oldKey.copyWith(
        lastSeenAt: now,
        verificationStatus: KeyVerificationStatus.revoked,
        revokedAt: now,
      ),
    );
    await knownKeyRepository.saveKnownKey(
      scanned.copyWith(
        lastSeenAt: now,
        verificationStatus: KeyVerificationStatus.verified,
        clearRevokedAt: true,
      ),
    );
    final promoted = contact.copyWith(
      identityId: identity.identityId,
      currentFingerprint: identity.fingerprint,
      verificationStatus: KeyVerificationStatus.verified,
    );
    await contactRepository.saveContact(promoted);
    await _recordVerification(
      contactId,
      activeFingerprint,
      identity.fingerprint,
      now,
    );
    return promoted;
  });

  Future<Contact> _requireContact(String contactId) async {
    final contact = await contactRepository.findContact(contactId);
    if (contact == null) throw const ContactNotFoundException();
    return contact;
  }

  Future<void> _validatePublicIdentity(PublicIdentity identity) async {
    if (identity.cryptoVersion != ProtocolConstants.version) {
      throw const ContactTrustException('Unsupported identity version.');
    }
    final expected = await cryptoService.calculateFingerprint(
      signingPublicKey: identity.signingPublicKey,
      encryptionPublicKey: identity.encryptionPublicKey,
      cryptoVersion: identity.cryptoVersion,
    );
    if (expected != identity.fingerprint) {
      throw const ContactTrustException('Public identity fingerprint mismatch.');
    }
  }

  Future<void> _recordVerification(
    String contactId,
    String? previousFingerprint,
    String currentFingerprint,
    DateTime at,
  ) => _recordEvent(
    type: SecurityEventType.keyVerified,
    contactId: contactId,
    previousFingerprint: previousFingerprint,
    currentFingerprint: currentFingerprint,
    at: at,
  );

  Future<void> _recordEvent({
    required SecurityEventType type,
    required String contactId,
    required DateTime at,
    String? previousFingerprint,
    String? currentFingerprint,
  }) => securityEventRepository.addSecurityEvent(
    SecurityEvent(
      type: type,
      createdAt: at,
      contactId: contactId,
      previousFingerprint: previousFingerprint,
      currentFingerprint: currentFingerprint,
    ),
  );

  Future<T> _exclusive<T>(Future<T> Function() operation) async {
    final previous = _tail;
    final gate = Completer<void>();
    _tail = gate.future;
    await previous;
    try {
      return await operation();
    } finally {
      gate.complete();
    }
  }

  static bool _sameIdentity(PublicIdentity left, PublicIdentity right) =>
      left.identityId == right.identityId &&
      left.cryptoVersion == right.cryptoVersion &&
      _sameBytes(left.signingPublicKey, right.signingPublicKey) &&
      _sameBytes(left.encryptionPublicKey, right.encryptionPublicKey);

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }
}

class ContactTrustException implements Exception {
  const ContactTrustException(this.message);
  final String message;

  @override
  String toString() => 'ContactTrustException: $message';
}

final class ContactNotFoundException extends ContactTrustException {
  const ContactNotFoundException() : super('Contact not found.');
}

final class VerificationMismatchException extends ContactTrustException {
  const VerificationMismatchException()
    : super('QR identity does not match a pinned or pending key.');
}
