import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/application/contact_trust_service.dart';
import 'package:protocol7/domain/model/entities.dart';
import 'package:protocol7/domain/model/identity.dart';
import 'package:protocol7/domain/model/security_state.dart';
import 'package:protocol7/infrastructure/storage/in_memory_trust_store.dart';
import 'package:protocol7/protocol/key_verification_qr_codec.dart';
import 'package:protocol7/security/sodium_crypto_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late SodiumCryptoService cryptoService;
  late InMemoryTrustStore store;
  late ContactTrustService service;
  late UserIdentity bobA;
  late UserIdentity bobB;
  late UserIdentity mallory;

  setUpAll(() async {
    cryptoService = await SodiumCryptoService.create();
  });

  setUp(() async {
    store = InMemoryTrustStore();
    service = ContactTrustService(
      cryptoService: cryptoService,
      contactRepository: store,
      knownKeyRepository: store,
      securityEventRepository: store,
    );
    bobA = await cryptoService.generateIdentity();
    bobB = await cryptoService.generateIdentity();
    mallory = await cryptoService.generateIdentity();
  });

  tearDown(() {
    bobA.destroy();
    bobB.destroy();
    mallory.destroy();
  });

  test('first key is pinned as unverified and repeated key is accepted', () async {
    final contact = await service.addContact(
      displayName: 'Bob',
      transportAddress: 'bob@example.test',
    );
    expect(contact.id, isNot(contains('@')));

    final first = await service.observeIdentity(
      contactId: contact.id,
      announcedIdentity: bobA.publicIdentity,
      seenAt: DateTime.utc(2026, 1, 1),
    );
    final repeated = await service.observeIdentity(
      contactId: contact.id,
      announcedIdentity: bobA.publicIdentity,
      seenAt: DateTime.utc(2026, 1, 2),
    );

    expect(first.kind, TrustObservationKind.firstUse);
    expect(repeated.kind, TrustObservationKind.knownKey);
    expect(first.contact.currentFingerprint, bobA.fingerprint);
    expect(first.contact.verificationStatus, KeyVerificationStatus.unverified);
    final keys = await store.listKnownKeys(contact.id);
    expect(keys, hasLength(1));
    expect(keys.single.lastSeenAt, DateTime.utc(2026, 1, 2));
    final events = await store.listSecurityEvents(contactId: contact.id);
    expect(events, hasLength(1));
    expect(events.single.type, SecurityEventType.newKeyDetected);
  });

  test('a changed key is retained but never silently replaces the pin', () async {
    final contact = await _contactWithPinnedBob(service, bobA.publicIdentity);

    final result = await service.observeIdentity(
      contactId: contact.id,
      announcedIdentity: bobB.publicIdentity,
      seenAt: DateTime.utc(2026, 2, 1),
    );

    expect(result.kind, TrustObservationKind.keyChanged);
    expect(result.contact.currentFingerprint, bobA.fingerprint);
    expect(result.contact.identityId, bobA.identityId);
    expect(result.contact.verificationStatus, KeyVerificationStatus.changed);
    final keys = await store.listKnownKeys(contact.id);
    expect(keys, hasLength(2));
    final candidate = keys.singleWhere(
      (key) => key.publicIdentity.fingerprint == bobB.fingerprint,
    );
    expect(candidate.verificationStatus, KeyVerificationStatus.changed);
    expect(candidate.previousFingerprint, bobA.fingerprint);
    final events = await store.listSecurityEvents(contactId: contact.id);
    expect(events.last.type, SecurityEventType.keyChanged);
    expect(events.last.previousFingerprint, bobA.fingerprint);
    expect(events.last.currentFingerprint, bobB.fingerprint);
  });

  test('QR verification promotes an observed changed key and keeps history', () async {
    final contact = await _contactWithPinnedBob(service, bobA.publicIdentity);
    await service.verifyFromQr(
      contactId: contact.id,
      qrPayload: const KeyVerificationQrCodec().encode(bobA.publicIdentity),
    );
    await service.observeIdentity(
      contactId: contact.id,
      announcedIdentity: bobB.publicIdentity,
    );

    final verified = await service.verifyFromQr(
      contactId: contact.id,
      qrPayload: const KeyVerificationQrCodec().encode(bobB.publicIdentity),
      verifiedAt: DateTime.utc(2026, 3, 1),
    );

    expect(verified.currentFingerprint, bobB.fingerprint);
    expect(verified.identityId, bobB.identityId);
    expect(verified.verificationStatus, KeyVerificationStatus.verified);
    final oldKey = await store.findKnownKey(contact.id, bobA.fingerprint);
    final newKey = await store.findKnownKey(contact.id, bobB.fingerprint);
    expect(oldKey?.verificationStatus, KeyVerificationStatus.revoked);
    expect(oldKey?.revokedAt, DateTime.utc(2026, 3, 1));
    expect(newKey?.verificationStatus, KeyVerificationStatus.verified);
  });

  test('QR for an unrelated identity cannot verify a contact', () async {
    final contact = await _contactWithPinnedBob(service, bobA.publicIdentity);

    await expectLater(
      service.verifyFromQr(
        contactId: contact.id,
        qrPayload: const KeyVerificationQrCodec().encode(
          mallory.publicIdentity,
        ),
      ),
      throwsA(isA<VerificationMismatchException>()),
    );
  });

  test('tampered QR fingerprint is rejected before trust changes', () async {
    final contact = await service.addContact(
      displayName: 'Bob',
      transportAddress: 'bob@example.test',
    );
    final payload = jsonDecode(
      const KeyVerificationQrCodec().encode(bobA.publicIdentity),
    ) as Map<String, dynamic>;
    payload['fingerprint'] = mallory.fingerprint;

    await expectLater(
      service.verifyFromQr(
        contactId: contact.id,
        qrPayload: jsonEncode(payload),
      ),
      throwsA(isA<ContactTrustException>()),
    );
    expect((await store.findContact(contact.id))?.currentFingerprint, isNull);
  });

  test('QR parser rejects unexpected fields', () {
    final payload = jsonDecode(
      const KeyVerificationQrCodec().encode(bobA.publicIdentity),
    ) as Map<String, dynamic>;
    payload['unexpected'] = true;

    expect(
      () => const KeyVerificationQrCodec().decode(jsonEncode(payload)),
      throwsA(isA<QrPayloadException>()),
    );
  });
}

Future<Contact> _contactWithPinnedBob(
  ContactTrustService service,
  PublicIdentity identity,
) async {
  final contact = await service.addContact(
    displayName: 'Bob',
    transportAddress: 'bob@example.test',
  );
  await service.observeIdentity(
    contactId: contact.id,
    announcedIdentity: identity,
  );
  return contact;
}
