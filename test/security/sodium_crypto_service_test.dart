import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/core/protocol_constants.dart';
import 'package:protocol7/domain/model/encrypted_envelope.dart';
import 'package:protocol7/domain/model/identity.dart';
import 'package:protocol7/domain/model/secure_message.dart';
import 'package:protocol7/protocol/encrypted_envelope_codec.dart';
import 'package:protocol7/protocol/json_message_serializer.dart';
import 'package:protocol7/security/sodium_crypto_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late SodiumCryptoService cryptoService;
  late UserIdentity alice;
  late UserIdentity bob;
  late UserIdentity mallory;

  setUpAll(() async {
    cryptoService = await SodiumCryptoService.create();
  });

  setUp(() async {
    alice = await cryptoService.generateIdentity();
    bob = await cryptoService.generateIdentity();
    mallory = await cryptoService.generateIdentity();
  });

  tearDown(() {
    alice.destroy();
    bob.destroy();
    mallory.destroy();
  });

  test('Alice encrypts and signs; Bob decrypts and verifies', () async {
    const serializer = JsonMessageSerializer();
    const envelopeCodec = EncryptedEnvelopeCodec();
    final messageId = cryptoService.generateMessageId();
    final message = SecureMessage(
      protocolVersion: ProtocolConstants.version,
      messageId: messageId,
      conversationId: 'alice-bob',
      senderIdentityId: alice.identityId,
      createdAt: DateTime.now().toUtc(),
      messageType: MessageType.text,
      body: 'Привет.',
    );
    final plaintext = serializer.serialize(message);

    final envelope = await cryptoService.encryptForRecipient(
      plaintext: plaintext,
      messageId: messageId,
      sender: alice,
      recipient: bob.publicIdentity,
    );
    final wireBytes = envelopeCodec.encode(envelope);
    final decodedEnvelope = envelopeCodec.decode(wireBytes);
    final decrypted = await cryptoService.decrypt(
      envelope: decodedEnvelope,
      recipient: bob,
    );
    final decodedMessage = serializer.deserialize(decrypted);

    expect(decodedMessage.body, 'Привет.');
    expect(decodedMessage.senderIdentityId, alice.identityId);
    expect(utf8.decode(wireBytes), isNot(contains('Привет.')));
  });

  test('wrong recipient cannot decrypt', () async {
    final envelope = await _envelopeFor(
      cryptoService,
      sender: alice,
      recipient: bob,
    );

    await expectLater(
      cryptoService.decrypt(envelope: envelope, recipient: mallory),
      throwsA(isA<DecryptionException>()),
    );
  });

  test('ciphertext tampering is detected', () async {
    final envelope = await _envelopeFor(
      cryptoService,
      sender: alice,
      recipient: bob,
    );
    final tamperedCiphertext = envelope.ciphertext;
    tamperedCiphertext[tamperedCiphertext.length - 1] ^= 1;
    final tampered = _copyEnvelope(
      envelope,
      ciphertext: tamperedCiphertext,
    );

    await expectLater(
      cryptoService.decrypt(envelope: tampered, recipient: bob),
      throwsA(isA<DecryptionException>()),
    );
  });

  test('signature tampering produces INVALID_SIGNATURE', () async {
    final envelope = await _envelopeFor(
      cryptoService,
      sender: alice,
      recipient: bob,
    );
    final tamperedSignature = envelope.signature;
    tamperedSignature[0] ^= 1;
    final tampered = _copyEnvelope(envelope, signature: tamperedSignature);

    await expectLater(
      cryptoService.decrypt(envelope: tampered, recipient: bob),
      throwsA(isA<InvalidSignatureException>()),
    );
  });

  test('message IDs and identities are random, not counters or timestamps', () {
    final first = cryptoService.generateMessageId();
    final second = cryptoService.generateMessageId();
    expect(first, isNot(second));
    expect(first, hasLength(22));
    expect(second, hasLength(22));
    expect(alice.identityId, isNot(bob.identityId));
  });
}

Future<EncryptedEnvelope> _envelopeFor(
  SodiumCryptoService cryptoService, {
  required UserIdentity sender,
  required UserIdentity recipient,
}) async {
  final messageId = cryptoService.generateMessageId();
  return cryptoService.encryptForRecipient(
    plaintext: Uint8List.fromList(utf8.encode('secret payload')),
    messageId: messageId,
    sender: sender,
    recipient: recipient.publicIdentity,
  );
}

EncryptedEnvelope _copyEnvelope(
  EncryptedEnvelope source, {
  Uint8List? ciphertext,
  Uint8List? signature,
}) => EncryptedEnvelope(
  protocolVersion: source.protocolVersion,
  messageId: source.messageId,
  senderPublicIdentity: source.senderPublicIdentity,
  cryptoMetadata: source.cryptoMetadata,
  ciphertext: ciphertext ?? source.ciphertext,
  signature: signature ?? source.signature,
);
