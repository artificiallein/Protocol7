import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/domain/model/encrypted_envelope.dart';
import 'package:protocol7/domain/model/identity.dart';
import 'package:protocol7/domain/model/transport_message.dart';
import 'package:protocol7/infrastructure/transport/fake_message_transport.dart';
import 'package:protocol7/security/sodium_crypto_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late SodiumCryptoService cryptoService;

  setUpAll(() async {
    cryptoService = await SodiumCryptoService.create();
  });

  test('routes opaque envelopes and supports fetch and watch', () async {
    final network = FakeTransportNetwork.testing(
      clock: () => DateTime.utc(2026, 4, 1),
    );
    final aliceTransport = network.createEndpoint('alice@example.test');
    final bobTransport = network.createEndpoint('bob@example.test');
    await aliceTransport.connect();
    await bobTransport.connect();
    addTearDown(aliceTransport.dispose);
    addTearDown(bobTransport.dispose);
    final alice = await cryptoService.generateIdentity();
    final bob = await cryptoService.generateIdentity();
    addTearDown(alice.destroy);
    addTearDown(bob.destroy);
    final envelope = await _envelope(cryptoService, alice, bob);
    final watched = bobTransport.watch().first;

    await aliceTransport.send(
      OutboundTransportMessage(
        recipientAddress: bobTransport.address,
        envelope: envelope,
      ),
    );

    final live = await watched;
    final fetched = await bobTransport.fetch();
    expect(live.senderAddress, aliceTransport.address);
    expect(live.receivedAt, DateTime.utc(2026, 4, 1));
    expect(fetched, hasLength(1));
    expect(fetched.single.transportId, live.transportId);
    expect(fetched.single.envelope.ciphertext, envelope.ciphertext);
    expect(await bobTransport.fetch(), isEmpty);
  });

  test('can deterministically drop, duplicate, and delay delivery', () async {
    final network = FakeTransportNetwork.testing();
    final aliceTransport = network.createEndpoint('alice@example.test');
    final bobTransport = network.createEndpoint('bob@example.test');
    await aliceTransport.connect();
    await bobTransport.connect();
    addTearDown(aliceTransport.dispose);
    addTearDown(bobTransport.dispose);
    final alice = await cryptoService.generateIdentity();
    final bob = await cryptoService.generateIdentity();
    addTearDown(alice.destroy);
    addTearDown(bob.destroy);
    final envelope = await _envelope(cryptoService, alice, bob);
    final outbound = OutboundTransportMessage(
      recipientAddress: bobTransport.address,
      envelope: envelope,
    );

    aliceTransport.behavior = const FakeTransportBehavior(drop: true);
    await aliceTransport.send(outbound);
    expect(await bobTransport.fetch(), isEmpty);

    aliceTransport.behavior = const FakeTransportBehavior(copies: 2);
    await aliceTransport.send(outbound);
    final duplicates = await bobTransport.fetch();
    expect(duplicates, hasLength(2));
    expect(duplicates[0].transportId, isNot(duplicates[1].transportId));

    aliceTransport.behavior = const FakeTransportBehavior(
      delay: Duration(milliseconds: 20),
    );
    var completed = false;
    final delayed = aliceTransport.send(outbound).then((_) => completed = true);
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);
    await delayed;
    expect(completed, isTrue);
  });

  test('can modify ciphertext and the crypto layer rejects it', () async {
    final network = FakeTransportNetwork.testing();
    final aliceTransport = network.createEndpoint('alice@example.test');
    final bobTransport = network.createEndpoint('bob@example.test');
    await aliceTransport.connect();
    await bobTransport.connect();
    addTearDown(aliceTransport.dispose);
    addTearDown(bobTransport.dispose);
    final alice = await cryptoService.generateIdentity();
    final bob = await cryptoService.generateIdentity();
    addTearDown(alice.destroy);
    addTearDown(bob.destroy);
    final envelope = await _envelope(cryptoService, alice, bob);
    aliceTransport.behavior = FakeTransportBehavior(
      mutate: (source) {
        final ciphertext = source.ciphertext;
        ciphertext[0] ^= 1;
        return EncryptedEnvelope(
          protocolVersion: source.protocolVersion,
          messageId: source.messageId,
          senderPublicIdentity: source.senderPublicIdentity,
          cryptoMetadata: source.cryptoMetadata,
          ciphertext: ciphertext,
          signature: source.signature,
        );
      },
    );

    await aliceTransport.send(
      OutboundTransportMessage(
        recipientAddress: bobTransport.address,
        envelope: envelope,
      ),
    );
    final received = (await bobTransport.fetch()).single;

    await expectLater(
      cryptoService.decrypt(envelope: received.envelope, recipient: bob),
      throwsA(isA<DecryptionException>()),
    );
  });

  test('requires a connection and rejects unknown recipients', () async {
    final network = FakeTransportNetwork.testing();
    final aliceTransport = network.createEndpoint('alice@example.test');
    addTearDown(aliceTransport.dispose);
    final alice = await cryptoService.generateIdentity();
    final bob = await cryptoService.generateIdentity();
    addTearDown(alice.destroy);
    addTearDown(bob.destroy);
    final outbound = OutboundTransportMessage(
      recipientAddress: 'missing@example.test',
      envelope: await _envelope(cryptoService, alice, bob),
    );

    await expectLater(
      aliceTransport.send(outbound),
      throwsA(isA<FakeTransportException>()),
    );
    await aliceTransport.connect();
    await expectLater(
      aliceTransport.send(outbound),
      throwsA(isA<FakeTransportException>()),
    );
  });
}

Future<EncryptedEnvelope> _envelope(
  SodiumCryptoService cryptoService,
  UserIdentity sender,
  UserIdentity recipient,
) => cryptoService.encryptForRecipient(
  plaintext: Uint8List.fromList(utf8.encode('fake transport secret')),
  messageId: cryptoService.generateMessageId(),
  sender: sender,
  recipient: recipient.publicIdentity,
);
