import 'dart:async';

import '../../core/protocol_constants.dart';
import '../../domain/model/encrypted_envelope.dart';
import '../../domain/model/identity.dart';
import '../../domain/model/transport_message.dart';
import '../../domain/ports/message_transport.dart';

typedef EnvelopeMutation = EncryptedEnvelope Function(
  EncryptedEnvelope envelope,
);

final class FakeTransportBehavior {
  const FakeTransportBehavior({
    this.delay = Duration.zero,
    this.drop = false,
    this.copies = 1,
    this.mutate,
  });

  final Duration delay;
  final bool drop;
  final int copies;
  final EnvelopeMutation? mutate;
}

/// An explicitly test-only, in-process transport network.
///
/// It is never wired by the production composition root. Transport addresses
/// are routing metadata only and do not establish sender identity or trust.
final class FakeTransportNetwork {
  FakeTransportNetwork.testing({DateTime Function()? clock})
    : _clock = clock ?? DateTime.now;

  final DateTime Function() _clock;
  final Map<String, FakeMessageTransport> _endpoints =
      <String, FakeMessageTransport>{};
  var _transportSequence = 0;

  FakeMessageTransport createEndpoint(String address) {
    _validateAddress(address);
    if (_endpoints.containsKey(address)) {
      throw FakeTransportException('Duplicate fake address: $address.');
    }
    final endpoint = FakeMessageTransport._(this, address);
    _endpoints[address] = endpoint;
    return endpoint;
  }

  Future<void> _route({
    required String senderAddress,
    required OutboundTransportMessage message,
    required FakeTransportBehavior behavior,
  }) async {
    if (behavior.delay.isNegative ||
        behavior.copies < 1 ||
        behavior.copies > 16) {
      throw const FakeTransportException('Invalid fake transport behavior.');
    }
    _validateAddress(message.recipientAddress);
    final recipient = _endpoints[message.recipientAddress];
    if (recipient == null || recipient._disposed) {
      throw FakeTransportException(
        'Unknown fake recipient: ${message.recipientAddress}.',
      );
    }
    if (behavior.drop) return;
    if (behavior.delay > Duration.zero) {
      await Future<void>.delayed(behavior.delay);
    }

    final original = _cloneEnvelope(message.envelope);
    final routed = behavior.mutate?.call(original) ?? original;
    for (var copy = 0; copy < behavior.copies; copy++) {
      _transportSequence++;
      recipient._receive(
        ReceivedTransportMessage(
          transportId: 'fake-$_transportSequence',
          senderAddress: senderAddress,
          recipientAddress: message.recipientAddress,
          receivedAt: _clock().toUtc(),
          envelope: _cloneEnvelope(routed),
        ),
      );
    }
  }

  void _remove(FakeMessageTransport endpoint) {
    if (identical(_endpoints[endpoint.address], endpoint)) {
      _endpoints.remove(endpoint.address);
    }
  }

  static void _validateAddress(String address) {
    if (address.isEmpty ||
        address.length > ProtocolConstants.maxTransportAddressCharacters) {
      throw const FakeTransportException('Invalid fake transport address.');
    }
  }
}

final class FakeMessageTransport implements MessageTransport {
  FakeMessageTransport._(this._network, this.address);

  final FakeTransportNetwork _network;
  final String address;
  final List<ReceivedTransportMessage> _inbox =
      <ReceivedTransportMessage>[];
  final StreamController<ReceivedTransportMessage> _controller =
      StreamController<ReceivedTransportMessage>.broadcast(sync: true);

  FakeTransportBehavior behavior = const FakeTransportBehavior();
  bool _connected = false;
  bool _disposed = false;

  @override
  Future<void> connect() async {
    _requireNotDisposed();
    _connected = true;
  }

  @override
  Future<void> disconnect() async {
    _requireNotDisposed();
    _connected = false;
  }

  @override
  Future<void> send(OutboundTransportMessage message) async {
    _requireConnected();
    await _network._route(
      senderAddress: address,
      message: message,
      behavior: behavior,
    );
  }

  @override
  Future<List<ReceivedTransportMessage>> fetch() async {
    _requireConnected();
    final messages = List<ReceivedTransportMessage>.unmodifiable(_inbox);
    _inbox.clear();
    return messages;
  }

  @override
  Stream<ReceivedTransportMessage> watch() {
    _requireConnected();
    return _controller.stream;
  }

  @override
  Future<bool> testConnection() async => _connected && !_disposed;

  Future<void> dispose() async {
    if (_disposed) return;
    _connected = false;
    _disposed = true;
    _network._remove(this);
    _inbox.clear();
    await _controller.close();
  }

  void _receive(ReceivedTransportMessage message) {
    if (_disposed) return;
    _inbox.add(message);
    if (_connected) _controller.add(message);
  }

  void _requireConnected() {
    _requireNotDisposed();
    if (!_connected) {
      throw const FakeTransportException('Fake transport is disconnected.');
    }
  }

  void _requireNotDisposed() {
    if (_disposed) {
      throw const FakeTransportException('Fake transport is disposed.');
    }
  }
}

EncryptedEnvelope _cloneEnvelope(EncryptedEnvelope source) =>
    EncryptedEnvelope(
      protocolVersion: source.protocolVersion,
      messageId: source.messageId,
      senderPublicIdentity: _cloneIdentity(source.senderPublicIdentity),
      cryptoMetadata: CryptoMetadata(suite: source.cryptoMetadata.suite),
      ciphertext: source.ciphertext,
      signature: source.signature,
    );

PublicIdentity _cloneIdentity(PublicIdentity source) => PublicIdentity(
  identityId: source.identityId,
  signingPublicKey: source.signingPublicKey,
  encryptionPublicKey: source.encryptionPublicKey,
  fingerprint: source.fingerprint,
  createdAt: source.createdAt,
  cryptoVersion: source.cryptoVersion,
);

final class FakeTransportException implements Exception {
  const FakeTransportException(this.message);
  final String message;

  @override
  String toString() => 'FakeTransportException: $message';
}
