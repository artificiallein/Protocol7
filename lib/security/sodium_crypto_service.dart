import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium.dart';

import '../core/protocol_constants.dart';
import '../domain/model/encrypted_envelope.dart';
import '../domain/model/identity.dart';
import '../domain/ports/crypto_service.dart';

final class SodiumCryptoService implements CryptoService {
  SodiumCryptoService._(this._sodium);

  final Sodium _sodium;

  static Future<SodiumCryptoService> create() async =>
      SodiumCryptoService._(await SodiumInit.init());

  @override
  Future<UserIdentity> generateIdentity() async {
    final signingKeyPair = _sodium.crypto.sign.keyPair();
    final encryptionKeyPair = _sodium.crypto.box.keyPair();
    try {
      final fingerprint = await calculateFingerprint(
        signingPublicKey: signingKeyPair.publicKey,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        cryptoVersion: ProtocolConstants.version,
      );
      final publicIdentity = PublicIdentity(
        identityId: _randomId(ProtocolConstants.identityIdBytes),
        signingPublicKey: signingKeyPair.publicKey,
        encryptionPublicKey: encryptionKeyPair.publicKey,
        fingerprint: fingerprint,
        createdAt: DateTime.now().toUtc(),
        cryptoVersion: ProtocolConstants.version,
      );
      return UserIdentity(
        publicIdentity: publicIdentity,
        signingPrivateKey: signingKeyPair.secretKey.extractBytes(),
        encryptionPrivateKey: encryptionKeyPair.secretKey.extractBytes(),
      );
    } finally {
      signingKeyPair.dispose();
      encryptionKeyPair.dispose();
    }
  }

  @override
  Future<EncryptedEnvelope> encryptForRecipient({
    required Uint8List plaintext,
    required String messageId,
    required UserIdentity sender,
    required PublicIdentity recipient,
  }) async {
    _requireCurrentIdentity(sender.publicIdentity);
    _requireCurrentIdentity(recipient);
    if (plaintext.length > ProtocolConstants.maxMessageBytes) {
      throw const CryptoInputException('Plaintext exceeds the P7/1 limit.');
    }
    _requireIdentifier(messageId, 'messageId');

    final signatureInput = _signatureInput(
      plaintext: plaintext,
      messageId: messageId,
      sender: sender.publicIdentity,
      recipientIdentityId: recipient.identityId,
    );
    final signature = await sign(message: signatureInput, identity: sender);
    final ciphertext = _sodium.crypto.box.seal(
      message: plaintext,
      publicKey: recipient.encryptionPublicKey,
    );

    return EncryptedEnvelope(
      protocolVersion: ProtocolConstants.version,
      messageId: messageId,
      senderPublicIdentity: sender.publicIdentity,
      cryptoMetadata: const CryptoMetadata(
        suite: ProtocolConstants.cryptoSuite,
      ),
      ciphertext: ciphertext,
      signature: signature,
    );
  }

  @override
  Future<Uint8List> decrypt({
    required EncryptedEnvelope envelope,
    required UserIdentity recipient,
  }) async {
    _requireCurrentIdentity(recipient.publicIdentity);
    _validateEnvelopeMetadata(envelope);

    final recipientSecret = SecureKey.fromList(
      _sodium,
      recipient.encryptionPrivateKey,
    );
    late final Uint8List plaintext;
    try {
      plaintext = _sodium.crypto.box.sealOpen(
        cipherText: envelope.ciphertext,
        publicKey: recipient.publicIdentity.encryptionPublicKey,
        secretKey: recipientSecret,
      );
    } on SodiumException catch (error) {
      throw DecryptionException(error);
    } finally {
      recipientSecret.dispose();
    }

    if (plaintext.length > ProtocolConstants.maxMessageBytes) {
      plaintext.fillRange(0, plaintext.length, 0);
      throw const CryptoInputException('Decrypted message exceeds P7/1 limits.');
    }

    final signatureInput = _signatureInput(
      plaintext: plaintext,
      messageId: envelope.messageId,
      sender: envelope.senderPublicIdentity,
      recipientIdentityId: recipient.identityId,
    );
    final valid = await verifySignature(
      message: signatureInput,
      signature: envelope.signature,
      identity: envelope.senderPublicIdentity,
    );
    if (!valid) {
      plaintext.fillRange(0, plaintext.length, 0);
      throw const InvalidSignatureException();
    }
    return plaintext;
  }

  @override
  Future<Uint8List> sign({
    required Uint8List message,
    required UserIdentity identity,
  }) async {
    final secretKey = SecureKey.fromList(_sodium, identity.signingPrivateKey);
    try {
      return _sodium.crypto.sign.detached(message: message, secretKey: secretKey);
    } finally {
      secretKey.dispose();
    }
  }

  @override
  Future<bool> verifySignature({
    required Uint8List message,
    required Uint8List signature,
    required PublicIdentity identity,
  }) async {
    if (signature.length != _sodium.crypto.sign.bytes) return false;
    return _sodium.crypto.sign.verifyDetached(
      message: message,
      signature: signature,
      publicKey: identity.signingPublicKey,
    );
  }

  @override
  Future<String> calculateFingerprint({
    required Uint8List signingPublicKey,
    required Uint8List encryptionPublicKey,
    required int cryptoVersion,
  }) async => _calculateFingerprint(
    signingPublicKey: signingPublicKey,
    encryptionPublicKey: encryptionPublicKey,
    cryptoVersion: cryptoVersion,
  );

  String _calculateFingerprint({
    required Uint8List signingPublicKey,
    required Uint8List encryptionPublicKey,
    required int cryptoVersion,
  }) {
    if (signingPublicKey.length != _sodium.crypto.sign.publicKeyBytes ||
        encryptionPublicKey.length != _sodium.crypto.box.publicKeyBytes) {
      throw const CryptoInputException('Invalid public key length.');
    }
    final input = BytesBuilder(copy: false)
      ..add(utf8.encode('Protocol 7 fingerprint\u0000'))
      ..add(_uint32(cryptoVersion))
      ..add(signingPublicKey)
      ..add(encryptionPublicKey);
    final hash = _sodium.crypto.genericHash(
      message: input.takeBytes(),
      outLen: ProtocolConstants.fingerprintBytes,
    );
    final hex = hash
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
    return [
      for (var index = 0; index < hex.length; index += 4)
        hex.substring(index, index + 4),
    ].join(' ');
  }

  @override
  Future<bool> validateIdentity(UserIdentity identity) async {
    try {
      _requireCurrentIdentity(identity.publicIdentity);
      final calculated = await calculateFingerprint(
        signingPublicKey: identity.publicIdentity.signingPublicKey,
        encryptionPublicKey: identity.publicIdentity.encryptionPublicKey,
        cryptoVersion: identity.cryptoVersion,
      );
      if (calculated != identity.fingerprint) return false;

      final challenge = Uint8List.fromList(
        utf8.encode('Protocol 7 identity validation'),
      );
      final signature = await sign(message: challenge, identity: identity);
      if (!await verifySignature(
        message: challenge,
        signature: signature,
        identity: identity.publicIdentity,
      )) {
        return false;
      }

      final secretKey = SecureKey.fromList(
        _sodium,
        identity.encryptionPrivateKey,
      );
      try {
        final sealed = _sodium.crypto.box.seal(
          message: challenge,
          publicKey: identity.publicIdentity.encryptionPublicKey,
        );
        final opened = _sodium.crypto.box.sealOpen(
          cipherText: sealed,
          publicKey: identity.publicIdentity.encryptionPublicKey,
          secretKey: secretKey,
        );
        return _sodium.memcmp(challenge, opened);
      } finally {
        secretKey.dispose();
      }
    } on Object {
      return false;
    }
  }

  @override
  String generateMessageId() => _randomId(ProtocolConstants.messageIdBytes);

  String _randomId(int byteLength) => base64Url
      .encode(_sodium.randombytes.buf(byteLength))
      .replaceAll('=', '');

  void _validateEnvelopeMetadata(EncryptedEnvelope envelope) {
    if (envelope.protocolVersion != ProtocolConstants.version) {
      throw const UnsupportedProtocolVersionException();
    }
    if (envelope.cryptoMetadata.suite != ProtocolConstants.cryptoSuite) {
      throw const UnsupportedCryptoSuiteException();
    }
    _requireIdentifier(envelope.messageId, 'messageId');
    _requireCurrentIdentity(envelope.senderPublicIdentity);
    if (envelope.ciphertext.length < _sodium.crypto.box.sealBytes ||
        envelope.ciphertext.length >
            ProtocolConstants.maxMessageBytes + _sodium.crypto.box.sealBytes) {
      throw const CryptoInputException('Invalid ciphertext length.');
    }
  }

  void _requireCurrentIdentity(PublicIdentity identity) {
    if (identity.cryptoVersion != ProtocolConstants.version) {
      throw const UnsupportedProtocolVersionException();
    }
    _requireIdentifier(identity.identityId, 'identityId');
    if (identity.signingPublicKey.length !=
            _sodium.crypto.sign.publicKeyBytes ||
        identity.encryptionPublicKey.length !=
            _sodium.crypto.box.publicKeyBytes) {
      throw const CryptoInputException('Invalid public identity key length.');
    }
    final expectedFingerprint = _calculateFingerprint(
      signingPublicKey: identity.signingPublicKey,
      encryptionPublicKey: identity.encryptionPublicKey,
      cryptoVersion: identity.cryptoVersion,
    );
    if (identity.fingerprint != expectedFingerprint) {
      throw const CryptoInputException('Public identity fingerprint mismatch.');
    }
  }

  static void _requireIdentifier(String value, String field) {
    if (value.isEmpty || value.length > 128) {
      throw CryptoInputException('Invalid $field.');
    }
  }

  static Uint8List _signatureInput({
    required Uint8List plaintext,
    required String messageId,
    required PublicIdentity sender,
    required String recipientIdentityId,
  }) {
    final builder = BytesBuilder(copy: false)
      ..add(utf8.encode('Protocol 7 signed envelope\u0000'))
      ..add(_uint32(ProtocolConstants.version))
      ..add(_lengthPrefixedUtf8(ProtocolConstants.cryptoSuite))
      ..add(_lengthPrefixedUtf8(messageId))
      ..add(_lengthPrefixedUtf8(sender.identityId))
      ..add(_lengthPrefixedUtf8(recipientIdentityId))
      ..add(sender.signingPublicKey)
      ..add(sender.encryptionPublicKey)
      ..add(_uint32(plaintext.length))
      ..add(plaintext);
    return builder.takeBytes();
  }

  static Uint8List _lengthPrefixedUtf8(String value) {
    final bytes = utf8.encode(value);
    return Uint8List.fromList([..._uint32(bytes.length), ...bytes]);
  }

  static Uint8List _uint32(int value) {
    if (value < 0 || value > 0xffffffff) {
      throw const CryptoInputException('Value cannot be encoded as uint32.');
    }
    final data = ByteData(4)..setUint32(0, value, Endian.big);
    return data.buffer.asUint8List();
  }
}

final class CryptoInputException implements Exception {
  const CryptoInputException(this.message);
  final String message;

  @override
  String toString() => message;
}

final class DecryptionException implements Exception {
  const DecryptionException(this.cause);
  final Object cause;

  @override
  String toString() => 'Authenticated decryption failed.';
}

final class InvalidSignatureException implements Exception {
  const InvalidSignatureException();

  @override
  String toString() => 'INVALID_SIGNATURE';
}

final class UnsupportedProtocolVersionException implements Exception {
  const UnsupportedProtocolVersionException();

  @override
  String toString() => 'Unsupported Protocol 7 version.';
}

final class UnsupportedCryptoSuiteException implements Exception {
  const UnsupportedCryptoSuiteException();

  @override
  String toString() => 'Unsupported Protocol 7 crypto suite.';
}
