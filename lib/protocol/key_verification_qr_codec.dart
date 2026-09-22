import 'dart:convert';
import 'dart:typed_data';

import '../core/protocol_constants.dart';
import '../domain/model/identity.dart';

final class KeyVerificationQrCodec {
  const KeyVerificationQrCodec();

  static const _fields = <String>{
    'protocol',
    'version',
    'identityId',
    'signingPublicKey',
    'encryptionPublicKey',
    'fingerprint',
    'createdAt',
    'cryptoVersion',
  };

  String encode(PublicIdentity identity) {
    final encoded = jsonEncode(<String, Object>{
      'protocol': 'Protocol 7',
      'version': ProtocolConstants.version,
      'identityId': identity.identityId,
      'signingPublicKey': base64Url.encode(identity.signingPublicKey),
      'encryptionPublicKey': base64Url.encode(identity.encryptionPublicKey),
      'fingerprint': identity.fingerprint,
      'createdAt': identity.createdAt.toUtc().toIso8601String(),
      'cryptoVersion': identity.cryptoVersion,
    });
    if (utf8.encode(encoded).length > ProtocolConstants.maxQrPayloadBytes) {
      throw const QrPayloadException('QR verification payload is too large.');
    }
    return encoded;
  }

  PublicIdentity decode(String encoded) {
    if (encoded.isEmpty ||
        utf8.encode(encoded).length > ProtocolConstants.maxQrPayloadBytes) {
      throw const QrPayloadException('Invalid QR verification payload size.');
    }
    try {
      final decoded = jsonDecode(encoded);
      if (decoded is! Map<String, dynamic> ||
          decoded.keys.toSet().difference(_fields).isNotEmpty ||
          _fields.difference(decoded.keys.toSet()).isNotEmpty) {
        throw const QrPayloadException(
          'Unexpected QR verification payload fields.',
        );
      }
      if (decoded['protocol'] != 'Protocol 7' ||
          decoded['version'] != ProtocolConstants.version ||
          decoded['cryptoVersion'] != ProtocolConstants.version) {
        throw const QrPayloadException('Unsupported QR verification version.');
      }
      return PublicIdentity(
        identityId: _string(decoded, 'identityId', 128),
        signingPublicKey: _key(
          decoded,
          'signingPublicKey',
          ProtocolConstants.signingPublicKeyBytes,
        ),
        encryptionPublicKey: _key(
          decoded,
          'encryptionPublicKey',
          ProtocolConstants.encryptionPublicKeyBytes,
        ),
        fingerprint: _string(decoded, 'fingerprint', 128),
        createdAt: DateTime.parse(
          _string(decoded, 'createdAt', 64),
        ).toUtc(),
        cryptoVersion: ProtocolConstants.version,
      );
    } on QrPayloadException {
      rethrow;
    } on Object {
      throw const QrPayloadException('Malformed QR verification payload.');
    }
  }

  static String _string(
    Map<String, dynamic> map,
    String field,
    int maxLength,
  ) {
    final value = map[field];
    if (value is! String || value.isEmpty || value.length > maxLength) {
      throw QrPayloadException('Invalid QR field: $field.');
    }
    return value;
  }

  static Uint8List _key(
    Map<String, dynamic> map,
    String field,
    int expectedLength,
  ) {
    final decoded = base64Url.decode(_string(map, field, 128));
    if (decoded.length != expectedLength) {
      throw QrPayloadException('Invalid QR key length: $field.');
    }
    return decoded;
  }
}

final class QrPayloadException implements Exception {
  const QrPayloadException(this.message);
  final String message;

  @override
  String toString() => 'QrPayloadException: $message';
}
