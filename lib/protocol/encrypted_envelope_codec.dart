import 'dart:convert';
import 'dart:typed_data';

import '../core/protocol_constants.dart';
import '../domain/model/encrypted_envelope.dart';
import '../domain/model/identity.dart';
import 'protocol_format_exception.dart';

final class EncryptedEnvelopeCodec {
  const EncryptedEnvelopeCodec();

  Uint8List encode(EncryptedEnvelope envelope) {
    _validateEnvelope(envelope);
    final sender = envelope.senderPublicIdentity;
    final bytes = Uint8List.fromList(
      utf8.encode(
        jsonEncode(<String, Object>{
          'protocolVersion': envelope.protocolVersion,
          'messageId': envelope.messageId,
          'senderPublicIdentity': <String, Object>{
            'identityId': sender.identityId,
            'signingPublicKey': base64Url.encode(sender.signingPublicKey),
            'encryptionPublicKey': base64Url.encode(sender.encryptionPublicKey),
            'fingerprint': sender.fingerprint,
            'createdAt': sender.createdAt.toUtc().toIso8601String(),
            'cryptoVersion': sender.cryptoVersion,
          },
          'cryptoMetadata': <String, Object>{
            'suite': envelope.cryptoMetadata.suite,
          },
          'ciphertext': base64Url.encode(envelope.ciphertext),
          'signature': base64Url.encode(envelope.signature),
        }),
      ),
    );
    if (bytes.length > ProtocolConstants.maxEnvelopeBytes) {
      throw const ProtocolFormatException('Encrypted envelope is too large.');
    }
    return bytes;
  }

  EncryptedEnvelope decode(Uint8List bytes) {
    if (bytes.isEmpty || bytes.length > ProtocolConstants.maxEnvelopeBytes) {
      throw const ProtocolFormatException('Invalid envelope byte length.');
    }
    try {
      final decoded = jsonDecode(utf8.decode(bytes));
      if (decoded is! Map<String, dynamic>) {
        throw const ProtocolFormatException('Envelope root must be an object.');
      }
      final version = _int(decoded, 'protocolVersion');
      if (version != ProtocolConstants.version) {
        throw const ProtocolFormatException('Unsupported protocol version.');
      }
      final rawSender = decoded['senderPublicIdentity'];
      final rawCrypto = decoded['cryptoMetadata'];
      if (rawSender is! Map<String, dynamic> ||
          rawCrypto is! Map<String, dynamic>) {
        throw const ProtocolFormatException('Invalid envelope metadata.');
      }
      final sender = PublicIdentity(
        identityId: _string(rawSender, 'identityId', maxLength: 128),
        signingPublicKey: _base64(
          rawSender,
          'signingPublicKey',
          ProtocolConstants.signingPublicKeyBytes,
        ),
        encryptionPublicKey: _base64(
          rawSender,
          'encryptionPublicKey',
          ProtocolConstants.encryptionPublicKeyBytes,
        ),
        fingerprint: _string(rawSender, 'fingerprint', maxLength: 128),
        createdAt: DateTime.parse(
          _string(rawSender, 'createdAt', maxLength: 64),
        ).toUtc(),
        cryptoVersion: _int(rawSender, 'cryptoVersion'),
      );
      final envelope = EncryptedEnvelope(
        protocolVersion: version,
        messageId: _string(decoded, 'messageId', maxLength: 128),
        senderPublicIdentity: sender,
        cryptoMetadata: CryptoMetadata(
          suite: _string(rawCrypto, 'suite', maxLength: 128),
        ),
        ciphertext: _base64(
          decoded,
          'ciphertext',
          ProtocolConstants.maxMessageBytes +
              ProtocolConstants.sealedBoxOverheadBytes,
        ),
        signature: _base64(
          decoded,
          'signature',
          ProtocolConstants.signatureBytes,
        ),
      );
      _validateEnvelope(envelope);
      return envelope;
    } on ProtocolFormatException {
      rethrow;
    } on Object {
      throw const ProtocolFormatException('Malformed P7/1 envelope.');
    }
  }

  static void _validateEnvelope(EncryptedEnvelope envelope) {
    if (envelope.protocolVersion != ProtocolConstants.version ||
        envelope.senderPublicIdentity.cryptoVersion !=
            ProtocolConstants.version) {
      throw const ProtocolFormatException('Unsupported protocol version.');
    }
    if (envelope.cryptoMetadata.suite != ProtocolConstants.cryptoSuite) {
      throw const ProtocolFormatException('Unsupported crypto suite.');
    }
    if (envelope.messageId.isEmpty || envelope.messageId.length > 128) {
      throw const ProtocolFormatException('Invalid messageId.');
    }
    if (envelope.ciphertext.isEmpty ||
        envelope.ciphertext.length >
            ProtocolConstants.maxMessageBytes +
                ProtocolConstants.sealedBoxOverheadBytes ||
        envelope.signature.length != ProtocolConstants.signatureBytes) {
      throw const ProtocolFormatException('Invalid cryptographic payload.');
    }
  }

  static String _string(
    Map<String, dynamic> map,
    String key, {
    required int maxLength,
  }) {
    final value = map[key];
    if (value is! String || value.isEmpty || value.length > maxLength) {
      throw ProtocolFormatException('Invalid $key.');
    }
    return value;
  }

  static int _int(Map<String, dynamic> map, String key) {
    final value = map[key];
    if (value is! int) throw ProtocolFormatException('Invalid $key.');
    return value;
  }

  static Uint8List _base64(
    Map<String, dynamic> map,
    String key,
    int maxDecodedLength,
  ) {
    final encoded = _string(
      map,
      key,
      maxLength: ((maxDecodedLength + 2) ~/ 3) * 4,
    );
    final bytes = base64Url.decode(encoded);
    if (bytes.length != maxDecodedLength &&
        key != 'ciphertext') {
      throw ProtocolFormatException('Invalid $key length.');
    }
    if (bytes.isEmpty || bytes.length > maxDecodedLength) {
      throw ProtocolFormatException('Invalid $key length.');
    }
    return bytes;
  }
}
