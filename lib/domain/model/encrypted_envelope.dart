import 'dart:typed_data';

import 'identity.dart';

final class CryptoMetadata {
  const CryptoMetadata({required this.suite});

  final String suite;
}

final class EncryptedEnvelope {
  EncryptedEnvelope({
    required this.protocolVersion,
    required this.messageId,
    required this.senderPublicIdentity,
    required this.cryptoMetadata,
    required List<int> ciphertext,
    required List<int> signature,
  }) : _ciphertext = Uint8List.fromList(ciphertext),
       _signature = Uint8List.fromList(signature);

  final int protocolVersion;
  final String messageId;
  final PublicIdentity senderPublicIdentity;
  final CryptoMetadata cryptoMetadata;
  final Uint8List _ciphertext;
  final Uint8List _signature;

  Uint8List get ciphertext => Uint8List.fromList(_ciphertext);
  Uint8List get signature => Uint8List.fromList(_signature);
}
