import 'dart:typed_data';

import '../model/encrypted_envelope.dart';
import '../model/identity.dart';

abstract interface class CryptoService {
  Future<UserIdentity> generateIdentity();

  Future<EncryptedEnvelope> encryptForRecipient({
    required Uint8List plaintext,
    required String messageId,
    required UserIdentity sender,
    required PublicIdentity recipient,
  });

  Future<Uint8List> decrypt({
    required EncryptedEnvelope envelope,
    required UserIdentity recipient,
  });

  Future<Uint8List> sign({
    required Uint8List message,
    required UserIdentity identity,
  });

  Future<bool> verifySignature({
    required Uint8List message,
    required Uint8List signature,
    required PublicIdentity identity,
  });

  Future<String> calculateFingerprint({
    required Uint8List signingPublicKey,
    required Uint8List encryptionPublicKey,
    required int cryptoVersion,
  });

  Future<bool> validateIdentity(UserIdentity identity);
  String generateMessageId();
}
