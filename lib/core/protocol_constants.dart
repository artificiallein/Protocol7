abstract final class ProtocolConstants {
  static const int version = 1;
  static const String label = 'P7/1';
  static const String cryptoSuite = 'P7/1-libsodium-sealedbox-ed25519-blake2b';

  static const int identityIdBytes = 16;
  static const int messageIdBytes = 16;
  static const int fingerprintBytes = 16;
  static const int signingPublicKeyBytes = 32;
  static const int signingPrivateKeyBytes = 64;
  static const int encryptionPublicKeyBytes = 32;
  static const int encryptionPrivateKeyBytes = 32;
  static const int signatureBytes = 64;
  static const int sealedBoxOverheadBytes = 48;

  static const int maxMessageBytes = 64 * 1024;
  static const int maxEnvelopeBytes = 256 * 1024;
  static const int maxBodyCharacters = 32 * 1024;
  static const int maxAttachmentCount = 8;
}
