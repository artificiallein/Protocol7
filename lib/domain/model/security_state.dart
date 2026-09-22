enum KeyVerificationStatus { unverified, verified, changed, revoked }

enum MessageStatus {
  local,
  pending,
  encrypting,
  sending,
  sentToServer,
  received,
  decrypting,
  decrypted,
  failed,
}

enum SecurityEventType {
  newKeyDetected,
  keyVerified,
  keyChanged,
  invalidSignature,
  replayDetected,
  decryptionFailed,
  unsupportedProtocolVersion,
}
