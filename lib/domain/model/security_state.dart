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

enum SecurityEventType { keyChanged, invalidSignature, replayDetected }
