import 'encrypted_envelope.dart';

final class OutboundTransportMessage {
  const OutboundTransportMessage({
    required this.recipientAddress,
    required this.envelope,
  });

  final String recipientAddress;
  final EncryptedEnvelope envelope;
}

/// Transport metadata is untrusted and must never establish cryptographic trust.
final class ReceivedTransportMessage {
  const ReceivedTransportMessage({
    required this.transportId,
    required this.senderAddress,
    required this.recipientAddress,
    required this.receivedAt,
    required this.envelope,
  });

  final String transportId;
  final String senderAddress;
  final String recipientAddress;
  final DateTime receivedAt;
  final EncryptedEnvelope envelope;
}
