final class Attachment {
  const Attachment({
    required this.id,
    required this.filename,
    required this.mimeType,
    required this.size,
  });

  final String id;
  final String filename;
  final String mimeType;
  final int size;
}

enum MessageType { text, keyAnnouncement }

final class SecureMessage {
  const SecureMessage({
    required this.protocolVersion,
    required this.messageId,
    required this.conversationId,
    required this.senderIdentityId,
    required this.createdAt,
    required this.messageType,
    required this.body,
    this.attachments = const [],
    this.replyTo,
  });

  final int protocolVersion;
  final String messageId;
  final String conversationId;
  final String senderIdentityId;
  final DateTime createdAt;
  final MessageType messageType;
  final String body;
  final List<Attachment> attachments;
  final String? replyTo;
}
