import 'dart:convert';
import 'dart:typed_data';

import '../core/protocol_constants.dart';
import '../domain/model/secure_message.dart';
import '../domain/ports/message_serializer.dart';
import 'protocol_format_exception.dart';

final class JsonMessageSerializer implements MessageSerializer {
  const JsonMessageSerializer();

  @override
  Uint8List serialize(SecureMessage message) {
    _validateMessage(message);
    final bytes = Uint8List.fromList(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'protocolVersion': message.protocolVersion,
          'messageId': message.messageId,
          'conversationId': message.conversationId,
          'senderIdentityId': message.senderIdentityId,
          'createdAt': message.createdAt.toUtc().toIso8601String(),
          'messageType': message.messageType.name,
          'body': message.body,
          'attachments': [
            for (final attachment in message.attachments)
              <String, Object>{
                'id': attachment.id,
                'filename': attachment.filename,
                'mimeType': attachment.mimeType,
                'size': attachment.size,
              },
          ],
          'replyTo': message.replyTo,
        }),
      ),
    );
    if (bytes.length > ProtocolConstants.maxMessageBytes) {
      throw const ProtocolFormatException('Serialized message is too large.');
    }
    return bytes;
  }

  @override
  SecureMessage deserialize(Uint8List bytes) {
    if (bytes.isEmpty || bytes.length > ProtocolConstants.maxMessageBytes) {
      throw const ProtocolFormatException('Invalid message byte length.');
    }
    try {
      final decoded = jsonDecode(utf8.decode(bytes));
      if (decoded is! Map<String, dynamic>) {
        throw const ProtocolFormatException('Message root must be an object.');
      }
      final version = _int(decoded, 'protocolVersion');
      if (version != ProtocolConstants.version) {
        throw const ProtocolFormatException('Unsupported protocol version.');
      }
      final typeName = _string(decoded, 'messageType', maxLength: 64);
      final type = MessageType.values.where((value) => value.name == typeName);
      if (type.length != 1) {
        throw const ProtocolFormatException('Unsupported message type.');
      }
      final rawAttachments = decoded['attachments'];
      if (rawAttachments is! List ||
          rawAttachments.length > ProtocolConstants.maxAttachmentCount) {
        throw const ProtocolFormatException('Invalid attachments list.');
      }
      final attachments = <Attachment>[
        for (final raw in rawAttachments) _parseAttachment(raw),
      ];
      final rawReplyTo = decoded['replyTo'];
      if (rawReplyTo != null && rawReplyTo is! String) {
        throw const ProtocolFormatException('Invalid replyTo.');
      }
      final message = SecureMessage(
        protocolVersion: version,
        messageId: _string(decoded, 'messageId', maxLength: 128),
        conversationId: _string(decoded, 'conversationId', maxLength: 128),
        senderIdentityId: _string(decoded, 'senderIdentityId', maxLength: 128),
        createdAt: DateTime.parse(
          _string(decoded, 'createdAt', maxLength: 64),
        ).toUtc(),
        messageType: type.single,
        body: _string(
          decoded,
          'body',
          maxLength: ProtocolConstants.maxBodyCharacters,
          allowEmpty: true,
        ),
        attachments: List.unmodifiable(attachments),
        replyTo: rawReplyTo as String?,
      );
      _validateMessage(message);
      return message;
    } on ProtocolFormatException {
      rethrow;
    } on Object {
      throw const ProtocolFormatException('Malformed P7/1 message.');
    }
  }

  static Attachment _parseAttachment(Object? raw) {
    if (raw is! Map<String, dynamic>) {
      throw const ProtocolFormatException('Invalid attachment.');
    }
    final size = _int(raw, 'size');
    if (size < 0) {
      throw const ProtocolFormatException('Invalid attachment size.');
    }
    return Attachment(
      id: _string(raw, 'id', maxLength: 128),
      filename: _string(raw, 'filename', maxLength: 512),
      mimeType: _string(raw, 'mimeType', maxLength: 255),
      size: size,
    );
  }

  static void _validateMessage(SecureMessage message) {
    if (message.protocolVersion != ProtocolConstants.version) {
      throw const ProtocolFormatException('Unsupported protocol version.');
    }
    _validateIdentifier(message.messageId, 'messageId');
    _validateIdentifier(message.conversationId, 'conversationId');
    _validateIdentifier(message.senderIdentityId, 'senderIdentityId');
    if (message.body.length > ProtocolConstants.maxBodyCharacters) {
      throw const ProtocolFormatException('Message body is too large.');
    }
    if (message.attachments.length > ProtocolConstants.maxAttachmentCount) {
      throw const ProtocolFormatException('Too many attachments.');
    }
    if (message.replyTo != null) {
      _validateIdentifier(message.replyTo!, 'replyTo');
    }
  }

  static void _validateIdentifier(String value, String name) {
    if (value.isEmpty || value.length > 128) {
      throw ProtocolFormatException('Invalid $name.');
    }
  }

  static String _string(
    Map<String, dynamic> map,
    String key, {
    required int maxLength,
    bool allowEmpty = false,
  }) {
    final value = map[key];
    if (value is! String ||
        (!allowEmpty && value.isEmpty) ||
        value.length > maxLength) {
      throw ProtocolFormatException('Invalid $key.');
    }
    return value;
  }

  static int _int(Map<String, dynamic> map, String key) {
    final value = map[key];
    if (value is! int) throw ProtocolFormatException('Invalid $key.');
    return value;
  }
}
