import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/core/protocol_constants.dart';
import 'package:protocol7/domain/model/secure_message.dart';
import 'package:protocol7/protocol/json_message_serializer.dart';
import 'package:protocol7/protocol/protocol_format_exception.dart';

void main() {
  const serializer = JsonMessageSerializer();

  test('round-trips the stable P7/1 message fields', () {
    final message = SecureMessage(
      protocolVersion: ProtocolConstants.version,
      messageId: 'random-message-id',
      conversationId: 'conversation-id',
      senderIdentityId: 'sender-id',
      createdAt: DateTime.utc(2026, 9, 22, 12, 30),
      messageType: MessageType.text,
      body: 'Привет.',
      replyTo: 'previous-random-id',
    );

    final serialized = serializer.serialize(message);
    final decoded = serializer.deserialize(serialized);

    expect(decoded.protocolVersion, ProtocolConstants.version);
    expect(decoded.messageId, message.messageId);
    expect(decoded.senderIdentityId, message.senderIdentityId);
    expect(decoded.createdAt, message.createdAt);
    expect(decoded.body, message.body);
    expect(decoded.replyTo, message.replyTo);
  });

  test('rejects an unknown protocol version instead of guessing', () {
    final malformed = Uint8List.fromList(
      utf8.encode(
        jsonEncode(<String, Object?>{
          'protocolVersion': 999,
          'messageId': 'id',
          'conversationId': 'conversation',
          'senderIdentityId': 'sender',
          'createdAt': DateTime.utc(2026).toIso8601String(),
          'messageType': 'text',
          'body': 'body',
          'attachments': <Object>[],
          'replyTo': null,
        }),
      ),
    );

    expect(
      () => serializer.deserialize(malformed),
      throwsA(isA<ProtocolFormatException>()),
    );
  });

  test('rejects oversized input before parsing', () {
    final oversized = Uint8List(ProtocolConstants.maxMessageBytes + 1);
    expect(
      () => serializer.deserialize(oversized),
      throwsA(isA<ProtocolFormatException>()),
    );
  });
}
