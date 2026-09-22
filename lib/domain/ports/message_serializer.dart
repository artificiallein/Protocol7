import 'dart:typed_data';

import '../model/secure_message.dart';

abstract interface class MessageSerializer {
  Uint8List serialize(SecureMessage message);
  SecureMessage deserialize(Uint8List bytes);
}
