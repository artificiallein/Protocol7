import '../model/encrypted_envelope.dart';

abstract interface class MessageTransport {
  Future<void> connect();
  Future<void> disconnect();
  Future<void> send(EncryptedEnvelope envelope);
  Future<List<EncryptedEnvelope>> fetch();
  Stream<EncryptedEnvelope> watch();
  Future<bool> testConnection();
}
