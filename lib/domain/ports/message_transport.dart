import '../model/transport_message.dart';

abstract interface class MessageTransport {
  Future<void> connect();
  Future<void> disconnect();
  Future<void> send(OutboundTransportMessage message);
  Future<List<ReceivedTransportMessage>> fetch();
  Stream<ReceivedTransportMessage> watch();
  Future<bool> testConnection();
}
