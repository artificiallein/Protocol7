import '../model/entities.dart';

abstract interface class ContactRepository {
  Future<Contact?> findContact(String contactId);
  Future<void> saveContact(Contact contact);
}

abstract interface class KnownKeyRepository {
  Future<KnownKey?> findKnownKey(String contactId, String fingerprint);
  Future<List<KnownKey>> listKnownKeys(String contactId);
  Future<void> saveKnownKey(KnownKey knownKey);
}

abstract interface class SecurityEventRepository {
  Future<void> addSecurityEvent(SecurityEvent event);
  Future<List<SecurityEvent>> listSecurityEvents({String? contactId});
}
