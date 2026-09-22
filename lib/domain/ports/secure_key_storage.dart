import '../model/identity.dart';

abstract interface class SecureKeyStorage {
  Future<void> storePrivateIdentity(UserIdentity identity);
  Future<UserIdentity?> loadPrivateIdentity();
  Future<void> deletePrivateIdentity();
  Future<bool> hasIdentity();
}
