import '../domain/model/identity.dart';
import '../domain/ports/crypto_service.dart';
import '../domain/ports/secure_key_storage.dart';

final class IdentityService {
  IdentityService({required this.cryptoService, required this.keyStorage});

  final CryptoService cryptoService;
  final SecureKeyStorage keyStorage;

  Future<UserIdentity> createIdentity() async {
    if (await keyStorage.hasIdentity()) {
      throw StateError('A local identity already exists.');
    }

    final identity = await cryptoService.generateIdentity();
    try {
      await keyStorage.storePrivateIdentity(identity);
      return identity;
    } catch (_) {
      identity.destroy();
      rethrow;
    }
  }

  Future<UserIdentity> loadIdentity() async {
    final identity = await keyStorage.loadPrivateIdentity();
    if (identity == null) {
      throw StateError('No local identity exists.');
    }

    final calculatedFingerprint = await cryptoService.calculateFingerprint(
      signingPublicKey: identity.publicIdentity.signingPublicKey,
      encryptionPublicKey: identity.publicIdentity.encryptionPublicKey,
      cryptoVersion: identity.cryptoVersion,
    );
    final keyMaterialIsValid = await cryptoService.validateIdentity(identity);
    if (calculatedFingerprint != identity.fingerprint || !keyMaterialIsValid) {
      identity.destroy();
      throw const IdentityIntegrityException();
    }
    return identity;
  }

  Future<UserIdentity> loadOrCreateIdentity() async {
    if (await keyStorage.hasIdentity()) return loadIdentity();
    return createIdentity();
  }

  Future<PublicIdentity> getPublicIdentity() async {
    final identity = await loadIdentity();
    try {
      return identity.publicIdentity;
    } finally {
      identity.destroy();
    }
  }

  Future<String> getFingerprint() async =>
      (await getPublicIdentity()).fingerprint;
}

final class IdentityIntegrityException implements Exception {
  const IdentityIntegrityException();

  @override
  String toString() => 'Stored identity failed integrity validation.';
}
