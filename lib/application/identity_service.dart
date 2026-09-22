import '../domain/model/identity.dart';
import '../domain/ports/crypto_service.dart';
import '../domain/ports/secure_key_storage.dart';

final class IdentityService {
  IdentityService({
    required CryptoService cryptoService,
    required SecureKeyStorage keyStorage,
  }) : _cryptoService = cryptoService,
       _keyStorage = keyStorage;

  final CryptoService _cryptoService;
  final SecureKeyStorage _keyStorage;

  Future<UserIdentity> createIdentity() async {
    if (await _keyStorage.hasIdentity()) {
      throw StateError('A local identity already exists.');
    }

    final identity = await _cryptoService.generateIdentity();
    try {
      await _keyStorage.storePrivateIdentity(identity);
      return identity;
    } catch (_) {
      identity.destroy();
      rethrow;
    }
  }

  Future<UserIdentity> loadIdentity() async {
    final identity = await _keyStorage.loadPrivateIdentity();
    if (identity == null) {
      throw StateError('No local identity exists.');
    }

    final calculatedFingerprint = await _cryptoService.calculateFingerprint(
      signingPublicKey: identity.publicIdentity.signingPublicKey,
      encryptionPublicKey: identity.publicIdentity.encryptionPublicKey,
      cryptoVersion: identity.cryptoVersion,
    );
    final keyMaterialIsValid = await _cryptoService.validateIdentity(identity);
    if (calculatedFingerprint != identity.fingerprint || !keyMaterialIsValid) {
      identity.destroy();
      throw const IdentityIntegrityException();
    }
    return identity;
  }

  Future<UserIdentity> loadOrCreateIdentity() async {
    if (await _keyStorage.hasIdentity()) return loadIdentity();
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
