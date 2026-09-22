import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:protocol7/core/protocol_constants.dart';
import 'package:protocol7/domain/model/identity.dart';
import 'package:protocol7/infrastructure/storage/flutter_secure_key_storage.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    FlutterSecureStorage.setMockInitialValues(<String, String>{});
  });

  test('round-trips private identity through secure storage', () async {
    final storage = FlutterSecureKeyStorage();
    final identity = _identity();
    addTearDown(identity.destroy);

    await storage.storePrivateIdentity(identity);
    final loaded = await storage.loadPrivateIdentity();
    if (loaded != null) addTearDown(loaded.destroy);

    expect(await storage.hasIdentity(), isTrue);
    expect(loaded, isNotNull);
    expect(loaded!.identityId, identity.identityId);
    expect(loaded.fingerprint, identity.fingerprint);
    expect(loaded.signingPrivateKey, identity.signingPrivateKey);
    expect(loaded.encryptionPrivateKey, identity.encryptionPrivateKey);
  });

  test('rejects a completed but incomplete record', () async {
    FlutterSecureStorage.setMockInitialValues(<String, String>{
      'protocol7.identity.v1.complete': '1',
    });
    final storage = FlutterSecureKeyStorage();

    await expectLater(
      storage.loadPrivateIdentity(),
      throwsA(isA<CorruptIdentityStorageException>()),
    );
  });

  test('delete removes the completion marker', () async {
    final storage = FlutterSecureKeyStorage();
    final identity = _identity();
    addTearDown(identity.destroy);
    await storage.storePrivateIdentity(identity);

    await storage.deletePrivateIdentity();

    expect(await storage.hasIdentity(), isFalse);
    expect(await storage.loadPrivateIdentity(), isNull);
  });
}

UserIdentity _identity() => UserIdentity(
  publicIdentity: PublicIdentity(
    identityId: 'test-identity',
    signingPublicKey: List<int>.filled(
      ProtocolConstants.signingPublicKeyBytes,
      1,
    ),
    encryptionPublicKey: List<int>.filled(
      ProtocolConstants.encryptionPublicKeyBytes,
      2,
    ),
    fingerprint: '0000 0000 0000 0000 0000 0000 0000 0000',
    createdAt: DateTime.utc(2026, 9, 22),
    cryptoVersion: ProtocolConstants.version,
  ),
  signingPrivateKey: List<int>.filled(
    ProtocolConstants.signingPrivateKeyBytes,
    3,
  ),
  encryptionPrivateKey: List<int>.filled(
    ProtocolConstants.encryptionPrivateKeyBytes,
    4,
  ),
);
